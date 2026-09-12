#include <errno.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>
#include <linux/netlink.h>

#include "common.h"

static volatile sig_atomic_t running = 1;
static int nl_fd = -1;

static void on_signal(int signo)
{
    (void)signo;
    running = 0;
    if (nl_fd >= 0)
        close(nl_fd);
}

static const char *rule_type_name(uint32_t type)
{
    switch (type) {
    case SECPROBE_RULE_FILE:
        return "file";
    case SECPROBE_RULE_PROCESS:
        return "process";
    default:
        return "unknown";
    }
}

static const char *action_name(uint32_t action)
{
    switch (action) {
    case SECPROBE_ACTION_OPEN:
        return "openat";
    case SECPROBE_ACTION_EXEC:
        return "execve";
    default:
        return "unknown";
    }
}

static void usage(const char *prog)
{
    fprintf(stderr,
            "Usage:\n"
            "  %s listen\n"
            "  %s block_file <absolute_path>\n"
            "  %s block_proc <process_name_or_absolute_path>\n",
            prog, prog, prog);
}

static int open_netlink_socket(void)
{
    struct sockaddr_nl local;
    int fd;

    fd = socket(AF_NETLINK, SOCK_RAW, SECPROBE_NETLINK_PROTO);
    if (fd < 0) {
        perror("socket(AF_NETLINK)");
        return -1;
    }

    memset(&local, 0, sizeof(local));
    local.nl_family = AF_NETLINK;
    local.nl_pid = (uint32_t)getpid();
    local.nl_groups = 0;

    if (bind(fd, (struct sockaddr *)&local, sizeof(local)) < 0) {
        perror("bind(AF_NETLINK)");
        close(fd);
        return -1;
    }

    return fd;
}

static int send_msg(int fd, const struct secprobe_msg *msg)
{
    char buffer[NLMSG_SPACE(sizeof(*msg))];
    struct sockaddr_nl kernel;
    struct nlmsghdr *nlh;
    struct iovec iov;
    struct msghdr msgh;
    ssize_t sent;

    memset(&kernel, 0, sizeof(kernel));
    kernel.nl_family = AF_NETLINK;
    kernel.nl_pid = 0;
    kernel.nl_groups = 0;

    memset(buffer, 0, sizeof(buffer));
    nlh = (struct nlmsghdr *)buffer;
    nlh->nlmsg_len = NLMSG_LENGTH(sizeof(*msg));
    nlh->nlmsg_type = NLMSG_DONE;
    nlh->nlmsg_flags = 0;
    nlh->nlmsg_pid = (uint32_t)getpid();

    memcpy(NLMSG_DATA(nlh), msg, sizeof(*msg));

    iov.iov_base = nlh;
    iov.iov_len = nlh->nlmsg_len;

    memset(&msgh, 0, sizeof(msgh));
    msgh.msg_name = &kernel;
    msgh.msg_namelen = sizeof(kernel);
    msgh.msg_iov = &iov;
    msgh.msg_iovlen = 1;

    sent = sendmsg(fd, &msgh, 0);
    if (sent < 0) {
        perror("sendmsg");
        return -1;
    }

    return 0;
}

static int register_listener(int fd)
{
    struct secprobe_msg msg;

    memset(&msg, 0, sizeof(msg));
    msg.magic = SECPROBE_MAGIC;
    msg.version = SECPROBE_VERSION;
    msg.msg_type = SECPROBE_MSG_REGISTER;

    return send_msg(fd, &msg);
}

static int send_rule(int fd, uint32_t type, const char *target)
{
    struct secprobe_msg msg;

    if (!target || target[0] == '\0') {
        fprintf(stderr, "target must not be empty\n");
        return -1;
    }

    if (strlen(target) >= SECPROBE_MAX_PATH) {
        fprintf(stderr, "target is too long, max is %d bytes\n",
                SECPROBE_MAX_PATH - 1);
        return -1;
    }

    memset(&msg, 0, sizeof(msg));
    msg.magic = SECPROBE_MAGIC;
    msg.version = SECPROBE_VERSION;
    msg.msg_type = SECPROBE_MSG_RULE_ADD;
    msg.payload.rule.type = type;
    msg.payload.rule.is_blacklist = 1;
    strncpy(msg.payload.rule.target, target, sizeof(msg.payload.rule.target) - 1);

    return send_msg(fd, &msg);
}

static void print_alert(const struct secprobe_alert *alert)
{
    printf("[ALERT] action=%s rule=%s pid=%d comm=%s target=%s\n",
           action_name(alert->action),
           rule_type_name(alert->rule_type),
           alert->pid,
           alert->comm,
           alert->target);
    fflush(stdout);
}

static int listen_alerts(int fd)
{
    char buffer[NLMSG_SPACE(sizeof(struct secprobe_msg))];

    while (running) {
        struct nlmsghdr *nlh;
        struct secprobe_msg *msg;
        ssize_t received;

        memset(buffer, 0, sizeof(buffer));
        received = recv(fd, buffer, sizeof(buffer), 0);
        if (received < 0) {
            if (!running)
                break;
            if (errno == EINTR)
                continue;
            perror("recv");
            return -1;
        }

        if ((size_t)received < NLMSG_SPACE(sizeof(*msg)))
            continue;

        nlh = (struct nlmsghdr *)buffer;
        if (!NLMSG_OK(nlh, (unsigned int)received))
            continue;

        if (nlh->nlmsg_len < NLMSG_LENGTH(sizeof(*msg)))
            continue;

        msg = (struct secprobe_msg *)NLMSG_DATA(nlh);
        if (msg->magic != SECPROBE_MAGIC || msg->version != SECPROBE_VERSION)
            continue;

        if (msg->msg_type == SECPROBE_MSG_ALERT)
            print_alert(&msg->payload.alert);
    }

    return 0;
}

int main(int argc, char **argv)
{
    uint32_t rule_type;
    int fd;
    int ret;

    if (argc != 2 && argc != 3) {
        usage(argv[0]);
        return EXIT_FAILURE;
    }

    fd = open_netlink_socket();
    if (fd < 0)
        return EXIT_FAILURE;
    nl_fd = fd;

    signal(SIGINT, on_signal);
    signal(SIGTERM, on_signal);

    if (register_listener(fd) != 0) {
        close(fd);
        return EXIT_FAILURE;
    }

    if (strcmp(argv[1], "listen") == 0) {
        if (argc != 2) {
            usage(argv[0]);
            close(fd);
            return EXIT_FAILURE;
        }
        printf("secprobe listener started, press Ctrl+C to stop\n");
        ret = listen_alerts(fd);
        close(fd);
        return ret == 0 ? EXIT_SUCCESS : EXIT_FAILURE;
    }

    if (argc != 3) {
        usage(argv[0]);
        close(fd);
        return EXIT_FAILURE;
    }

    if (strcmp(argv[1], "block_file") == 0) {
        rule_type = SECPROBE_RULE_FILE;
    } else if (strcmp(argv[1], "block_proc") == 0) {
        rule_type = SECPROBE_RULE_PROCESS;
    } else {
        usage(argv[0]);
        close(fd);
        return EXIT_FAILURE;
    }

    if (send_rule(fd, rule_type, argv[2]) != 0) {
        close(fd);
        return EXIT_FAILURE;
    }

    printf("added blacklist %s rule: %s\n", rule_type_name(rule_type), argv[2]);
    printf("listening for alerts, press Ctrl+C to stop\n");

    ret = listen_alerts(fd);
    close(fd);
    return ret == 0 ? EXIT_SUCCESS : EXIT_FAILURE;
}
