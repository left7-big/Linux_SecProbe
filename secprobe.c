// SPDX-License-Identifier: GPL-2.0
#include <linux/init.h>
#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/slab.h>
#include <linux/list.h>
#include <linux/rwlock.h>
#include <linux/spinlock.h>
#include <linux/workqueue.h>
#include <linux/skbuff.h>
#include <linux/netlink.h>
#include <linux/kprobes.h>
#include <linux/kallsyms.h>
#include <linux/uaccess.h>
#include <linux/errno.h>
#include <linux/sched.h>
#include <linux/string.h>
#include <net/sock.h>
#include <net/netlink.h>
#include <asm/ptrace.h>

#include "common.h"

#define SECPROBE_MAX_RULES 128
#define SECPROBE_MAX_ALERTS 256

struct secprobe_rule_node {
    struct list_head list;
    struct secprobe_rule rule;
};

struct secprobe_alert_node {
    struct list_head list;
    struct secprobe_alert alert;
};

typedef long (*secprobe_copy_user_str_fn)(char *dst,
                                          const void __user *src,
                                          long count);

static struct sock *secprobe_nl_sock;
static u32 secprobe_user_portid;

static LIST_HEAD(secprobe_rules);
static rwlock_t secprobe_rules_lock;
static unsigned int secprobe_rule_count;

static LIST_HEAD(secprobe_alerts);
static DEFINE_SPINLOCK(secprobe_alerts_lock);
static unsigned int secprobe_alert_count;
static void secprobe_alert_workfn(struct work_struct *work);
static DECLARE_WORK(secprobe_alert_work, secprobe_alert_workfn);

static secprobe_copy_user_str_fn secprobe_copy_user_str;

static int secprobe_execve_pre(struct kprobe *kp, struct pt_regs *regs);
static int secprobe_openat_pre(struct kprobe *kp, struct pt_regs *regs);

static struct kprobe secprobe_execve_kp = {
    .symbol_name = "__x64_sys_execve",
    .pre_handler = secprobe_execve_pre,
};

static struct kprobe secprobe_openat_kp = {
    .symbol_name = "__x64_sys_openat",
    .pre_handler = secprobe_openat_pre,
};

static bool secprobe_valid_rule_type(u32 type)
{
    return type == SECPROBE_RULE_FILE || type == SECPROBE_RULE_PROCESS;
}

static bool secprobe_valid_msg(const struct secprobe_msg *msg)
{
    if (!msg)
        return false;

    if (msg->magic != SECPROBE_MAGIC)
        return false;

    if (msg->version != SECPROBE_VERSION)
        return false;

    return true;
}

static int secprobe_add_rule(const struct secprobe_rule *rule)
{
    struct secprobe_rule_node *node;
    unsigned long flags;

    if (!rule || !secprobe_valid_rule_type(rule->type))
        return -EINVAL;

    if (rule->target[0] == '\0')
        return -EINVAL;

    node = kzalloc(sizeof(*node), GFP_KERNEL);
    if (!node)
        return -ENOMEM;

    memcpy(&node->rule, rule, sizeof(node->rule));
    node->rule.target[SECPROBE_MAX_PATH - 1] = '\0';
    node->rule.is_blacklist = node->rule.is_blacklist ? 1 : 0;

    write_lock_irqsave(&secprobe_rules_lock, flags);
    if (secprobe_rule_count >= SECPROBE_MAX_RULES) {
        write_unlock_irqrestore(&secprobe_rules_lock, flags);
        kfree(node);
        return -ENOSPC;
    }

    list_add_tail(&node->list, &secprobe_rules);
    secprobe_rule_count++;
    write_unlock_irqrestore(&secprobe_rules_lock, flags);

    pr_info("secprobe: added %s rule for %s\n",
            node->rule.type == SECPROBE_RULE_FILE ? "file" : "process",
            node->rule.target);

    return 0;
}

static const char *secprobe_basename(const char *path)
{
    const char *base;
    const char *p;

    base = path;
    for (p = path; p && *p; p++) {
        if (*p == '/')
            base = p + 1;
    }

    return base;
}

static bool secprobe_rule_matches(const struct secprobe_rule *rule,
                                  const char *target)
{
    const char *base;

    if (strncmp(rule->target, target, SECPROBE_MAX_PATH) == 0)
        return true;

    if (rule->type != SECPROBE_RULE_PROCESS)
        return false;

    if (strchr(rule->target, '/'))
        return false;

    base = secprobe_basename(target);
    return base && base[0] != '\0' &&
           strncmp(rule->target, base, SECPROBE_MAX_PATH) == 0;
}

static bool secprobe_path_blocked(u32 rule_type, const char *target)
{
    struct secprobe_rule_node *node;
    unsigned long flags;
    bool blocked;

    blocked = false;
    if (!target || target[0] == '\0')
        return false;

    read_lock_irqsave(&secprobe_rules_lock, flags);
    list_for_each_entry(node, &secprobe_rules, list) {
        if (node->rule.type != rule_type)
            continue;

        if (!node->rule.is_blacklist)
            continue;

        if (secprobe_rule_matches(&node->rule, target)) {
            blocked = true;
            break;
        }
    }
    read_unlock_irqrestore(&secprobe_rules_lock, flags);

    return blocked;
}

static void secprobe_free_rules(void)
{
    struct secprobe_rule_node *node;
    struct secprobe_rule_node *tmp;
    unsigned long flags;

    write_lock_irqsave(&secprobe_rules_lock, flags);
    list_for_each_entry_safe(node, tmp, &secprobe_rules, list) {
        list_del(&node->list);
        kfree(node);
    }
    secprobe_rule_count = 0;
    write_unlock_irqrestore(&secprobe_rules_lock, flags);
}

static int secprobe_send_alert_now(const struct secprobe_alert *alert)
{
    struct secprobe_msg *msg;
    struct nlmsghdr *nlh;
    struct sk_buff *skb;
    u32 portid;
    int ret;

    if (!alert)
        return -EINVAL;

    portid = READ_ONCE(secprobe_user_portid);
    if (!secprobe_nl_sock || portid == 0)
        return -ENODEV;

    skb = nlmsg_new(sizeof(*msg), GFP_KERNEL);
    if (!skb)
        return -ENOMEM;

    nlh = nlmsg_put(skb, 0, 0, NLMSG_DONE, sizeof(*msg), 0);
    if (!nlh) {
        kfree_skb(skb);
        return -EMSGSIZE;
    }

    msg = nlmsg_data(nlh);
    memset(msg, 0, sizeof(*msg));
    msg->magic = SECPROBE_MAGIC;
    msg->version = SECPROBE_VERSION;
    msg->msg_type = SECPROBE_MSG_ALERT;
    memcpy(&msg->payload.alert, alert, sizeof(*alert));

    ret = netlink_unicast(secprobe_nl_sock, skb, portid, MSG_DONTWAIT);
    if (ret < 0)
        pr_debug("secprobe: netlink alert send failed: %d\n", ret);

    return ret;
}

static void secprobe_alert_workfn(struct work_struct *work)
{
    struct secprobe_alert_node *node;
    unsigned long flags;

    for (;;) {
        spin_lock_irqsave(&secprobe_alerts_lock, flags);
        if (list_empty(&secprobe_alerts)) {
            spin_unlock_irqrestore(&secprobe_alerts_lock, flags);
            break;
        }

        node = list_first_entry(&secprobe_alerts,
                                struct secprobe_alert_node,
                                list);
        list_del(&node->list);
        secprobe_alert_count--;
        spin_unlock_irqrestore(&secprobe_alerts_lock, flags);

        secprobe_send_alert_now(&node->alert);
        kfree(node);
    }
}

static void secprobe_queue_alert(u32 action, u32 rule_type, const char *target)
{
    struct secprobe_alert_node *node;
    unsigned long flags;

    node = kzalloc(sizeof(*node), GFP_ATOMIC);
    if (!node)
        return;

    node->alert.action = action;
    node->alert.rule_type = rule_type;
    node->alert.pid = task_pid_nr(current);
    memcpy(node->alert.comm, current->comm, SECPROBE_COMM_LEN - 1);
    node->alert.comm[SECPROBE_COMM_LEN - 1] = '\0';
    strlcpy(node->alert.target, target, SECPROBE_MAX_PATH);

    spin_lock_irqsave(&secprobe_alerts_lock, flags);
    if (secprobe_alert_count >= SECPROBE_MAX_ALERTS) {
        spin_unlock_irqrestore(&secprobe_alerts_lock, flags);
        kfree(node);
        return;
    }

    list_add_tail(&node->list, &secprobe_alerts);
    secprobe_alert_count++;
    spin_unlock_irqrestore(&secprobe_alerts_lock, flags);

    schedule_work(&secprobe_alert_work);
}

static void secprobe_free_alerts(void)
{
    struct secprobe_alert_node *node;
    struct secprobe_alert_node *tmp;
    unsigned long flags;

    spin_lock_irqsave(&secprobe_alerts_lock, flags);
    list_for_each_entry_safe(node, tmp, &secprobe_alerts, list) {
        list_del(&node->list);
        kfree(node);
    }
    secprobe_alert_count = 0;
    spin_unlock_irqrestore(&secprobe_alerts_lock, flags);
}

static bool secprobe_copy_user_path(const char __user *user_path,
                                    char *kernel_buf,
                                    size_t kernel_buf_len)
{
    long copied;

    if (!user_path || !kernel_buf || kernel_buf_len == 0)
        return false;

    memset(kernel_buf, 0, kernel_buf_len);

    /*
     * Kprobe handlers run in a fragile context, so do not use helpers that may
     * take a recoverable page fault path. strncpy_from_unsafe_user() is the
     * no-fault probing helper used for this kind of best-effort string read.
     */
    copied = secprobe_copy_user_str(kernel_buf, user_path, kernel_buf_len);
    if (copied <= 0)
        return false;

    kernel_buf[kernel_buf_len - 1] = '\0';
    return true;
}

static void secprobe_block_exec_path(struct pt_regs *sys_regs)
{
    sys_regs->di = 0;
}

static void secprobe_block_open_path(struct pt_regs *sys_regs)
{
    sys_regs->si = 0;
}

static int secprobe_execve_pre(struct kprobe *kp, struct pt_regs *regs)
{
    const struct pt_regs *sys_regs;
    const char __user *filename;
    char path[SECPROBE_MAX_PATH];

    sys_regs = (const struct pt_regs *)regs->di;
    if (!sys_regs)
        return 0;

    filename = (const char __user *)sys_regs->di;
    if (!secprobe_copy_user_path(filename, path, sizeof(path)))
        return 0;

    if (!secprobe_path_blocked(SECPROBE_RULE_PROCESS, path))
        return 0;

    secprobe_block_exec_path((struct pt_regs *)sys_regs);
    secprobe_queue_alert(SECPROBE_ACTION_EXEC, SECPROBE_RULE_PROCESS, path);
    return 0;
}

static int secprobe_openat_pre(struct kprobe *kp, struct pt_regs *regs)
{
    const struct pt_regs *sys_regs;
    const char __user *filename;
    char path[SECPROBE_MAX_PATH];

    sys_regs = (const struct pt_regs *)regs->di;
    if (!sys_regs)
        return 0;

    filename = (const char __user *)sys_regs->si;
    if (!secprobe_copy_user_path(filename, path, sizeof(path)))
        return 0;

    if (!secprobe_path_blocked(SECPROBE_RULE_FILE, path))
        return 0;

    secprobe_block_open_path((struct pt_regs *)sys_regs);
    secprobe_queue_alert(SECPROBE_ACTION_OPEN, SECPROBE_RULE_FILE, path);
    return 0;
}

static void secprobe_nl_recv(struct sk_buff *skb)
{
    struct nlmsghdr *nlh;
    struct secprobe_msg *msg;
    u32 portid;
    int ret;

    if (!skb)
        return;

    nlh = nlmsg_hdr(skb);
    if (!nlh || nlmsg_len(nlh) < sizeof(*msg))
        return;

    msg = nlmsg_data(nlh);
    if (!secprobe_valid_msg(msg))
        return;

    portid = NETLINK_CB(skb).portid;

    switch (msg->msg_type) {
    case SECPROBE_MSG_REGISTER:
        WRITE_ONCE(secprobe_user_portid, portid);
        pr_info("secprobe: registered user listener portid=%u\n", portid);
        break;
    case SECPROBE_MSG_RULE_ADD:
        ret = secprobe_add_rule(&msg->payload.rule);
        if (ret)
            pr_info("secprobe: failed to add rule: %d\n", ret);
        break;
    default:
        pr_debug("secprobe: ignored unknown message type %u\n",
                 msg->msg_type);
        break;
    }
}

static int secprobe_register_kprobes(void)
{
    int ret;

    ret = register_kprobe(&secprobe_execve_kp);
    if (ret) {
        pr_err("secprobe: failed to register execve kprobe: %d\n", ret);
        return ret;
    }

    ret = register_kprobe(&secprobe_openat_kp);
    if (ret) {
        pr_err("secprobe: failed to register openat kprobe: %d\n", ret);
        unregister_kprobe(&secprobe_execve_kp);
        return ret;
    }

    pr_info("secprobe: kprobes registered: %s, %s\n",
            secprobe_execve_kp.symbol_name,
            secprobe_openat_kp.symbol_name);

    return 0;
}

static void secprobe_unregister_kprobes(void)
{
    unregister_kprobe(&secprobe_openat_kp);
    unregister_kprobe(&secprobe_execve_kp);
}

static int __init secprobe_init(void)
{
    struct netlink_kernel_cfg cfg = {
        .input = secprobe_nl_recv,
    };
    int ret;

    rwlock_init(&secprobe_rules_lock);

    secprobe_copy_user_str =
        (secprobe_copy_user_str_fn)kallsyms_lookup_name("strncpy_from_unsafe_user");

    if (!secprobe_copy_user_str) {
        pr_err("secprobe: strncpy_from_unsafe_user is unavailable\n");
        return -ENOENT;
    }

    pr_info("secprobe: resolved strncpy_from_unsafe_user=%px\n",
            secprobe_copy_user_str);

    secprobe_nl_sock = netlink_kernel_create(&init_net,
                                             SECPROBE_NETLINK_PROTO,
                                             &cfg);
    if (!secprobe_nl_sock) {
        pr_err("secprobe: failed to create netlink socket\n");
        return -ENOMEM;
    }

    ret = secprobe_register_kprobes();
    if (ret) {
        netlink_kernel_release(secprobe_nl_sock);
        secprobe_nl_sock = NULL;
        return ret;
    }

    pr_info("secprobe: loaded\n");
    return 0;
}

static void __exit secprobe_exit(void)
{
    secprobe_unregister_kprobes();
    flush_work(&secprobe_alert_work);
    secprobe_free_alerts();

    if (secprobe_nl_sock) {
        netlink_kernel_release(secprobe_nl_sock);
        secprobe_nl_sock = NULL;
    }

    secprobe_free_rules();
    WRITE_ONCE(secprobe_user_portid, 0);
    pr_info("secprobe: unloaded\n");
}

module_init(secprobe_init);
module_exit(secprobe_exit);

MODULE_LICENSE("GPL");
MODULE_AUTHOR("secprobe course project");
MODULE_DESCRIPTION("Simple LKM security probe using Kprobes and Netlink");
