#ifndef SECPROBE_COMMON_H
#define SECPROBE_COMMON_H

/*
 * common.h
 *
 * Shared protocol definitions for the kernel module and user-space tool.
 * Keep all Netlink payloads pointer-free and fixed-size so both sides can
 * copy them as plain data without depending on process address spaces.
 */

#ifdef __KERNEL__
#include <linux/types.h>
typedef __u8 secprobe_u8;
typedef __u32 secprobe_u32;
typedef __s32 secprobe_s32;
#else
#include <stdint.h>
typedef uint8_t secprobe_u8;
typedef uint32_t secprobe_u32;
typedef int32_t secprobe_s32;
#endif

#define SECPROBE_NETLINK_PROTO 31

#define SECPROBE_MAGIC   0x53454350U
#define SECPROBE_VERSION 1

#define SECPROBE_MAX_PATH 256
#define SECPROBE_COMM_LEN 16

#define SECPROBE_MSG_REGISTER 0
#define SECPROBE_MSG_RULE_ADD 1
#define SECPROBE_MSG_ALERT    2

#define SECPROBE_RULE_FILE    1
#define SECPROBE_RULE_PROCESS 2

#define SECPROBE_ACTION_OPEN  1
#define SECPROBE_ACTION_EXEC  2

struct secprobe_rule {
    secprobe_u32 type;
    secprobe_u8 is_blacklist;
    secprobe_u8 reserved[3];
    char target[SECPROBE_MAX_PATH];
};

struct secprobe_alert {
    secprobe_u32 action;
    secprobe_u32 rule_type;
    secprobe_s32 pid;
    char comm[SECPROBE_COMM_LEN];
    char target[SECPROBE_MAX_PATH];
};

struct secprobe_msg {
    secprobe_u32 magic;
    secprobe_u32 version;
    secprobe_u32 msg_type;

    union {
        struct secprobe_rule rule;
        struct secprobe_alert alert;
    } payload;
};

#endif /* SECPROBE_COMMON_H */
