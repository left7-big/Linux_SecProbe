# SecProbe 内核安全探针

SecProbe 是一个基于 Linux LKM 的课程设计项目，用来演示如何在内核态实现一个简单的安全探针。项目通过 Kprobes 监控关键系统调用，通过 Netlink 实现用户态和内核态通信，支持两类基础安全能力：

1. **敏感文件保护**：阻止进程访问指定文件路径，例如 `/etc/passwd`。
2. **进程执行拦截**：阻止执行指定程序，例如 `whoami` 或 `/usr/bin/whoami`。

本项目面向 CentOS 虚拟机实验环境，当前适配内核版本：

```bash
4.18.0-305.3.1.el8.x86_64
```

> 注意：这是操作系统课程设计实验项目，只建议在虚拟机中测试，不建议加载到生产机器。

## 1. 项目文件说明

```text
.
├── common.h      # 内核态和用户态共用的通信协议头文件
├── secprobe.c    # 内核模块源码，负责规则保存、Kprobes 拦截和告警上报
├── user_ctrl.c   # 用户态控制端源码，负责下发规则和监听告警
├── Makefile      # 编译脚本，同时编译 secprobe.ko 和 user_ctrl
└── README.md     # 项目说明、实现原理和实验步骤
```

### common.h

[common.h](common.h) 是内核态和用户态共同包含的头文件，定义了 Netlink 通信时使用的数据结构和常量。

它主要包含：

- `SECPROBE_NETLINK_PROTO`：自定义 Netlink 协议号。
- `struct secprobe_rule`：用户态下发给内核的规则。
- `struct secprobe_alert`：内核态上报给用户态的告警。
- `struct secprobe_msg`：Netlink 顶层消息结构。

规则类型：

```c
#define SECPROBE_RULE_FILE    1
#define SECPROBE_RULE_PROCESS 2
```

告警动作：

```c
#define SECPROBE_ACTION_OPEN  1
#define SECPROBE_ACTION_EXEC  2
```

这个文件里的通信结构体不包含指针，只使用整数和固定长度字符数组。这样做是为了避免用户态地址和内核态地址不一致造成解析错误。

### secprobe.c

[secprobe.c](secprobe.c) 是内核模块主体，负责实现核心功能。

它主要完成：

1. 模块加载和卸载：
   - `secprobe_init()`
   - `secprobe_exit()`

2. Netlink 通信：
   - 接收用户态规则。
   - 注册用户态监听端。
   - 向用户态发送告警。

3. 规则保存：
   - 使用内核链表保存规则。
   - 使用 `rwlock_t` 保护规则链表。
   - 限制最多保存 128 条规则，避免无限占用内核内存。

4. Kprobes 拦截：
   - 挂钩 `__x64_sys_execve`，用于进程执行拦截。
   - 挂钩 `__x64_sys_openat`，用于文件访问拦截。

5. 告警异步上报：
   - kprobe 命中规则后，不直接发送 Netlink。
   - 先把告警放入内核链表。
   - 再通过 workqueue 异步发送，降低 kprobe 上下文中的风险。

### user_ctrl.c

[user_ctrl.c](user_ctrl.c) 是用户态控制程序，编译后生成可执行文件 `user_ctrl`。

它支持三类命令：

```bash
sudo ./user_ctrl listen
sudo ./user_ctrl block_file <absolute_path>
sudo ./user_ctrl block_proc <process_name_or_absolute_path>
```

含义分别是：

- `listen`：只监听告警，不下发新规则。
- `block_file`：下发文件保护规则。
- `block_proc`：下发进程执行拦截规则。

### Makefile

[Makefile](Makefile) 用于自动编译项目。

执行：

```bash
make
```

会同时生成：

```text
secprobe.ko
user_ctrl
```

其中：

- `secprobe.ko` 是需要加载到内核中的模块。
- `user_ctrl` 是用户态规则控制和告警监听程序。

## 2. 项目实现原理

### 2.1 用户态和内核态通信

用户态程序 [user_ctrl.c](user_ctrl.c) 通过 Netlink 向内核模块 [secprobe.c](secprobe.c) 发送规则。

内核模块收到规则后，把规则保存到内核链表中。之后如果 Kprobes 捕获到目标行为，就会根据链表中的规则进行匹配。

当前支持三种 Netlink 消息：

```c
#define SECPROBE_MSG_REGISTER 0
#define SECPROBE_MSG_RULE_ADD 1
#define SECPROBE_MSG_ALERT    2
```

含义是：

- `SECPROBE_MSG_REGISTER`：用户态注册自己为告警接收端。
- `SECPROBE_MSG_RULE_ADD`：用户态向内核添加规则。
- `SECPROBE_MSG_ALERT`：内核向用户态上报告警。

### 2.2 文件保护规则

文件保护使用 `openat` 系统调用入口实现。

当进程执行：

```bash
cat /etc/passwd
```

底层会触发 `openat`。内核模块通过 kprobe 捕获 `__x64_sys_openat`，读取其中的文件路径参数。如果路径和文件规则完全一致，就让本次系统调用失败，并上报告警。

文件规则目前是**精确路径匹配**。例如：

```bash
sudo ./user_ctrl block_file /etc/passwd
```

只稳定匹配：

```text
/etc/passwd
```

不会故意做包含匹配，例如不会因为规则是 `passwd` 就拦截所有带 `passwd` 的路径。这样可以减少误伤。

### 2.3 进程拦截规则

进程拦截使用 `execve` 系统调用入口实现。

当 shell 执行：

```bash
whoami
```

shell 通常会根据 `PATH` 找到真实程序路径，然后执行类似：

```c
execve("/usr/bin/whoami", ...)
```

内核模块通过 kprobe 捕获 `__x64_sys_execve`，读取被执行程序路径，然后和进程规则比较。

当前进程规则支持两种写法：

1. **完整路径匹配**

   ```bash
   sudo ./user_ctrl block_proc /usr/bin/whoami
   ```

   这种规则只匹配完整路径 `/usr/bin/whoami`。

2. **进程名匹配**

   ```bash
   sudo ./user_ctrl block_proc whoami
   ```

   这种规则不包含 `/`，内核会取实际执行路径的最后一段进行匹配。

   例如下面这些执行路径都会被当作进程名 `whoami` 来匹配：

   ```text
   /usr/bin/whoami
   /bin/whoami
   ./whoami
   ```

   注意：这里是匹配可执行文件名本身，不是任意字符串包含。也就是说，规则 `whoami` 不会故意匹配 `mywhoami_test`，这样可以避免进程规则误伤。

### 2.4 为什么当前阻断结果可能是 Bad address

项目早期尝试过直接让系统调用返回 `-EACCES`，但在 CentOS 4.18 的 kprobe 场景里，强行修改 `regs->ip` 和 `regs->sp` 可能造成内核严重异常。

当前安全版本采用更保守的方式：

- 命中文件规则时，把 `openat` 的路径参数改成 `NULL`。
- 命中进程规则时，把 `execve` 的路径参数改成 `NULL`。

这样系统调用会走内核自己的错误处理路径，通常返回 `-EFAULT`。用户态经常显示为：

```text
Bad address
```

这个提示不如 `Permission denied` 直观，但更稳妥，能避免 Kernel Panic。

### 2.5 为什么要异步上报告警

kprobe handler 的上下文比较敏感，不适合直接执行复杂逻辑。项目中命中规则后只做必要处理，然后把告警放入链表，并调度 workqueue。

真正的 Netlink 发送在 workqueue 中完成。这样可以减少在 kprobe 上下文里分配内存、发送消息带来的风险。

## 3. 编译步骤

确认内核版本：

```bash
uname -r
```

确认内核开发头文件存在：

```bash
ls /lib/modules/$(uname -r)/build
```

进入项目目录并编译：

```bash
cd /home/left7/Documents/safety
make
```

编译成功后应看到：

```text
secprobe.ko
user_ctrl
```

## 4. 实验步骤

### 4.1 加载内核模块

```bash
cd /home/left7/Documents/safety
sudo insmod secprobe.ko
```

查看内核日志：

```bash
dmesg | tail -n 30
```

如果看到类似输出，说明模块加载成功：

```text
secprobe: resolved strncpy_from_unsafe_user=...
secprobe: kprobes registered: __x64_sys_execve, __x64_sys_openat
secprobe: loaded
```

如果看到：

```text
module verification failed: signature and/or required key missing
```

这通常只是自编译模块未签名导致的提示，不代表加载失败。真正要看后面有没有 `secprobe: loaded`。

### 4.2 实验一：敏感文件保护

终端 1 执行：

```bash
cd /home/left7/Documents/safety
sudo ./user_ctrl block_file /etc/passwd
```

这个命令会：

1. 向内核模块下发一条文件黑名单规则。
2. 留在前台监听告警。

终端 2 执行：

```bash
cat /etc/passwd
```

预期现象通常类似：

```text
cat: /etc/passwd: Bad address
```

终端 1 应该看到类似告警：

```text
[ALERT] action=openat rule=file pid=1234 comm=cat target=/etc/passwd
```

测试完成后，在终端 1 按：

```text
Ctrl+C
```

这只会退出用户态监听程序，不会卸载内核模块。

### 4.3 实验二：进程执行拦截，按完整路径匹配

终端 1 执行：

```bash
cd /home/left7/Documents/safety
sudo ./user_ctrl block_proc /usr/bin/whoami
```

终端 2 执行：

```bash
/usr/bin/whoami
```

预期现象通常类似：

```text
-bash: /usr/bin/whoami: Bad address
```

终端 1 应该看到类似告警：

```text
[ALERT] action=execve rule=process pid=1234 comm=bash target=/usr/bin/whoami
```

测试完成后，在终端 1 按 `Ctrl+C` 退出用户态监听程序。

### 4.4 实验三：进程执行拦截，按进程名匹配

这是本项目当前增强后的推荐测试方式。

终端 1 执行：

```bash
cd /home/left7/Documents/safety
sudo ./user_ctrl block_proc whoami
```

终端 2 执行：

```bash
whoami
```

虽然你输入的是 `whoami`，shell 实际执行的通常是 `/usr/bin/whoami`。内核模块会取 `/usr/bin/whoami` 的最后一段 `whoami` 与规则比较，因此可以命中。

预期现象通常类似：

```text
-bash: /usr/bin/whoami: Bad address
```

终端 1 应看到类似告警：

```text
[ALERT] action=execve rule=process pid=1234 comm=bash target=/usr/bin/whoami
```

测试完成后，在终端 1 按 `Ctrl+C`。

### 4.5 实验四：只监听告警

如果规则已经下发过，而你只是想重新打开一个用户态告警窗口，可以执行：

```bash
sudo ./user_ctrl listen
```

`listen` 不会添加新规则，只会把当前 `user_ctrl` 注册为内核告警接收端。

注意：当前模块只保存一个用户态监听端。如果多个 `user_ctrl` 同时运行，最后注册的那个会收到告警。

## 5. 卸载模块和清理

所有实验结束后，卸载内核模块：

```bash
sudo rmmod secprobe
```

查看日志：

```bash
dmesg | tail -n 20
```

预期看到：

```text
secprobe: unloaded
```

清理编译产物：

```bash
make clean
```

## 6. 可以替换哪些测试对象

文件保护可以替换成其他**完整文件路径**：

```bash
sudo ./user_ctrl block_file /etc/shadow
sudo ./user_ctrl block_file /etc/hosts
sudo ./user_ctrl block_file /root/secret.txt
```

进程拦截可以使用完整路径：

```bash
sudo ./user_ctrl block_proc /usr/bin/ls
sudo ./user_ctrl block_proc /usr/bin/cat
sudo ./user_ctrl block_proc /bin/bash
```

也可以使用进程名：

```bash
sudo ./user_ctrl block_proc ls
sudo ./user_ctrl block_proc cat
sudo ./user_ctrl block_proc whoami
```

文件规则为了避免误伤，仍然要求精确路径。进程规则为了方便实验，支持进程名匹配。

## 7. 当前限制

1. **文件规则只支持精确路径匹配**

   例如规则是 `/etc/passwd`，只有系统调用参数中传入的路径也刚好是 `/etc/passwd` 时才稳定命中。当前不解析相对路径、软链接、`..` 或挂载命名空间。

2. **进程规则支持完整路径或进程名匹配，但不是任意包含匹配**

   规则 `whoami` 可以匹配 `/usr/bin/whoami`，但不会故意匹配 `mywhoami_test`。

3. **规则只保存在内存中**

   模块卸载后规则会清空，没有持久化保存。

4. **当前只支持添加规则**

   暂不支持删除规则、列出规则、清空规则。

5. **当前只支持一个监听端**

   最后注册的 `user_ctrl` 会成为告警接收端。

6. **当前主要适配 x86_64 CentOS 4.18**

   本项目挂钩 `__x64_sys_execve` 和 `__x64_sys_openat`。如果换到其他内核版本，系统调用符号名可能不同，需要检查 `/proc/kallsyms` 或 `System.map`。

## 8. 常见问题

### 8.1 `insmod` 失败怎么办？

查看日志：

```bash
dmesg | tail -n 50
```

常见原因包括：

- 当前运行内核版本和编译用的 kernel headers 不一致。
- 系统安全策略禁止加载未签名模块。
- 当前内核没有相关 Kprobes 或 Netlink 支持。

### 8.2 为什么显示 Bad address 而不是 Permission denied？

当前项目优先保证虚拟机稳定。命中规则后，模块把系统调用路径参数改成 `NULL`，让内核原始系统调用自己返回错误，因此用户态通常显示 `Bad address`。

这说明访问或执行失败，拦截已经生效。

### 8.3 `cat /etc/passwd` 没有被拦截怎么办？

先确认模块已经加载：

```bash
dmesg | tail -n 30
```

再确认规则已经下发：

```bash
sudo ./user_ctrl block_file /etc/passwd
```

注意文件规则是精确匹配，测试时请使用相同路径：

```bash
cat /etc/passwd
```

### 8.4 `sudo ./user_ctrl block_proc whoami` 为什么能拦截 `/usr/bin/whoami`？

因为进程规则没有 `/` 时，内核模块会取实际执行路径最后一段做比较：

```text
/usr/bin/whoami -> whoami
```

所以规则 `whoami` 能匹配实际执行路径 `/usr/bin/whoami`。

### 8.5 为什么不在 kprobe handler 中直接发送 Netlink？

kprobe handler 上下文比较敏感，不适合做复杂操作。项目中先把告警放入链表，再用 workqueue 发送 Netlink，能降低内核崩溃风险。

### 8.6 为什么读取用户空间字符串要特别小心？

系统调用参数中的路径来自用户空间地址。内核不能直接把它当普通指针访问，否则地址非法时可能触发内核异常。项目中使用 `strncpy_from_unsafe_user()` 做受控读取，读取失败就放行，避免因为异常输入导致 Kernel Panic。

## 9. 项目意义和可扩展方向

本项目把操作系统课程中的系统调用、内核模块、内核态/用户态隔离、进程执行和文件访问等知识点连接成了一个完整实验。

它体现了一个安全探针的基本流程：

```text
用户态下发规则 -> 内核态保存规则 -> Kprobes 捕获行为 -> 规则匹配 -> 阻断并告警
```

后续可以扩展：

1. 支持规则删除、规则列表、规则清空。
2. 支持 UID、进程名、父进程等更细粒度条件。
3. 支持文件目录前缀保护，例如保护整个 `/etc/ssh/`。
4. 支持多个用户态监听端。
5. 用户态把告警写入日志文件。
6. 改用 LSM hook 实现更规范的访问控制，并返回更准确的 `-EACCES`。
