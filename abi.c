#define _GNU_SOURCE
#include <errno.h>
#include <sched.h>
#include <seccomp.h>
#include <setjmp.h>
#include <signal.h>
#include <stdio.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/syscall.h>
#include <sys/utsname.h>
#include <sys/wait.h>
#include <unistd.h>

static unsigned long namespace_mask(void) {
    return 0x80UL | 0x20000UL | 0x2000000UL | 0x4000000UL | 0x8000000UL | 0x10000000UL |
           0x20000000UL | 0x40000000UL | 0x200000000UL;
}

static sigjmp_buf jump_buffer;
static volatile sig_atomic_t jump_signal;

static void on_signal(int sig) {
    jump_signal = sig;
    siglongjmp(jump_buffer, 1);
}

static long raw_syscall(long nr) {
    long ret;
    asm volatile("syscall" : "=a"(ret) : "a"(nr) : "rcx", "r11", "memory");
    return ret;
}

static int ia32_syscall(int nr, int arg1, int arg2, int *eax_out) {
    struct sigaction sa, old;
    memset(&sa, 0, sizeof(sa));
    sa.sa_handler = on_signal;
    sigemptyset(&sa.sa_mask);
    if (sigaction(SIGSEGV, &sa, &old) < 0) return -1;
    if (sigaction(SIGILL, &sa, NULL) < 0) return -1;
    jump_signal = 0;
    if (sigsetjmp(jump_buffer, 1) != 0) {
        sigaction(SIGSEGV, &old, NULL);
        sigaction(SIGILL, &old, NULL);
        return jump_signal;
    }
    int ret = 0;
    int number = nr;
    int a1 = arg1;
    int a2 = arg2;
    asm volatile(
        "pushq %%rbx\n\t"
        "movl %[nr], %%eax\n\t"
        "movl %[a1], %%ebx\n\t"
        "movl %[a2], %%ecx\n\t"
        "int $0x80\n\t"
        "movl %%eax, %[ret]\n\t"
        "popq %%rbx\n\t"
        : [ret] "=m"(ret)
        : [nr] "m"(number), [a1] "m"(a1), [a2] "m"(a2)
        : "rax", "rcx", "memory", "cc");
    sigaction(SIGSEGV, &old, NULL);
    sigaction(SIGILL, &old, NULL);
    *eax_out = ret;
    return 0;
}

static int allow_basics(scmp_filter_ctx ctx) {
    int allow[] = {SCMP_SYS(read),       SCMP_SYS(write),      SCMP_SYS(close),
                   SCMP_SYS(exit),       SCMP_SYS(exit_group), SCMP_SYS(futex),
                   SCMP_SYS(brk),        SCMP_SYS(mmap),       SCMP_SYS(munmap),
                   SCMP_SYS(mprotect),   SCMP_SYS(rt_sigreturn), SCMP_SYS(newfstatat),
                   SCMP_SYS(fstat),      SCMP_SYS(getpid),     SCMP_SYS(clock_gettime),
                   SCMP_SYS(wait4),      SCMP_SYS(gettid)};
    for (size_t i = 0; i < sizeof(allow) / sizeof(allow[0]); i++) {
        if (allow[i] < 0) continue;
        if (seccomp_rule_add(ctx, SCMP_ACT_ALLOW, allow[i], 0) < 0) return -1;
    }
    return 0;
}

static int child_print(void *raw) {
    int fd = *(int *)raw;
    char buf[80];
    ssize_t n = readlink("/proc/self/ns/mnt", buf, sizeof(buf) - 1);
    if (n < 0) dprintf(fd, "child_readlink_errno=%d\n", errno);
    else {
        buf[n] = 0;
        dprintf(fd, "child_mnt=%s\n", buf);
    }
    _exit(0);
}

static void run_clone_filter(void) {
    unsigned long mask = namespace_mask();
    char parent[80];
    ssize_t n = readlink("/proc/self/ns/mnt", parent, sizeof(parent) - 1);
    parent[n > 0 ? n : 0] = 0;
    printf("CLONE_PARENT_MNT %s\n", parent);
    size_t len = 1 << 20;
    char *unf = mmap(NULL, len, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS | MAP_STACK, -1, 0);
    int pipefd[2];
    if (pipe(pipefd) < 0) return;
    errno = 0;
    pid_t unfiltered = clone(child_print, unf + len, CLONE_NEWNS | SIGCHLD, &pipefd[1]);
    int unf_err = errno;
    printf("UNFILTERED_NAMESPACE_CLONE rc=%d errno=%d\n", unfiltered, unf_err);
    if (unfiltered > 0) {
        close(pipefd[1]);
        char msg[80];
        ssize_t got = read(pipefd[0], msg, sizeof(msg) - 1);
        if (got < 0) got = 0;
        msg[got] = 0;
        int st = 0;
        waitpid(unfiltered, &st, 0);
        printf("UNFILTERED_NAMESPACE_CHILD status=%d %s", st, msg);
    }
    close(pipefd[0]);

    pid_t kid = fork();
    if (kid == 0) {
        int ns_pipe[2], plain_pipe[2];
        if (pipe(ns_pipe) < 0 || pipe(plain_pipe) < 0) _exit(3);
        char *ns_stack = mmap(NULL, len, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS | MAP_STACK, -1, 0);
        char *plain_stack = mmap(NULL, len, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS | MAP_STACK, -1, 0);
        scmp_filter_ctx ctx = seccomp_init(SCMP_ACT_ERRNO(222));
        allow_basics(ctx);
        int add = seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(clone), 1,
                                   SCMP_A0(SCMP_CMP_MASKED_EQ, mask, 0));
        printf("CLONE_RULE_ADD %d datum_a=0x%lx datum_b=0\n", add, mask);
        fflush(stdout);
        seccomp_export_pfc(ctx, 1);
        fflush(stdout);
        if (seccomp_load(ctx) < 0) {
            printf("CLONE_LOAD errno=%d\n", errno);
            _exit(2);
        }
        errno = 0;
        pid_t ns = clone(child_print, ns_stack + len, CLONE_NEWNS | SIGCHLD, &ns_pipe[1]);
        int ns_err = errno;
        errno = 0;
        pid_t plain = clone(child_print, plain_stack + len, SIGCHLD, &plain_pipe[1]);
        int plain_err = errno;
        errno = 0;
        pid_t forked = fork();
        int fork_err = errno;
        printf("FILTERED_NAMESPACE flags=0x%x rc=%d errno=%d\n", CLONE_NEWNS | SIGCHLD, ns, ns_err);
        printf("FILTERED_PLAIN flags=0x%x rc=%d errno=%d\n", SIGCHLD, plain, plain_err);
        printf("FILTERED_FORK rc=%d errno=%d\n", forked, fork_err);
        fflush(stdout);
        if (forked == 0) _exit(0);
        if (plain > 0) {
            close(plain_pipe[1]);
            char msg[80];
            ssize_t got = read(plain_pipe[0], msg, sizeof(msg) - 1);
            if (got < 0) got = 0;
            msg[got] = 0;
            int st = 0;
            waitpid(plain, &st, 0);
            printf("FILTERED_PLAIN_CHILD status=%d %s", st, msg);
        }
        if (forked > 0) {
            int st = 0;
            waitpid(forked, &st, 0);
            printf("FILTERED_FORK_STATUS %d\n", st);
        }
        fflush(stdout);
        _exit(0);
    }
    int status = 0;
    waitpid(kid, &status, 0);
    printf("CLONE_FILTER_CHILD_STATUS %d\n", status);
}

static void governed_denies(void) {
    pid_t kid = fork();
    if (kid == 0) {
        scmp_filter_ctx ctx = seccomp_init(SCMP_ACT_ERRNO(222));
        allow_basics(ctx);
        if (seccomp_load(ctx) < 0) _exit(2);
        struct {
            long nr;
            const char *name;
        } items[] = {
            {__NR_clone3, "clone3"},
            {__NR_io_uring_setup, "io_uring_setup"},
            {__NR_io_setup, "io_setup"},
            {__NR_io_submit, "io_submit"},
        };
        for (size_t i = 0; i < sizeof(items) / sizeof(items[0]); i++) {
            errno = 0;
            long rc = syscall(items[i].nr, 0, 0, 0, 0, 0, 0);
            printf("GOVERNED_%s nr=%ld rc=%ld errno=%d\n", items[i].name, items[i].nr, rc, errno);
        }
        fflush(stdout);
        _exit(0);
    }
    int status = 0;
    waitpid(kid, &status, 0);
    printf("GOVERNED_DENY_STATUS %d\n", status);
}

static void native_arch_proof(void) {
    long libc_pid = getpid();
    long raw = raw_syscall(39);
    printf("NATIVE_GETPID libc=%ld raw_syscall_39=%ld match=%d\n", libc_pid, raw, libc_pid == raw);
    pid_t kid = fork();
    if (kid == 0) {
        scmp_filter_ctx ctx = seccomp_init(SCMP_ACT_ERRNO(222));
        if (seccomp_arch_exist(ctx, SCMP_ARCH_X86_64) != 0) {
            printf("NATIVE_ARCH_PRESENT no\n");
        } else {
            printf("NATIVE_ARCH_PRESENT SCMP_ARCH_X86_64\n");
        }
        seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(write), 0);
        seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(exit_group), 0);
        seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(futex), 0);
        seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(getpid), 0);
        seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(fstat), 0);
        seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(newfstatat), 0);
        seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(brk), 0);
        seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(exit), 0);
        fflush(stdout);
        seccomp_export_pfc(ctx, 1);
        fflush(stdout);
        if (seccomp_load(ctx) < 0) _exit(2);
        long got = raw_syscall(39);
        printf("NATIVE_FILTERED_GETPID rc=%ld errno=%d\n", got, errno);
        long denied = raw_syscall(__NR_clone3);
        int denied_err = errno;
        printf("NATIVE_FILTERED_CLONE3 rc=%ld errno=%d\n", denied, denied_err);
        fflush(stdout);
        _exit(0);
    }
    int status = 0;
    waitpid(kid, &status, 0);
    printf("NATIVE_FILTER_STATUS %d\n", status);
}

static void compat_probes(void) {
    int libc_pid = getpid();
    int eax = 0;
    int sig = ia32_syscall(20, 0, 0, &eax);
    if (sig > 0) {
        printf("IA32_GETPID signal=%d eax_not_returned libc_pid=%d\n", sig, libc_pid);
    } else {
        printf("IA32_GETPID signal=0 eax=%d libc_pid=%d match=%d\n", eax, libc_pid, eax == libc_pid);
    }
    long x32 = raw_syscall(0x40000000L | 39);
    printf("X32_GETPID rax=%ld libc_pid=%d enosys=%d match=%d\n", x32, libc_pid, x32 == -38, x32 == libc_pid);
}

static int ia32_invoke(int nr, int arg1, int arg2, int *eax_out) {
    if (sigsetjmp(jump_buffer, 1) != 0) return jump_signal;
    int ret = 0;
    int number = nr;
    int a1 = arg1;
    int a2 = arg2;
    asm volatile(
        "pushq %%rbx\n\t"
        "movl %[nr], %%eax\n\t"
        "movl %[a1], %%ebx\n\t"
        "movl %[a2], %%ecx\n\t"
        "int $0x80\n\t"
        "movl %%eax, %[ret]\n\t"
        "popq %%rbx\n\t"
        : [ret] "=m"(ret)
        : [nr] "m"(number), [a1] "m"(a1), [a2] "m"(a2)
        : "rax", "rcx", "memory", "cc");
    *eax_out = ret;
    return 0;
}

static void ia32_socketcall(void) {
    int eax = 0;
    int sig = ia32_syscall(102, 1, 0, &eax);
    if (sig > 0) printf("IA32_SOCKETCALL_UNFILTERED signal=%d\n", sig);
    else printf("IA32_SOCKETCALL_UNFILTERED eax=%d\n", eax);

    pid_t kid = fork();
    if (kid == 0) {
        struct sigaction sa;
        memset(&sa, 0, sizeof(sa));
        sa.sa_handler = on_signal;
        sigemptyset(&sa.sa_mask);
        sigaction(SIGSEGV, &sa, NULL);
        sigaction(SIGILL, &sa, NULL);
        scmp_filter_ctx ctx = seccomp_init(SCMP_ACT_ERRNO(222));
        if (seccomp_arch_add(ctx, SCMP_ARCH_X86) < 0) {
            printf("IA32_ARCH_ADD errno=%d\n", errno);
            _exit(2);
        }
        allow_basics(ctx);
        printf("IA32_FILTER_HAS_SCMP_ARCH_X86\n");
        fflush(stdout);
        if (seccomp_load(ctx) < 0) _exit(2);
        int filtered = 0;
        int filtered_sig = ia32_invoke(102, 1, 0, &filtered);
        if (filtered_sig > 0) printf("IA32_SOCKETCALL_FILTERED signal=%d\n", filtered_sig);
        else printf("IA32_SOCKETCALL_FILTERED eax=%d\n", filtered);
        fflush(stdout);
        _exit(0);
    }
    int status = 0;
    waitpid(kid, &status, 0);
    printf("IA32_SOCKETCALL_STATUS %d\n", status);
}

static void x32_policy(void) {
    pid_t kid = fork();
    if (kid == 0) {
        scmp_filter_ctx ctx = seccomp_init(SCMP_ACT_ERRNO(222));
        if (seccomp_arch_add(ctx, SCMP_ARCH_X32) < 0) {
            printf("X32_ARCH_ADD errno=%d\n", errno);
            _exit(2);
        }
        seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(write), 0);
        seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(exit_group), 0);
        seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(exit), 0);
        seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(fstat), 0);
        seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(brk), 0);
        printf("X32_FILTER_HAS_SCMP_ARCH_X32\n");
        fflush(stdout);
        seccomp_export_pfc(ctx, 1);
        fflush(stdout);
        if (seccomp_load(ctx) < 0) _exit(2);
        long denied = raw_syscall(0x40000000L | 39);
        printf("X32_FILTERED_GETPID_DENIED rax=%ld errno=%d\n", denied, errno);
        fflush(stdout);
        _exit(0);
    }
    int status = 0;
    waitpid(kid, &status, 0);
    printf("X32_POLICY_STATUS %d\n", status);

    kid = fork();
    if (kid == 0) {
        scmp_filter_ctx ctx = seccomp_init(SCMP_ACT_ERRNO(222));
        seccomp_arch_add(ctx, SCMP_ARCH_X32);
        allow_basics(ctx);
        /* getpid is already allowed on the native arch. Add the x32 syscall number explicitly. */
        seccomp_rule_add(ctx, SCMP_ACT_ALLOW, 39, 0);
        if (seccomp_load(ctx) < 0) _exit(2);
        long allowed = raw_syscall(0x40000000L | 39);
        printf("X32_FILTERED_GETPID_ALLOWED rax=%ld errno=%d\n", allowed, errno);
        fflush(stdout);
        _exit(0);
    }
    waitpid(kid, &status, 0);
    printf("X32_ALLOW_STATUS %d\n", status);
}

int main(void) {
    struct utsname u;
    uname(&u);
    printf("ABI_SYSNAME %s\nABI_MACHINE %s\nABI_RELEASE %s\n", u.sysname, u.machine, u.release);
    if (strcmp(u.machine, "x86_64") != 0) {
        printf("ENV_REJECTED machine=%s\n", u.machine);
        return 2;
    }
    native_arch_proof();
    compat_probes();
    ia32_socketcall();
    x32_policy();
    governed_denies();
    run_clone_filter();
    return 0;
}
