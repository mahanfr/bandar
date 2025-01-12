#define _GNU_SOURCE
#include <sys/types.h>
#include <stdio.h>
#include <grp.h>
#include <stdlib.h>
#include <string.h>
#include <fcntl.h>
#include <unistd.h>
#include <seccomp.h>
#include <errno.h>
#include <sys/mount.h>
#include <sys/wait.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/utsname.h>
#include <sys/socket.h>
#include <sys/prctl.h>
#include <sys/capability.h>
#include <sched.h>
#include <sys/syscall.h>
#include <fcntl.h>
#include <time.h>
#include <linux/limits.h>
#include <linux/capability.h>
#include "common.h"
#include "resources.h"

#define STACK_SIZE (1024 * 1024)

void call_usage(char* program_name) {
    fprintf(stderr, "Usage: %s -u 1 -m . -c /bin/sh ~\n", program_name);
    exit(EXIT_FAILURE);
}

void generate_hostname(char *buf, size_t len) {
    struct timespec now = {0};
    clock_gettime(CLOCK_MONOTONIC, &now);
    size_t ix = now.tv_nsec;
    snprintf(buf, len, "%05lx-%s", ix, "container");
}

int check_linux_version() {
    fprintf(stderr, "Validating Linux version...");
    struct utsname host = {0};
    if (uname(&host) != 0) {
        fprintf(stderr, "failed: %m\n");
        return 1;
    }
    int major = -1;
    int minor = -1;
    if (sscanf(host.release, "%u.%u", &major, &minor) != 2) {
        fprintf(stderr, "unexpected relase format %s\n", host.release);
        return 1;
    }
    if (major < 4) {
        fprintf(stderr, "expected kernerl version >4.7.x: %s\n",host.release);
        return 1;
    }
    if (strcmp("x86_64", host.machine) != 0) {
        fprintf(stderr, "expected arch x86_64: %s\n",host.machine);
        return 1;
    }
    fprintf(stderr, "%s on %s.\n", host.release, host.machine);
    return 0;
}

int set_child_capabilities() {
    fprintf(stderr, "Dropping capabilities...");
    int drop_caps[] = {
        CAP_AUDIT_CONTROL,
        CAP_AUDIT_READ,
        CAP_AUDIT_WRITE,
        CAP_BLOCK_SUSPEND,
        CAP_DAC_READ_SEARCH,
        CAP_FSETID,
        CAP_IPC_LOCK,
        CAP_MAC_ADMIN,
        CAP_MAC_OVERRIDE,
        CAP_MKNOD,
        CAP_SETFCAP,
        CAP_SYSLOG,
        CAP_SYS_ADMIN,
        CAP_SYS_BOOT,
        CAP_SYS_MODULE,
        CAP_SYS_NICE,
        CAP_SYS_RAWIO,
        CAP_SYS_RESOURCE,
        CAP_SYS_TIME,
        CAP_WAKE_ALARM
    };
    size_t num_caps = sizeof(drop_caps) / sizeof(*drop_caps);
    fprintf(stderr, "bounding...");
    for (size_t i = 0; i < num_caps ;i++) {
        if (prctl(PR_CAPBSET_DROP, drop_caps[i], 0, 0, 0)) {
            fprintf(stderr, "prctl failed: %m\n");
            return 1;
        }
    }
    fprintf(stderr, "inheritable...");
    cap_t caps = NULL;
    if (!(caps = cap_get_proc())
            || cap_set_flag(caps, CAP_INHERITABLE, num_caps, drop_caps, CAP_CLEAR)
            || cap_set_proc(caps)) {
        fprintf(stderr, "failed: %m\n");
        if (caps) cap_free(caps);
        return 1;
    }
    cap_free(caps);
    fprintf(stderr, "done! \n");
    return 0;
}

#define USERNS_OFFSET 10000
#define USERNS_COUNT 2000

int handle_child_uid_map (pid_t child_pid, int fd) {
    int uid_map = 0;
    int has_userns = -1;
    if (read(fd, &has_userns, sizeof(has_userns)) != sizeof(has_userns)) {
        fprintf(stderr, "can not read from child process! \n");
        return -1;
    }
    if (has_userns) {
        char path[PATH_MAX] = {0};
        for (char **file = (char * []) {"uid_map", "gid_map", 0}; *file; file++) {
            if (snprintf(path, sizeof(path), "/proc/%d/%s", child_pid, *file) > (int) sizeof(path)) {
                fprintf(stderr, "sprintf too big? %m\n");
                return -1;
            }
            fprintf(stderr, "writing %s...\n", path);
            if ((uid_map = open(path, O_WRONLY)) == -1) {
                fprintf(stderr, "filed to open %s: %m\n", path);
                return -1;
            }
            if (dprintf(uid_map, "0 %d %d\n", USERNS_OFFSET, USERNS_COUNT) == -1) {
                fprintf(stderr, "dprintf failed: %m\n");
                close(uid_map);
                return -1;
            }
            close(uid_map);
        }
        if (write(fd, &(int) {0}, sizeof(int)) != sizeof(int)) {
            fprintf(stderr, "couldn't write to socket: %m\n");
            return -1;
        }
    }
    return 0;
}

int userns(child_config *cfg) {
    printf("Trying a user namespace\n");
    int has_userns = !unshare(CLONE_NEWUSER);
    if (write(cfg->fd, &has_userns, sizeof(has_userns)) != sizeof(has_userns)) {
        fprintf(stderr, "Couldn't write to socket: %m\n");
        return -1;
    }
    int result = 0;
    if (read(cfg->fd, &result, sizeof(result)) != sizeof(result)) {
        fprintf(stderr, "Couldn't read form socket: %m\n");
        return -1;
    }
    if (result) return -1;
    if (has_userns) {
        printf("User name spaces has been set successfully\n");
    } else {
        fprintf(stderr, "unsupported? continueing.\n");
    }
    printf("Switching to uid %d / gid %d\n", cfg->uid, cfg->uid);
    if (setgroups(1, &(gid_t) {cfg->uid})) {
        fprintf(stderr, "Error setting groups: %m\n");
        return -1;
    }
    if (setresgid(cfg->uid, cfg->uid, cfg->uid)) {
        fprintf(stderr, "Error setting real, effective and savied gid: %m\n");
        return -1;
    }
    if (setresuid(cfg->uid, cfg->uid, cfg->uid)) {
        fprintf(stderr, "Error setting real, effective and savied uid: %m\n");
        return -1;
    }
    return 0;
}

int pivot_root(const char* new_root, const char *put_old) {
    return syscall(SYS_pivot_root, new_root, put_old);
}

int mounts(child_config *config) {
    printf("Remounting everything with MS_PRIVATE\n");
    fflush(stdout);
    if (mount(NULL, "/", NULL, MS_REC | MS_PRIVATE, NULL)) {
        fprintf(stderr, "Remounting failed: %m\n");
        return -1;
    }

    printf("Making a temp directory and bind mount\n");
    fflush(stdout);
    char mount_dir[] = "/tmp/tmp.XXXXXX";
    if (mkdtemp(mount_dir) == NULL) {
        fprintf(stderr, "Failed making a directory: %m\n");
        return -1;
    }
    if (mount(config->mount_dir, mount_dir, NULL, MS_BIND | MS_PRIVATE, NULL)) {
        fprintf(stderr, "Bind mount failed: %m\n");
        return -1;
    }
    char inner_mount_dir[] = "/tmp/tmp.XXXXXX/oldroot.XXXXXX";
    memcpy(inner_mount_dir, mount_dir, sizeof(mount_dir) - 1);
    if (mkdtemp(inner_mount_dir) == NULL) {
        fprintf(stderr, "Failed making the inner directory: %m\n");
        return -1;
    }

    printf("Pivoting root\n");
    fflush(stdout);
    if (pivot_root(mount_dir, inner_mount_dir)) {
        fprintf(stderr, "Pivoting Root failed: %m\n");
        return -1;
    }

    char* old_root_dir = basename(inner_mount_dir);
    // WTF IS THIS
    char old_root[sizeof(inner_mount_dir) + 1] = {"/"};
    strcpy(&old_root[1], old_root_dir);

    printf("Unmounting %s\n", old_root);
    fflush(stdout);
    if (chdir("/") != 0) {
        fprintf(stderr, "Chdir failed: %m\n");
        return -1;
    }
    if (umount2(old_root, MNT_DETACH)) {
        fprintf(stderr, "Unmount failed: %m\n");
        return -1;
    }
    if (rmdir(old_root)) {
        fprintf(stderr, "Remove dir failed: %m\n");
        return -1;
    }
    return 0;
}

#define SCMP_FAIL SCMP_ACT_ERRNO(EPERM)

int disable_syscalls() {
    scmp_filter_ctx ctx = NULL;
    fprintf(stderr, "Filtering Syscalls...");
    if (!(ctx = seccomp_init(SCMP_ACT_ALLOW))
    || seccomp_rule_add(ctx, SCMP_FAIL, SCMP_SYS(chmod), 1,
        SCMP_A1(SCMP_CMP_MASKED_EQ, S_ISUID, S_ISUID))
    || seccomp_rule_add(ctx, SCMP_FAIL, SCMP_SYS(chmod), 1,
        SCMP_A1(SCMP_CMP_MASKED_EQ, S_ISGID, S_ISGID))
    || seccomp_rule_add(ctx, SCMP_FAIL, SCMP_SYS(fchmod), 1,
        SCMP_A1(SCMP_CMP_MASKED_EQ, S_ISUID, S_ISUID))
    || seccomp_rule_add(ctx, SCMP_FAIL, SCMP_SYS(fchmod), 1,
        SCMP_A1(SCMP_CMP_MASKED_EQ, S_ISGID, S_ISGID))
    || seccomp_rule_add(ctx, SCMP_FAIL, SCMP_SYS(fchmodat), 1,
        SCMP_A2(SCMP_CMP_MASKED_EQ, S_ISUID, S_ISUID))
    || seccomp_rule_add(ctx, SCMP_FAIL, SCMP_SYS(fchmodat), 1,
        SCMP_A2(SCMP_CMP_MASKED_EQ, S_ISGID, S_ISGID))
    || seccomp_rule_add(ctx, SCMP_FAIL, SCMP_SYS(unshare), 1,
        SCMP_A0(SCMP_CMP_MASKED_EQ, CLONE_NEWUSER, CLONE_NEWUSER))
    || seccomp_rule_add(ctx, SCMP_FAIL, SCMP_SYS(clone), 1,
        SCMP_A0(SCMP_CMP_MASKED_EQ, CLONE_NEWUSER, CLONE_NEWUSER))
    || seccomp_rule_add(ctx, SCMP_FAIL, SCMP_SYS(ioctl), 1,
        SCMP_A1(SCMP_CMP_MASKED_EQ, TIOCSTI, TIOCSTI))
    || seccomp_rule_add(ctx, SCMP_FAIL, SCMP_SYS(keyctl), 0)
    || seccomp_rule_add(ctx, SCMP_FAIL, SCMP_SYS(add_key), 0)
    || seccomp_rule_add(ctx, SCMP_FAIL, SCMP_SYS(request_key), 0)
    || seccomp_rule_add(ctx, SCMP_FAIL, SCMP_SYS(ptrace), 0)
    || seccomp_rule_add(ctx, SCMP_FAIL, SCMP_SYS(mbind), 0)
    || seccomp_rule_add(ctx, SCMP_FAIL, SCMP_SYS(migrate_pages), 0)
    || seccomp_rule_add(ctx, SCMP_FAIL, SCMP_SYS(move_pages), 0)
    || seccomp_rule_add(ctx, SCMP_FAIL, SCMP_SYS(set_mempolicy), 0)
    || seccomp_rule_add(ctx, SCMP_FAIL, SCMP_SYS(userfaultfd), 0)
    || seccomp_rule_add(ctx, SCMP_FAIL, SCMP_SYS(perf_event_open), 0)
    || seccomp_attr_set(ctx, SCMP_FLTATR_CTL_NNP, 0)
    || seccomp_load(ctx)) {
        if (ctx) seccomp_release(ctx);
        fprintf(stderr, "failed: %m\n");
        return 1;
    }
    seccomp_release(ctx);
    fprintf(stderr, "done.\n");
    return 0;
}

int child(void *arg) {
    child_config *config = arg;
    if (sethostname(config->hostname, strlen(config->hostname))
              || mounts(config)
              || userns(config)
              || set_child_capabilities()
              || disable_syscalls()
    ) {
        fprintf(stderr, "Setting up child process failed!\n");
        close(config->fd);
        return -1;
    }
    if (close(config->fd) != 0) {
        fprintf(stderr, "failed to close socket: %m\n");
        return -1;
    }
    if (execve(config->argv[0], config->argv, NULL)) {
        fprintf(stderr, "execve failed! %m.\n");
        return -1;
    }
    return 0;
}

int main(int argc, char **argv) {
    setlinebuf(stdout);
    child_config config = {0};
    int option = 0;
    int sockets[2] = {0};
    pid_t child_pid = 0;
    int last_optind = 0;
    while ((option = getopt(argc, argv, "c:m:u:"))) {
        if (option == 'c') {
            config.argc = argc - last_optind - 1;
            config.argv = &argv[argc - config.argc];
            break;
        } else if (option == 'm') {
            config.mount_dir = optarg;
        } else if (option == 'u') {
            if (sscanf(optarg, "%d", &config.uid) != 1) {
                fprintf(stderr, "badly-formatted uid: %s\n", optarg);
                call_usage(argv[0]);
            }
        }else {
            call_usage(argv[0]);
        }
        last_optind = optind;
    }
    if (!config.argc) call_usage(argv[0]);
    if (!config.mount_dir) call_usage(argv[0]);

    char hostname[256] = {0};
    generate_hostname(hostname, sizeof(hostname));
    config.hostname = hostname;
    printf("%s \n", config.hostname);

    if (check_linux_version() != 0) return 1;

    // NameSpace
    if (socketpair(AF_LOCAL, SOCK_SEQPACKET, 0, sockets) != 0) {
        fprintf(stderr, "socketpair failed: %m\n");
        return 1;
    }
    if (fcntl(sockets[0], F_SETFD, FD_CLOEXEC) != 0) {
        fprintf(stderr, "fcntl failed: %m\n");
        goto cl_socket;
    }
    config.fd = sockets[1];
    void *stack = 0;
    if ((stack = malloc(STACK_SIZE)) == NULL) {
        fprintf(stderr, "malloc failed: %m\n");
        goto cl_socket;
    }
    // if (set_resources(&config)) {
    //     goto cl_resources;
    // }
    int flags = CLONE_NEWNS
        | CLONE_NEWCGROUP
        | CLONE_NEWPID
        | CLONE_NEWIPC
        | CLONE_NEWNET
        | CLONE_NEWUTS;
    if ((child_pid = clone(child, stack + STACK_SIZE, flags | SIGCHLD, &config) < 0)) {
        fprintf(stderr, "clone failed! %m\n");
        goto cl_socket;
    }
    sleep(2);
    close(sockets[1]);
    sockets[1] = 0;

    // Seccessful Exit
    return 0;

// cl_resources:
//     free_resources(&config);
cl_socket:
    if (sockets[0]) close(sockets[0]);
    if (sockets[1]) close(sockets[1]);
    return 1;
}
