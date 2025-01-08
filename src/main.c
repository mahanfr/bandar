#define _GNU_SOURCE
#include <linux/limits.h>
#include <sys/types.h>
#include <stdio.h>
#include <grp.h>
#include <stdlib.h>
#include <string.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/mount.h>
#include <sys/wait.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/utsname.h>
#include <sys/socket.h>
#include <linux/sched.h>
#include <sched.h>
#include <sys/syscall.h>
#include <fcntl.h>
#include <time.h>

#define STACK_SIZE (1024 * 1024)

struct child_config {
    int argc;
    uid_t uid;
    int fd;
    char *hostname;
    char **argv;
    char *mount_dir;
};

void call_usage(char* program_name) {
    fprintf(stderr, "Usage: %s -u -1 -m . -c /bin/sh ~\n", program_name);
    exit(EXIT_FAILURE);
}

void generate_hostname(char *buf, size_t len) {
    struct timespec now = {0};
    clock_gettime(CLOCK_MONOTONIC, &now);
    size_t ix = now.tv_nsec;
    snprintf(buf, len, "%05lx-%s", now.tv_sec, "container");
}

int check_linux_version() {
    fprintf(stdout, "validating Linux version...");
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
    if (strcmp("x86_64", host.machine)) {
        fprintf(stderr, "expected arch x86_64: %s\n",host.machine);
        return 1;
    }
    fprintf(stdout, "%s on %s.\n", host.release, host.machine);
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
            if (snprintf(path, sizeof(path), "/proc/%d/%s", child_pid, *file) > sizeof(path)) {
                fprintf(stderr, "sprintf too big? %m\n");
                return -1;
            }
            fprintf(stdout, "writing %s...\n", path);
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

int userns(struct child_config *cfg) {
    fprintf(stderr, "trying a user namespace...");
    int has_userns = !unshare(CLONE_NEWUSER);
    if (write(cfg->fd, &has_userns, sizeof(has_userns)) != sizeof(has_userns)) {
        fprintf(stderr, "couldn't write to socket: %m\n");
        return -1;
    }
    int result = 0;
    if (read(cfg->fd, &result, sizeof(result)) != sizeof(result)) {
        fprintf(stderr, "couldn't read form socket: %m\n");
        return -1;
    }
    if (result) return -1;
    if (has_userns) {
        fprintf(stderr, "done\n");
    } else {
        fprintf(stderr, "unsupported? continueing.\n");
    }
    fprintf(stderr, "Switching to uid %d / gid %d...", cfg->uid, cfg->uid);
    if (setgroups(1, &(gid_t) {cfg->uid}) ||
            setresgid(cfg->uid, cfg->uid, cfg->uid) ||
            setresuid(cfg->uid, cfg->uid, cfg->uid)) {
        fprintf(stderr, "error setting groups: %m\n");
        return -1;
    }
    fprintf(stderr, "done.\n");
    return 0;
}

int child(void *arg) {
    struct child_config *config = arg;
    if (sethostname(config->hostname, strlen(config->hostname))
    //        || mounts(config)
              || userns(config)
    //        || capebilities()
    //        || syscalls() 
    ) {
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
    struct child_config config = {0};
    int err = 0;
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
        goto err;
    }
    config.fd = sockets[1];
    void *stack = 0;
    if ((stack = malloc(STACK_SIZE)) == NULL) {
        fprintf(stderr, "malloc failed: %m\n");
        goto err;
    }
    // if (resources(&config)) {
    // }
    int flags = CLONE_NEWNS
        | CLONE_NEWCGROUP
        | CLONE_NEWPID
        | CLONE_NEWIPC
        | CLONE_NEWNET
        | CLONE_NEWUTS;
    if ((child_pid = clone(child, stack + STACK_SIZE, flags | SIGCHLD, &config) < 0)) {
        fprintf(stderr, "clone failed! %m\n");
        goto err;
    }
    close(sockets[1]);
    sockets[1] = 0;

    // Seccessful Exit
    return 0;
err:
    if (sockets[0]) close(sockets[0]);
    if (sockets[1]) close(sockets[1]);
    return 1;
}
