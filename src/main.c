#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/mount.h>
#include <sys/wait.h>
#include <sys/stat.h>
#include <sys/utsname.h>
#include <linux/sched.h>
#include <sched.h>
#include <sys/syscall.h>
#include <fcntl.h>
#include <time.h>

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

    (void) check_linux_version();

    // NameSpace

    return 0;
}
