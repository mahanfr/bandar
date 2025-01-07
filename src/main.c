#include <stdio.h>
#include <unistd.h>
#include <sys/mount.h>
#include <sys/wait.h>
#include <sys/stat.h>
#define _GNU_SOURCE
#include <linux/sched.h>
#include <sched.h>
#include <sys/syscall.h>
#include <fcntl.h>

#define STACK_SIZE (1024 * 1024)

static char child_stack[STACK_SIZE];

int child_function(void *arg) {
    printf("Inside container!\n");

    sethostname("First Container", 16);
    mount("proc", "/proc", "proc", 0, NULL);
    execlp("/bin/sh", "/bin/sh", NULL);
    return 0;
}

int main(void) {
    printf("Stating Container\n");
    int flags = CLONE_NEWNS
                | CLONE_NEWCGROUP
                | CLONE_NEWPID
                | CLONE_NEWIPC
                | CLONE_NEWNET
                | CLONE_NEWUTS;
    pid_t child_pid = clone(child_function, child_stack + STACK_SIZE,
                            flags | SIGCHLD, NULL);
    if (child_pid == -1) {
        perror("Failed to create a container");
        return -1;
    }

    if (waitpid(child_pid, NULL, 0) == -1) {
        perror("Failed to wait for child process");
        return -1;
    }

    printf("Container Stopped\n");
    return 0;
}
