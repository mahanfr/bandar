/*
 *  We'd like to prevent badly-behaved child processes from
 *  denying service to the rest of the system.
 *  Cgroups let us limit memory and cpu time in particular;
 *  limiting the pid count and IO usage is also useful.
 *  There's a very useful document in the kernel tree about it.
 *
 *  The cgroup and cgroup2 filesystems are the canonical interfaces to the cgroup system.
 *  cgroup2 is a little different, and unitialized on my system, so I'll use the first version here.
 *
 *  Cgroup namespaces are a little different from, for example, mount namespaces.
 *  We need to create the cgroup before we enter a cgroup namespace;
 *  once we do, that cgroup will behave like the root cgroup inside of the namespace.
 *  This isn't the most relevant, since a contained process can't mount
 *  the cgroup filesystem or /proc for introspection, but it's nice to be thorough.
 */
#include "resources.h"
#include "common.h"
#include <fcntl.h>
#include <linux/limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/stat.h>
#include <sys/resource.h>
#include <unistd.h>
#include <string.h>

#define MEMORY "1073741824"
#define SHARES "256"
#define PIDS "64"
#define WEIGHT "10"
#define FD_COUNT 64

typedef struct {
    char name[256];
    char value[256];
} cgrp_setting;

typedef struct {
    char control[256];
    cgrp_setting **settings;
} cgrp_control;

static cgrp_setting add_to_tasks = {
    .name = "tasks",
    .value = "0"
};

static cgrp_control *cgrps[] = {
    // Set memory/$hostname/memory.limit_in_bytes and memory.kmem.limit_in_bytes
    // so the contained process and its child processes can't total more
    // than 1GB memory in userspace.
    &(cgrp_control) {
        .control = "memory",
        .settings = (cgrp_setting *[]) {
            &(cgrp_setting) {
                .name = "memory.limit_in_bytes",
                .value = MEMORY
            },
            &(cgrp_setting) {
                .name = "memory.kmem.limit_in_bytes",
                .value = MEMORY
            },
            &add_to_tasks,
            NULL
        }
    },
    // Set cpu/$hostname/cpu.shares to 256. CPU shares are chunks of 1024; 256 * 4 = 1024,
    // so this lets the contained process take a quarter of cpu-time on a busy system at most.
    &(cgrp_control) {
        .control = "cpu",
        .settings = (cgrp_setting *[]) {
            &(cgrp_setting) {
                .name = "cpu.shares",
                .value = SHARES
            },
            &add_to_tasks,
            NULL
        }
    },
    // Set the pids/$hostname/pid.max, allowing the contained process and its children
    // to have 64 pids at most. This is useful because there are per-user pid limits
    // that we could hit on the host if the contained process occupies too many.
    &(cgrp_control) {
        .control = "pids",
        .settings = (cgrp_setting *[]) {
            &(cgrp_setting) {
                .name = "pids.max",
                .value = PIDS
            },
            &add_to_tasks,
            NULL
        }
    },
    // Set blkio/$hostname/weight to 50, so that it's
    // lower than the rest of the system and prioritized accordingly.
    &(cgrp_control) {
        .control = "blkio",
        .settings = (cgrp_setting *[]) {
            &(cgrp_setting) {
                .name = "blkio.weight",
                .value = PIDS
            },
            &add_to_tasks,
            NULL
        }
    },
    NULL
};

/*
 *  In each controller, we create a cgroup with a name using mkdir.
 *  Inside of that we wrote to the individual files in order to set values.
 *
 *  Adding pid to tasks to add the process tree to the cgroup.
 *  "0" is a special value that means "the writing process".
 */
int set_resources(child_config *config) {
    fprintf(stderr, "Setting cgroups...");
    for (cgrp_control **cgrp = cgrps; *cgrp; cgrp++) {
        char dir[PATH_MAX] = {0};
        fprintf(stderr, "%s...", (*cgrp)->control);
        if (snprintf(dir, sizeof(dir), "/sys/fs/cgroup/%s/%s",
                    (*cgrp)->control, config->hostname) < 0) {
            PanicLog("unknown format!\n");
            return -1;
        }
        if(mkdir(dir, S_IRUSR | S_IWUSR | S_IXUSR)) {
            fprintf(stderr, "mkdir %s failed: %m\n", dir);
            return -1;
        }
        for (cgrp_setting **setting = (*cgrp)->settings; *setting; setting++) {
            char path[PATH_MAX] = {0};
            int fd = 0;
            if(snprintf(path, sizeof(path), "%s/%s", dir, (*setting)->name) < 0) {
                PanicLog("unknown format!\n");
                return -1;
            }
            if((fd = open(path, O_WRONLY) < 0)) {
                fprintf(stderr, "openning %s failed: %m\n", path);
                return -1;
            }
            if(write(fd, (*setting)->value, strlen((*setting)->value)) < 0) {
                fprintf(stderr, "writing to %s failed: %m\n", path);
                close(fd);
                return -1;
            }
            close(fd);
        }
    }
    fprintf(stderr, "done.\n");

    // we will lower the hard limit on the number of file descriptors.
    // The file descriptor number, like the number of pids, is per-user,
    // and so we want to prevent in-container process from occupying all of them
    fprintf(stderr, "Setting rlimit...");
    if (setrlimit(RLIMIT_NOFILE,
                & (struct rlimit) {
                .rlim_max = FD_COUNT,
                .rlim_cur = FD_COUNT,
                })) {
        fprintf(stderr, "failed: %m\n");
        return 1;
    }
    fprintf(stderr, "done.\n");
    return 0;
}

//  Since we have the contained process waiting on the contained process,
//  First we move the contained process back into the root tasks;
//  then, since the child process is finished, and leaving the pid
//  namespace SIGKILLS its children, the tasks is empty.
//  We can safely rmdir at this point.
int free_resources(child_config *config) {
    fprintf(stderr, "Cleaning cgroups...");
    for (cgrp_control **cgrp = cgrps; *cgrp; cgrp++) {
        char dir[PATH_MAX] = {0};
        char task[PATH_MAX] = {0};
        int task_fd = 0;
        if (snprintf(dir, sizeof(dir), "/sys/fs/cgroup/%s/%s",
                    (*cgrp)->control, config->hostname) < 0
                || snprintf(task, sizeof(dir), "/sys/fs/cgroup/%s/tasks",
                    (*cgrp)->control) < 0)
        {
            PanicLog("unknown format!\n");
            return -1;
        }
        if ((task_fd = open(task, O_WRONLY)) == -1) {
            fprintf(stderr, "opening %s failed: %m\n", task);
            return -1;
        }
        if (write(task_fd, "0", 2) == -1) {
            fprintf(stderr, "writing to %s failed: %m\n", task);
            close(task_fd);
            return -1;
        }
        close(task_fd);

        if (rmdir(dir)) {
            fprintf(stderr, "rmdir %s failed: %m", dir);
            return -1;
        }
    }
    fprintf(stderr, "done.\n");
    return 0;
}
