#ifndef _CONFIGS_H_
#define _CONFIGS_H_

#include <stdlib.h>
#include <stdio.h>

#define PanicLog(s) fprintf(stderr, "%s:%d - %s", __FILE__, __LINE__, s)

void BLog(const char *format, ...);

typedef struct {
    int argc;
    uid_t uid;
    int fd;
    char *hostname;
    char **argv;
    char *mount_dir;
} child_config;

#endif
