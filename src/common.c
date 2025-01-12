#include "common.h"
#include <stdarg.h>

void BLog(const char *__restrict format, ...) {
    va_list args;
    va_start(args, format);
    if (fprintf(stdout, format, args) == 0) {
        fprintf(stderr, format, args);
    }
    va_end(args);
}
