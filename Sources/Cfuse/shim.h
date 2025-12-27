#define FUSE_USE_VERSION 31
#include <fuse.h>

// Swift cannot import C macros, so we need a shim for fuse_main

static inline int fuse_main_swift(int argc, char *argv[], const struct fuse_operations *op, void *user_data) {
    return fuse_main(argc, argv, op, user_data);
}
