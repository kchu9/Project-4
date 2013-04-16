/*
  FUSE: Filesystem in Userspace
  Copyright (C) 2001-2007  Miklos Szeredi <miklos@szeredi.hu>

  Minor modifications and note by Andy Sayler (2012) <www.andysayler.com>
  Some leetfs crypto stuff by Ken Sheedlo (2012)
    for CSCI 3753 P.A. 5 - University of Colorado at Boulder
    LEETFS - the LEET Encrypts Everything Transparently Filesystem

  Source: fuse-2.8.7.tar.gz examples directory
  http://sourceforge.net/projects/fuse/files/fuse-2.X/

  This program can be distributed under the terms of the GNU GPL.
  See the file COPYING.

  gcc -Wall `pkg-config fuse --cflags` fusexmp.c -o fusexmp `pkg-config fuse --libs`

  Note: This implementation is largely stateless and does not maintain
        open file handels between open and release calls (fi->fh).
        Instead, files are opened and closed as necessary inside read(), write(),
        etc calls. As such, the functions that rely on maintaining file handles are
        not implmented (fgetattr(), etc). Those seeking a more efficient and
        more complete implementation may wish to add fi->fh support to minimize
        open() and close() calls and support fh dependent functions.

*/

#define FUSE_USE_VERSION 28
#define BUFSIZE 256
#define PAGESIZE 4096
#define CIPHER_BLOCKSIZE 128
#define AES_ENCRYPT 1
#define AES_DECRYPT 0
#define AES_PASSTHRU -1
#define HAVE_SETXATTR
#define ENCRYPTED_ATTR  "user.pa5-encfs.encrypted"

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#ifdef linux
/* For pread()/pwrite() */
#define _XOPEN_SOURCE 500
#endif

#define _GNU_SOURCE
#include <fuse.h>
#include <stdio.h>
#include <stdlib.h>
#include <limits.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <dirent.h>
#include <errno.h>
#include <sys/time.h>
#ifdef HAVE_SETXATTR
#include <sys/xattr.h>
#endif

#include <openssl/evp.h>
#include <openssl/aes.h>

#include "aes-crypt.h"

typedef struct {
    char *rootdir;
    char key[32];
    char iv[32];
} leet_state;

static char *_leet_fullpath(char *buf, const char *path, size_t bufsize){
    leet_state *state = (leet_state *)(fuse_get_context()->private_data);
    snprintf(buf, bufsize, "%s%s", state->rootdir, path);
    return buf;
}

static int leet_getattr(const char *path, struct stat *stbuf)
{
    int res;
    char buf[BUFSIZE];

    res = lstat(_leet_fullpath(buf, path, BUFSIZE), stbuf);
#ifdef PRINTF_DEBUG
    fprintf(stderr, "leet_getattr: res = %d\n", res);
#endif
    if (res == -1)
        return -errno;

    return 0;
}
static int leet_access(const char *path, int mask) {
    int res;
    char buf[BUFSIZE];

    res = access(_leet_fullpath(buf, path, BUFSIZE), mask);
#ifdef PRINTF_DEBUG
    fprintf(stderr, "leet_access: res = %d\n", res);
#endif
    if (res == -1)
        return -errno;

    return 0;
}

static int leet_readlink(const char *path, char *buf, size_t size)
{
    int res;
    char pathbuf[BUFSIZE];

    res = readlink(_leet_fullpath(pathbuf, path, BUFSIZE), buf, size - 1);
#ifdef PRINTF_DEBUG
    fprintf(stderr, "leet_readlink: res = %d\n", res);
#endif
    if (res == -1)
        return -errno;

    buf[res] = '\0';
    return 0;
}


static int leet_readdir(const char *path, void *buf, fuse_fill_dir_t filler,
        off_t offset, struct fuse_file_info *fi)
{
    DIR *dp;
    struct dirent *de;
    char pathbuf[BUFSIZE];

    (void) offset;
    (void) fi;

    dp = opendir(_leet_fullpath(pathbuf, path, BUFSIZE));
#ifdef PRINTF_DEBUG
    fprintf(stderr, "leet_readdir: dp = %p\n", dp);
#endif
    if (dp == NULL)
        return -errno;

    while ((de = readdir(dp)) != NULL) {
        struct stat st;
        memset(&st, 0, sizeof(st));
        st.st_ino = de->d_ino;
        st.st_mode = de->d_type << 12;
        if (filler(buf, de->d_name, &st, 0))
            break;
    }

    closedir(dp);
    return 0;
}

static int leet_mknod(const char *path, mode_t mode, dev_t rdev)
{
    int res;
    char buf[BUFSIZE];

    _leet_fullpath(buf, path, BUFSIZE);

    /* On Linux this could just be 'mknod(path, mode, rdev)' but this
       is more portable */
#ifdef PRINTF_DEBUG
    fprintf(stderr, "leet_mknod: ");
#endif
    if (S_ISREG(mode)) {
        res = open(buf, O_CREAT | O_EXCL | O_WRONLY, mode);
        if (res >= 0)
            res = close(res);
    } else if (S_ISFIFO(mode))
        res = mkfifo(buf, mode);
    else
        res = mknod(buf, mode, rdev);
    if (res == -1)
        return -errno;

#ifdef PRINTF_DEBUG
    fprintf(stderr, "res = %d\n", res);
#endif
    return 0;
}

static int leet_mkdir(const char *path, mode_t mode)
{
    int res;
    char buf[BUFSIZE];

    res = mkdir(_leet_fullpath(buf, path, BUFSIZE), mode);
#ifdef PRINTF_DEBUG
    fprintf(stderr, "leet_mkdir: res = %d\n", res);
#endif
    if (res == -1)
        return -errno;

    return 0;
}

static int leet_unlink(const char *path)
{
    int res;
    char buf[BUFSIZE];

    res = unlink(_leet_fullpath(buf, path, BUFSIZE));
#ifdef PRINTF_DEBUG
    fprintf(stderr, "leet_unlink: res = %d\n", res);
#endif
    if (res == -1)
        return -errno;

    return 0;
}

static int leet_rmdir(const char *path)
{
    int res;
    char buf[BUFSIZE];

    res = rmdir(_leet_fullpath(buf, path, BUFSIZE));
#ifdef PRINTF_DEBUG
    fprintf(stderr, "leet_rmdir: res = %d\n", res);
#endif
    if (res == -1)
        return -errno;

    return 0;
}

static int leet_symlink(const char *from, const char *to)
{
    int res;
    char full_from[BUFSIZE];
    char full_to[BUFSIZE];

    res = symlink(_leet_fullpath(full_from, from, BUFSIZE), 
            _leet_fullpath(full_to, to, BUFSIZE));
#ifdef PRINTF_DEBUG
    fprintf(stderr, "leet_symlink: res = %d\n", res);
#endif
    if (res == -1)
        return -errno;

    return 0;
}

static int leet_rename(const char *from, const char *to)
{
    int res;
    char full_from[BUFSIZE];
    char full_to[BUFSIZE];

    res = rename(_leet_fullpath(full_from, from, BUFSIZE), 
            _leet_fullpath(full_to, to, BUFSIZE));
#ifdef PRINTF_DEBUG
    fprintf(stderr, "leet_rename: res = %d\n", res);
#endif
    if (res == -1)
        return -errno;

    return 0;
}

static int leet_link(const char *from, const char *to)
{
    int res;
    char full_from[BUFSIZE];
    char full_to[BUFSIZE];

    res = link(_leet_fullpath(full_from, from, BUFSIZE), 
            _leet_fullpath(full_to, to, BUFSIZE));
#ifdef PRINTF_DEBUG
    fprintf(stderr, "leet_link: res = %d\n", res);
#endif
    if (res == -1)
        return -errno;

    return 0;
}

static int leet_chmod(const char *path, mode_t mode)
{
    int res;
    char buf[BUFSIZE];

    res = chmod(_leet_fullpath(buf, path, BUFSIZE), mode);
#ifdef PRINTF_DEBUG
    fprintf(stderr, "leet_chmod: res = %d\n", res);
#endif
    if (res == -1)
        return -errno;

    return 0;
}

static int leet_chown(const char *path, uid_t uid, gid_t gid)
{
    int res;
    char buf[BUFSIZE];

    res = lchown(_leet_fullpath(buf, path, BUFSIZE), uid, gid);
#ifdef PRINTF_DEBUG
    fprintf(stderr, "leet_chown: res = %d\n", res);
#endif
    if (res == -1)
        return -errno;

    return 0;
}

static int leet_truncate(const char *path, off_t size)
{
    int res;
    char buf[BUFSIZE];

    res = truncate(_leet_fullpath(buf, path, BUFSIZE), size);
#ifdef PRINTF_DEBUG
    fprintf(stderr, "leet_truncate: res = %d\n", res);
#endif
    if (res == -1)
        return -errno;

    return 0;
}

static int leet_utimens(const char *path, const struct timespec ts[2])
{
    int res;
    struct timeval tv[2];
    char buf[BUFSIZE];

    tv[0].tv_sec = ts[0].tv_sec;
    tv[0].tv_usec = ts[0].tv_nsec / 1000;
    tv[1].tv_sec = ts[1].tv_sec;
    tv[1].tv_usec = ts[1].tv_nsec / 1000;

    res = utimes(_leet_fullpath(buf, path, BUFSIZE), tv);
#ifdef PRINTF_DEBUG
    fprintf(stderr, "leet_utimens: res = %d\n", res);
#endif
    if (res == -1)
        return -errno;

    return 0;
}

static int leet_open(const char *path, struct fuse_file_info *fi)
{
    int res;
    char buf[BUFSIZE];

    res = open(_leet_fullpath(buf, path, BUFSIZE), fi->flags);
#ifdef PRINTF_DEBUG
    fprintf(stderr, "leet_open: res = %d\n", res);
#endif
    if (res == -1)
        return -errno;

    close(res);
    return 0;
}

static int leet_read(const char *path, char *buf, size_t size, off_t offset,
        struct fuse_file_info *fi)
{
    FILE *f, *memstream;
    int res;
    char pathbuf[BUFSIZE];
    char *membuf;
    size_t memsize;

    (void) fi;
    f = fopen(_leet_fullpath(pathbuf, path, BUFSIZE), "r");
    memstream = open_memstream(&membuf, &memsize);
#ifdef PRINTF_DEBUG
    fprintf(stderr, "leet_read: fd = %d, ", fd);
#endif
    if (f == NULL || memstream == NULL)
        return -errno;

    char attrbuf[8];
    ssize_t attr_len = getxattr(pathbuf, ENCRYPTED_ATTR, attrbuf, 8);
    int crypt_action = AES_PASSTHRU;
    if(attr_len != -1 && !memcmp(attrbuf, "true", 4)){
        crypt_action = AES_DECRYPT;
    }

    /* Assume file is encrypted. Decrypt */
    leet_state *state = (leet_state *)(fuse_get_context()->private_data);
    do_crypt(f, memstream, crypt_action, state->key);
    fflush(memstream);
#if 0
    res = pread(fileno(tmp), buf, size, offset);
#endif
    fseek(memstream, offset, SEEK_SET);
#if 0
    res = pread(fileno(memstream), buf, size, offset);
#endif
    res = fread(buf, 1, size, memstream);
    fclose(memstream);

#ifdef PRINTF_DEBUG
    fprintf(stderr, "res = %d\n", res);
#endif
    if (res == -1)
        res = -errno;

    fclose(f);
    return res;
}

static int leet_write(const char *path, const char *buf, size_t size,
        off_t offset, struct fuse_file_info *fi)
{
    FILE *f, *memstream;
    int res;
    char pathbuf[BUFSIZE];
    char *membuf;
    size_t memsize;

    (void) fi;
    leet_state *state = (leet_state *)(fuse_get_context()->private_data);
    f = fopen(_leet_fullpath(pathbuf, path, BUFSIZE), "r");
    memstream = open_memstream(&membuf, &memsize);
#ifdef PRINTF_DEBUG
    fprintf(stderr, "leet_write: fd = %d, ", fd);
#endif
    if (memstream == NULL)
        return -errno;

    char attrbuf[8];
    ssize_t attr_len = getxattr(pathbuf, ENCRYPTED_ATTR, attrbuf, 8);
    int encrypted = 0;
    if(attr_len != -1 && !memcmp(attrbuf, "true", 4)){
        encrypted = 1;
    }

    if(f != NULL){
        /* Decrypt into the temporary file */
        do_crypt(f, memstream, (encrypted ? AES_DECRYPT : AES_PASSTHRU), state->key);
        fclose(f);
    }

    fseek(memstream, offset, SEEK_SET);
#if 0
    res = pwrite(fileno(memstream), buf, size, offset);
#endif
    res = fwrite(buf, 1, size, memstream);
    fflush(memstream);
    f = fopen(pathbuf, "w");

    /* Always encrypt the file data */
    fseek(memstream, 0, SEEK_SET);
    do_crypt(memstream, f, (encrypted ? AES_ENCRYPT : AES_PASSTHRU), state->key);
    fclose(memstream);
#ifdef PRINTF_DEBUG
    fprintf(stderr, "res = %d\n", res);
#endif
    if (res == -1)
        res = -errno;

    fclose(f);
    return res;
}

static int leet_statfs(const char *path, struct statvfs *stbuf)
{
    int res;
    char buf[BUFSIZE];

    res = statvfs(_leet_fullpath(buf, path, BUFSIZE), stbuf);
#ifdef PRINTF_DEBUG
    fprintf(stderr, "leet_statfs: res = %d\n", res);
#endif
    if (res == -1)
        return -errno;

    return 0;
}

static int leet_create(const char* path, mode_t mode, struct fuse_file_info* fi) {

    (void) fi;
    (void) mode;
    char buf[BUFSIZE];

    FILE *res;
    res = fopen(_leet_fullpath(buf, path, BUFSIZE), "w");
#ifdef PRINTF_DEBUG
    fprintf(stderr, "leet_create: res = %d\n", res);
#endif
    if(res == NULL)
        return -errno;

    FILE *tmp = tmpfile();
    leet_state *state = (leet_state *)(fuse_get_context()->private_data);
    do_crypt(tmp, res, AES_ENCRYPT, state->key);
    fclose(tmp);

    if(fsetxattr(fileno(res), ENCRYPTED_ATTR, "true", 4, 0)){
        return -errno;
    }

    fclose(res);


    return 0;
}


static int xmp_release(const char *path, struct fuse_file_info *fi)
{
    /* Just a stub.	 This method is optional and can safely be left
       unimplemented */

    (void) path;
    (void) fi;
    return 0;
}

static int xmp_fsync(const char *path, int isdatasync,
        struct fuse_file_info *fi)
{
    /* Just a stub.	 This method is optional and can safely be left
       unimplemented */

    (void) path;
    (void) isdatasync;
    (void) fi;
    return 0;
}

#ifdef HAVE_SETXATTR
static int leet_setxattr(const char *path, const char *name, const char *value,
        size_t size, int flags)
{
    char buf[BUFSIZE];
    int res = lsetxattr(_leet_fullpath(buf, path, BUFSIZE), name, value, 
            size, flags);
    if (res == -1)
        return -errno;
    return 0;
}

static int leet_getxattr(const char *path, const char *name, char *value,
        size_t size)
{
    char buf[BUFSIZE];
    int res = lgetxattr(_leet_fullpath(buf, path, BUFSIZE), name, value, size);
    if (res == -1)
        return -errno;
    return res;
}

static int leet_listxattr(const char *path, char *list, size_t size)
{
    char buf[BUFSIZE];
    int res = llistxattr(_leet_fullpath(buf, path, BUFSIZE), list, size);
    if (res == -1)
        return -errno;
    return res;
}

static int leet_removexattr(const char *path, const char *name)
{
    char buf[BUFSIZE];
    int res = lremovexattr(_leet_fullpath(buf, path, BUFSIZE), name);
    if (res == -1)
        return -errno;
    return 0;
}
#endif /* HAVE_SETXATTR */

static struct fuse_operations xmp_oper = {
    .getattr	= leet_getattr,
    .access		= leet_access,
    .readlink	= leet_readlink,
    .readdir	= leet_readdir,
    .mknod		= leet_mknod,
    .mkdir		= leet_mkdir,
    .symlink	= leet_symlink,
    .unlink		= leet_unlink,
    .rmdir		= leet_rmdir,
    .rename		= leet_rename,
    .link		= leet_link,
    .chmod		= leet_chmod,
    .chown		= leet_chown,
    .truncate	= leet_truncate,
    .utimens	= leet_utimens,
    .open		= leet_open,
    .read		= leet_read,
    .write		= leet_write,
    .statfs		= leet_statfs,
    .create         = leet_create,
    .release	= xmp_release,
    .fsync		= xmp_fsync,
#ifdef HAVE_SETXATTR
    .setxattr	= leet_setxattr,
    .getxattr	= leet_getxattr,
    .listxattr	= leet_listxattr,
    .removexattr	= leet_removexattr,
#endif
};

int main(int argc, char *argv[])
{
    umask(0);
    leet_state state;

    if(argc < 4){
#ifdef SECURE_KEYPHRASE
        if(argc == 3){
            /* TODO: implement a secure key phrase input technique */

        }else{
            /* TODO: Fail or implement defaults */

        }
#endif
        fprintf(stderr, "leetfs usage: ./pa5-encfs %s %s %s\n",
                "<Key Phrase>", "<Mirror Directory>", "<Mount Point>");
        return 1;
    }

    state.rootdir = realpath(argv[2], NULL);
    strncpy(state.key, argv[1], 32);
    state.key[31] = '\0';
    
    return fuse_main(argc - 2, argv + 2, &xmp_oper, &state);
}
