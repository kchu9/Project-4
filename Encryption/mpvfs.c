/*
  FUSE: Filesystem in Userspace
  Copyright (C) 2001-2007  Miklos Szeredi <miklos@szeredi.hu>

 Modified for CS 3210 by Kevin and Dennis



  gcc -Wall `pkg-config fuse --cflags` mpvfs.c -o fusexmp `pkg-config fuse --libs`

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
} mpv_state;

static char *mpv_fullpath(char *buf, const char *path, size_t bufsize){
    mpv_state *state = (mpv_state *)(fuse_get_context()->private_data);
    snprintf(buf, bufsize, "%s%s", state->rootdir, path);
    return buf;
}

static int mpv_getattr(const char *path, struct stat *stbuf)
{
	int res;
	char buf[BUFSIZE];
	res = lstat(mpv_fullpath(buf, path, BUFSIZE), stbuf);

	#ifdef PRINTF_DEBUG
	    fprintf(stderr, "mpv_getattr: res = %d\n", res);
	#endif

	if (res == -1)
		return -errno;

	return 0;
}

static int mpv_access(const char *path, int mask)
{
	int res;
	char buf[BUFSIZE];

	 res = access(mpv_fullpath(buf, path, BUFSIZE), mask);
	
	#ifdef PRINTF_DEBUG
	    fprintf(stderr, "mpv_access: res = %d\n", res);
	#endif

	if (res == -1)
		return -errno;

	return 0;
}

static int mpv_readlink(const char *path, char *buf, size_t size)
{
	int res;
	char pathbuf[BUFSIZE];

   	res = readlink(mpv_fullpath(pathbuf, path, BUFSIZE), buf, size - 1);
	
	#ifdef PRINTF_DEBUG
	    fprintf(stderr, "mpv_readlink: res = %d\n", res);
	#endif
	
	if (res == -1)
		return -errno;

	buf[res] = '\0';
	return 0;
}


static int mpv_readdir(const char *path, void *buf, fuse_fill_dir_t filler,
		       off_t offset, struct fuse_file_info *fi)
{
	DIR *dp;
	struct dirent *de;
	char pathbuf[BUFSIZE];

	(void) offset;
	(void) fi;

	  dp = opendir(mpv_fullpath(pathbuf, path, BUFSIZE));
	#ifdef PRINTF_DEBUG
	    fprintf(stderr, "mpv_readdir: dp = %p\n", dp);
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

static int mpv_mknod(const char *path, mode_t mode, dev_t rdev)
{
	int res;
	char buf[BUFSIZE];

   	 mpv_fullpath(buf, path, BUFSIZE);
	/* On Linux this could just be 'mknod(path, mode, rdev)' but this
	   is more portable */

	#ifdef PRINTF_DEBUG
		fprintf(stderr, "mpv_mknod: ");
	#endif


	if (S_ISREG(mode)) {
		res = open(path, O_CREAT | O_EXCL | O_WRONLY, mode);
		if (res >= 0)
			res = close(res);
	} else if (S_ISFIFO(mode))
		res = mkfifo(path, mode);
	else
		res = mknod(path, mode, rdev);
	if (res == -1)
		return -errno;

	#ifdef PRINTF_DEBUG
	    fprintf(stderr, "res = %d\n", res);
	#endif
	return 0;
}

static int mpv_mkdir(const char *path, mode_t mode)
{
	int res;
 	char buf[BUFSIZE];

    	res = mkdir(mpv_fullpath(buf, path, BUFSIZE), mode);

	#ifdef PRINTF_DEBUG
	    fprintf(stderr, "mpv_mkdir: res = %d\n", res);
	#endif

	if (res == -1)
		return -errno;

	return 0;
}

static int mpv_unlink(const char *path)
{
	int res;
	  char buf[BUFSIZE];

    	res = unlink(mpv_fullpath(buf, path, BUFSIZE));
	#ifdef PRINTF_DEBUG
	    fprintf(stderr, "mpv_unlink: res = %d\n", res);
	#endif
	if (res == -1)
		return -errno;

	return 0;
}

static int mpv_rmdir(const char *path)
{
	int res;
  	char buf[BUFSIZE];

	res = rmdir(mpv_fullpath(buf, path, BUFSIZE));
	#ifdef PRINTF_DEBUG
	    fprintf(stderr, "mpv_rmdir: res = %d\n", res);
	#endif
	if (res == -1)
		return -errno;

	return 0;
}

static int mpv_symlink(const char *from, const char *to)
{
	int res;

	char full_from[BUFSIZE];
	char full_to[BUFSIZE];

	res = symlink(mpv_fullpath(full_from, from, BUFSIZE), 
		    mpv_fullpath(full_to, to, BUFSIZE));
	#ifdef PRINTF_DEBUG
	    fprintf(stderr, "mpv_symlink: res = %d\n", res);
	#endif
	if (res == -1)
		return -errno;

	return 0;
}

static int mpv_rename(const char *from, const char *to)
{
	int res;
	 char full_from[BUFSIZE];
	 char full_to[BUFSIZE];

	 res = rename(mpv_fullpath(full_from, from, BUFSIZE), 
		    mpv_fullpath(full_to, to, BUFSIZE));
	#ifdef PRINTF_DEBUG
	    fprintf(stderr, "mpv_rename: res = %d\n", res);
	#endif
	if (res == -1)
		return -errno;

	return 0;
}

static int mpv_link(const char *from, const char *to)
{
	int res;

	char full_from[BUFSIZE];
    	char full_to[BUFSIZE];

	res = link(mpv_fullpath(full_from, from, BUFSIZE), 
            mpv_fullpath(full_to, to, BUFSIZE));
	#ifdef PRINTF_DEBUG
	    fprintf(stderr, "mpv_link: res = %d\n", res);
	#endif
	if (res == -1)
		return -errno;

	return 0;
}

static int mpv_chmod(const char *path, mode_t mode)
{
	int res;
	char buf[BUFSIZE];

	   res = chmod(mpv_fullpath(buf, path, BUFSIZE), mode);
	#ifdef PRINTF_DEBUG
	    fprintf(stderr, "mpv_chmod: res = %d\n", res);
	#endif
	if (res == -1)
		return -errno;

	return 0;
}

static int mpv_chown(const char *path, uid_t uid, gid_t gid)
{
	int res;
	char buf[BUFSIZE];

	res = lchown(mpv_fullpath(buf, path, BUFSIZE), uid, gid);
	#ifdef PRINTF_DEBUG
	    fprintf(stderr, "mpv_chown: res = %d\n", res);
	#endif
	if (res == -1)
		return -errno;

	return 0;
}

static int mpv_truncate(const char *path, off_t size)
{
	int res;
	char buf[BUFSIZE];

	res = truncate(mpv_fullpath(buf, path, BUFSIZE), size);
	#ifdef PRINTF_DEBUG
	    fprintf(stderr, "mpv_truncate: res = %d\n", res);
	#endif
	if (res == -1)
		return -errno;

	return 0;
}

static int mpv_utimens(const char *path, const struct timespec ts[2])
{
	int res;
	struct timeval tv[2];
	char buf[BUFSIZE];
	tv[0].tv_sec = ts[0].tv_sec;
	tv[0].tv_usec = ts[0].tv_nsec / 1000;
	tv[1].tv_sec = ts[1].tv_sec;
	tv[1].tv_usec = ts[1].tv_nsec / 1000;

       res = utimes(mpv_fullpath(buf, path, BUFSIZE), tv);
	#ifdef PRINTF_DEBUG
	    fprintf(stderr, "mpv_utimens: res = %d\n", res);
	#endif
	if (res == -1)
		return -errno;

	return 0;
}

static int mpv_open(const char *path, struct fuse_file_info *fi)
{
	int res;
	char buf[BUFSIZE];

	 res = open(mpv_fullpath(buf, path, BUFSIZE), fi->flags);
	#ifdef PRINTF_DEBUG
	    fprintf(stderr, "mpv_open: res = %d\n", res);
	#endif
	if (res == -1)
		return -errno;

	close(res);
	return 0;
}

static int mpv_read(const char *path, char *buf, size_t size, off_t offset,
		    struct fuse_file_info *fi)
{
/*
//TODO add encryption/decryption
	int fd;
	int res;
	char pathbuf[BUFSIZE];

	(void) fi;
//*may have issue,conflicts with bbfs
	fd = open(mpv_fullpath(pathbuf, path, BUFSIZE), O_RDONLY);
	if (fd == -1)
		return -errno;

	res = pread(fd, buf, size, offset);
	if (res == -1)
		res = -errno;

	close(fd);
	return res;*/
FILE *f, *memstream;
    int res;
    char pathbuf[BUFSIZE];
    char *membuf;
    size_t memsize;

    (void) fi;
    f = fopen(mpv_fullpath(pathbuf, path, BUFSIZE), "r");
    memstream = open_memstream(&membuf, &memsize);
#ifdef PRINTF_DEBUG
    fprintf(stderr, "mpv_read: fd = %d, ", fd);
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
    mpv_state *state = (mpv_state *)(fuse_get_context()->private_data);
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

static int mpv_write(const char *path, const char *buf, size_t size,
		     off_t offset, struct fuse_file_info *fi)
{
/*
//TODO add encryption/decryption
	int fd;
	int res;
	char pathbuf[BUFSIZE];

	(void) fi;
//may have issue,conflicts with bbfs
	fd = open(mpv_fullpath(pathbuf, path, BUFSIZE), O_WRONLY);
	if (fd == -1)
		return -errno;

	res = pwrite(fd, buf, size, offset);
	if (res == -1)
		res = -errno;

	close(fd);
	return res;*/
 FILE *f, *memstream;
    int res;
    char pathbuf[BUFSIZE];
    char *membuf;
    size_t memsize;

    (void) fi;
    mpv_state *state = (mpv_state *)(fuse_get_context()->private_data);
    f = fopen(mpv_fullpath(pathbuf, path, BUFSIZE), "r");
    memstream = open_memstream(&membuf, &memsize);
#ifdef PRINTF_DEBUG
    fprintf(stderr, "mpv_write: fd = %d, ", fd);
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

static int mpv_statfs(const char *path, struct statvfs *stbuf)
{
	int res;
	char buf[BUFSIZE];

	 res = statvfs(mpv_fullpath(buf, path, BUFSIZE), stbuf);
	#ifdef PRINTF_DEBUG
	    fprintf(stderr, "mpv_statfs: res = %d\n", res);
	#endif
	if (res == -1)
		return -errno;

	return 0;
}

static int mpv_create(const char* path, mode_t mode, struct fuse_file_info* fi) {
	
    /*(void) fi;
    char buf[BUFSIZE];
   #ifdef PRINTF_DEBUG
    fprintf(stderr, "mpv_create: res = %d\n", res);
   #endif
   // may have an issue
    int res;
    res = creat(mpv_fullpath(buf, path, BUFSIZE), mode);
    if(res <0)
	return -errno;

    close(res);

    return 0;*/
 (void) fi;
    (void) mode;
    char buf[BUFSIZE];

    FILE *res;
    res = fopen(mpv_fullpath(buf, path, BUFSIZE), "w");
#ifdef PRINTF_DEBUG
    fprintf(stderr, "mpv_create: res = %d\n", res);
#endif
    if(res == NULL)
        return -errno;

    FILE *tmp = tmpfile();
    mpv_state *state = (mpv_state *)(fuse_get_context()->private_data);
    do_crypt(tmp, res, AES_ENCRYPT, state->key);
    fclose(tmp);

    if(fsetxattr(fileno(res), ENCRYPTED_ATTR, "true", 4, 0)){
        return -errno;
    }

    fclose(res);


    return 0;
}


static int mpv_release(const char *path, struct fuse_file_info *fi)
{
	/* Just a stub.	 This method is optional and can safely be left
	   unimplemented */

	(void) path;
	(void) fi;
	return 0;
}

static int mpv_fsync(const char *path, int isdatasync,
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
static int mpv_setxattr(const char *path, const char *name, const char *value,
			size_t size, int flags)
{
	 char buf[BUFSIZE];
   	 int res = lsetxattr(mpv_fullpath(buf, path, BUFSIZE), name, value, 
            size, flags);
	if (res == -1)
		return -errno;
	return 0;
}

static int mpv_getxattr(const char *path, const char *name, char *value,
			size_t size)
{
	 char buf[BUFSIZE];
    int res = lgetxattr(mpv_fullpath(buf, path, BUFSIZE), name, value, size);
	if (res == -1)
		return -errno;
	return res;
}

static int mpv_listxattr(const char *path, char *list, size_t size)
{
	  char buf[BUFSIZE];
    int res = llistxattr(mpv_fullpath(buf, path, BUFSIZE), list, size);
	if (res == -1)
		return -errno;
	return res;
}

static int mpv_removexattr(const char *path, const char *name)
{
	char buf[BUFSIZE];
  	  int res = lremovexattr(mpv_fullpath(buf, path, BUFSIZE), name);
	if (res == -1)
		return -errno;
	return 0;
}
#endif /* HAVE_SETXATTR */

static struct fuse_operations mpv_oper = {
	.getattr	= mpv_getattr,
	.access		= mpv_access,
	.readlink	= mpv_readlink,
	.readdir	= mpv_readdir,
	.mknod		= mpv_mknod,
	.mkdir		= mpv_mkdir,
	.symlink	= mpv_symlink,
	.unlink		= mpv_unlink,
	.rmdir		= mpv_rmdir,
	.rename		= mpv_rename,
	.link		= mpv_link,
	.chmod		= mpv_chmod,
	.chown		= mpv_chown,
	.truncate	= mpv_truncate,
	.utimens	= mpv_utimens,
	.open		= mpv_open,
	.read		= mpv_read,
	.write		= mpv_write,
	.statfs		= mpv_statfs,
	.create         = mpv_create,
	.release	= mpv_release,
	.fsync		= mpv_fsync,
#ifdef HAVE_SETXATTR
	.setxattr	= mpv_setxattr,
	.getxattr	= mpv_getxattr,
	.listxattr	= mpv_listxattr,
	.removexattr	= mpv_removexattr,
#endif
};

int main(int argc, char *argv[])
{
    umask(0);
    mpv_state state;

    if(argc < 4){
#ifdef SECURE_KEYPHRASE
        if(argc == 3){
            /* TODO: implement a secure key phrase input technique */

        }else{
            /* TODO: Fail or implement defaults */

        }
#endif
        fprintf(stderr, "mpvfs usage: ./pa5-encfs %s %s %s\n",
                "<Key Phrase>", "<Mirror Directory>", "<Mount Point>");
        return 1;
    }

    state.rootdir = realpath(argv[2], NULL);
    strncpy(state.key, argv[1], 32);
    state.key[31] = '\0';
    
    return fuse_main(argc - 2, argv + 2, &mpv_oper, &state);
}
/*int main(int argc, char *argv[])
{
	umask(0);
	return fuse_main(argc, argv, &mpv_oper, NULL);
}*/
