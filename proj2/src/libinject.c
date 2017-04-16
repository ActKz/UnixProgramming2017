#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#include <stdarg.h>
#include <dlfcn.h>
#include <sys/types.h>
#include <dirent.h>
#include <sys/stat.h>

static int out;
#define UI %d
#define typename(x) _Generic((x),        /* Get the name of a type */             \
                _Bool: 0,           unsigned char: 9,\
                 char: 1,             signed char: 10,\
            short int: 2,      unsigned short int: 11,\
                  int: 3,            unsigned int: UI,\
             long int: 4,       unsigned long int: 13,\
        long long int: 5,  unsigned long long int: 14,\
                float: 6,                  double: 15,\
          long double: 7,                  char *: 16,\
               void *: 8,                   int *: 17,\
              default: 18)
#define FMT_TYPE(a, ... ) typename(a) ## ,  ## FMT_TYPE(__VA_ARGS__)
#define ARGPRINT(fmt, func, ... ) dprintf(out, fmt, #func, __VA_ARGS__)
#define MONITOR(func , ... ) do{\
    if(old_ ## func == NULL) {\
        void *handle = dlopen("libc.so.6", RTLD_LAZY);\
        if(handle == NULL){\
            fprintf(stderr, "libc.so.6 load error\n");\
            exit(1);\
        }\
        old_ ## func = dlsym(handle, #func );\
    }\
    fprintf(stderr, "WOW injected!\n");\
    if(old_ ## func != NULL){\
        fprintf(stderr, FMT_TYPE(__VA_ARGS__));\
        res = (__typeof__(old_ ## func))old_ ## func (__VA_ARGS__);\
    }\
    }while(0)


__attribute__((constructor)) static void init()
{
    char *output_name = getenv("MONITOR_OUTPUT");

    if(output_name != NULL && strcmp(output_name, "stderr") == 0){
        out = STDERR_FILENO;
    } else if(output_name != NULL && strcmp(output_name, "stdout") == 0){
        out = STDOUT_FILENO;
    } else {
        if(output_name == NULL){
            output_name = "monitor.out";
        }
        if((out = open(output_name, O_WRONLY | O_CREAT | O_TRUNC, 0666)) < 0){
            perror(strerror(errno));
            exit(1);
        }
    }
}


//int (*old_closedir)(DIR *dirp) = NULL;
//int closedir(DIR *dirp){ MONITOR(closedir, dirp);}

/*int (*old_creat)(const char *path, mode_t mode) = NULL;
int creat(const char *path, mode_t mode){ MONITOR(creat, path, mode);}

char* (*old_tmpnam)(char *s) = NULL;
char *tmpnam(char *s){ MONITOR(tmpnam, s);}

int (*old_setenv)(const char *name, const char *value, int overwrite) = NULL;
int setenv(const char *name, const char *value, int overwrite){ MONITOR(setenv, name, value, overwrite);}

void (*old__exit)(int status) = NULL;
void _exit(int status){ MONITOR(_exit, status);}

int (*old_fchown)(int fd, uid_t owner, gid_t group) = NULL;
int fchown(int fd, uid_t owner, gid_t group){ MONITOR(fchown, fd, owner, group);}

uid_t (*old_getuid)(void) = NULL;
uid_t getuid(void){ MONITOR(getuid);}

int (*old_setegid)(gid_t egid) = NULL;
int setegid(gid_t egid){ MONITOR(setegid, egid);}

int (*old_chmod)(const char *path, mode_t mode) = NULL;
int chmod(const char *path, mode_t mode){ MONITOR(chmod, path, mode);}

DIR *(*old_fdopendir)(int fd) = NULL;
DIR *fdopendir(int fd){ MONITOR(fdopendir, fd);}

int (*old_open)(const char *path, int oflag, ... ) = NULL;
int open(const char *path, int oflag, ... ){
    va_list args;
    va_start(args, oflag);
    MONITOR(open, path, oflag, args);
    va_end(args);
}

void (*old_exit)(int status) = NULL;
void exit(int status){ MONITOR(exit, status);}

void (*old_srand)(unsigned int seed) = NULL;
void srand(unsigned int seed){ MONITOR(srand, seed);}

int (*old_execl)(const char *path, const char *arg, ...) = NULL;
int execl(const char *path, const char *arg, ...){
    va_list args;
    va_start(args, arg);
    MONITOR(execl, path, arg, args);
    va_end(args);
}

pid_t (*old_fork)(void) = NULL;
pid_t fork(void){ MONITOR(fork);}

int (*old_link)(const char *oldpath, const char *newpath) = NULL;
int link(const char *oldpath, const char *newpath){ MONITOR(link, oldpath, newpath);}

int (*old_seteuid)(uid_t euid) = NULL;
int seteuid(uid_t euid){ MONITOR(seteuid, euid);}

int (*old_fchmod)(int fd, mode_t mode) = NULL;
int fchmod(int fd, mode_t mode){ MONITOR(fchmod, fd, mode);}

DIR *(*old_opendir)(const char *name) = NULL;
DIR *opendir(const char *name){ MONITOR(opendir, name);

int (*old_remove)(const char *pathname) = NULL;
int remove(const char *pathname){ MONITOR(remove, pathname);}

char *(*old_getenv)(const char *name) = NULL;
char *getenv(const char *name){ MONITOR(getenv, name);}

int (*old_system)(const char *command) = NULL;
int system(const char *command){ MONITOR(system, command);}

int (*old_execle)(const char *path, const char *arg,
        ..., char * const envp[]) = NULL;
int execle(const char *path, const char *arg,
        ..., char * const envp[]){
    va_list args;
    va_start(args, arg);
    MONITOR(execl, path, arg, args, envp);
    va_end(args);
}

int (*old_fsync)(int fd) = NULL;
int fsync(int fd){ MONITOR(fsync, fd);}

int (*old_pipe)(int pipefd[2]) = NULL;
int pipe(int pipefd[2]){ MONITOR(pipe, pipefd);}

int (*old_setgid)(gid_t gid) = NULL;
int setgid(gid_t gid){ MONITOR(setgid, gid);}

int (*old_fstat)(int fd, struct stat *buf) = NULL;
int fstat(int fd, struct stat *buf){ MONITOR(fstat, fd, buf);}

struct dirent *(*old_readdir)(DIR *dirp) = NULL;
struct dirent *readdir(DIR *dirp){ MONITOR(readdir, dirp);}

int (*old_rename)(const char *oldpath, const char *newpath) = NULL;
int rename(const char *oldpath, const char *newpath){ MONITOR(rename, oldpath, newpath);}

char *(*old_mkdtemp)(char *template) = NULL;
char *mkdtemp(char *template){ MONITOR(mkdtemp, template);}

int (*old_chdir)(const char *path) = NULL;
int chdir(const char *path){ MONITOR(chdir, path);}

int (*old_execlp)(const char *file, const char *arg, ...) = NULL;
int execlp(const char *file, const char *arg, ...){
    va_list args;
    va_start(args, arg);
    MONITOR(execlp, path, arg, args, envp);
    va_end(args);
}

int (*old_ftruncate)(int fd, off_t length) = NULL;
int ftruncate(int fd, off_t length){ MONITOR(ftruncate, fd, length);}

ssize_t (*old_pread)(int fd, void *buf, size_t count, off_t offset) = NULL;
ssize_t pread(int fd, void *buf, size_t count, off_t offset){ MONITOR(pread, fd, buf, count, offset);}

int (*old_setuid)(uid_t uid) = NULL;
int setuid(uid_t uid){ MONITOR(setuid, uid);}

int (*old_lstat)(const char *path, struct stat *buf) = NULL;
int lstat(const char *path, struct stat *buf){ MONITOR(lstat, path, buf);}

int (*old_readdir_r)(DIR *dirp, struct dirent *entry, struct dirent **result) = NULL;
int readdir_r(DIR *dirp, struct dirent *entry, struct dirent **result){ MONITOR(readdir_r, dirp, entry, result);}

void (*old_setbuf)(FILE *stream, char *buf) = NULL;
void setbuf(FILE *stream, char *buf){ MONITOR(setbuf, stream, buf);

int (*old_mkstemp)(char *template) = NULL;
int mkstemp(char *template){ MONITOR(mkstemp, template);}

int (*old_chown)(const char *path, uid_t owner, gid_t group) = NULL;
int chown(const char *path, uid_t owner, gid_t group){ MONITOR(chown, path, owner, group);}

int (*old_execv)(const char *path, char *const argv[]) = NULL;
int execv(const char *path, char *const argv[]){ MONITOR(execv, path, argv);}

char *(*old_getcwd)(char *buf, size_t size) = NULL;
char *getcwd(char *buf, size_t size){ MONITOR(getcwd, buf, size);}

ssize_t (*old_pwrite)(int fd, const void *buf, size_t count, off_t offset) = NULL;
ssize_t pwrite(int fd, const void *buf, size_t count, off_t offset){ MONITOR(pwrite, fd, buf, count, offset);}

unsigned int (*old_sleep)(unsigned int seconds) = NULL;
unsigned int sleep(unsigned int seconds){ MONITOR(sleep, seconds);}

int (*old_mkdir)(const char *pathname, mode_t mode) = NULL;
int mkdir(const char *pathname, mode_t mode){ MONITOR(mkdir, pathname, mode);}

void (*old_rewinddir)(DIR *dirp) = NULL;
void rewinddir(DIR *dirp){ MONITOR(rewinddir, dirp);}

int (*old_setvbuf)(FILE *stream, char *buf, int mode, size_t size) = NULL;
int setvbuf(FILE *stream, char *buf, int mode, size_t size){ MONITOR(setvbuf, stream, buf, mode, size);}

int (*old_putenv)(char *string) = NULL;
int putenv(char *string){ MONITOR(putenv, string);}

int (*old_close)(int fd) = NULL;
int close(int fd){ MONITOR(close, fd);}

int (*old_execve)(const char *filename, char *const argv[],
        char *const envp[]) = NULL;
int execve(const char *filename, char *const argv[],
        char *const envp[]){ MONITOR(execve, filename, argv, envp);}

gid_t (*old_getegid)(void) = NULL;
gid_t getegid(void){ MONITOR(getegid);}

ssize_t (*old_read)(int fd, void *buf, size_t count) = NULL;
ssize_t read(int fd, void *buf, size_t count);

int (*old_symlink)(const char *oldpath, const char *newpath) = NULL;
int symlink(const char *oldpath, const char *newpath){ MONITOR(symlink, oldpath, newpath);}

int (*old_mkfifo)(const char *pathname, mode_t mode) = NULL;
int mkfifo(const char *pathname, mode_t mode){ MONITOR(mkfifo, pathname, mode);}

void (*old_seekdir)(DIR *dirp, long offset) = NULL;
void seekdir(DIR *dirp, long offset){ MONITOR(seekdir, dirp, offset);}

char *(*old_tempnam)(const char *dir, const char *pfx) = NULL;
char *tempnam(const char *dir, const char *pfx){ MONITOR(tempnam, dir, pfx);}

int (*old_rand)(void) = NULL;
int rand(void){ MONITOR(rand);}

int (*old_dup)(int oldfd) = NULL;
int dup(int oldfd){ MONITOR(dup, oldfd);}

int (*old_execvp)(const char *file, char *const argv[]) = NULL;
int execvp(const char *file, char *const argv[]){ MONITOR(execvp, file, argv);}

uid_t (*old_geteuid)(void) = NULL;
uid_t geteuid(void){ MONITOR(geteuid);}

ssize_t (*old_readlink)(const char *path, char *buf, size_t bufsiz) = NULL;
ssize_t readlink(const char *path, char *buf, size_t bufsiz){ MONITOR(readlink, path, buf, bufsiz);}

int (*old_unlink)(const char *pathname) = NULL;
int unlink(const char *pathname){ MONITOR(unlink, pathname);}

int (*old_stat)(const char *path, struct stat *buf) = NULL;
int stat(const char *path, struct stat *buf){ MONITOR(stat, path, buf);}

long (*old_telldir)(DIR *dirp) = NULL;
long telldir(DIR *dirp){ MONITOR(telldir, dirp);}

FILE *(*old_tmpfile)(void) = NULL;
FILE *tmpfile(void){ MONITOR(tmpfile);}

int (*old_rand_r)(unsigned int *seedp) = NULL;
int rand_r(unsigned int *seedp){ MONITOR(rand_r, seedp);}

int (*old_dup2)(int oldfd, int newfd) = NULL;
int dup2(int oldfd, int newfd){ MONITOR(dup2, oldfd, newfd);}

int (*old_fchdir)(int fd) = NULL;
int fchdir(int fd){ MONITOR(fchdir, fd);}

gid_t (*old_getgid)(void) = NULL;
gid_t getgid(void){ MONITOR(getgid);}

int (*old_rmdir)(const char *pathname) = NULL;
int rmdir(const char *pathname){ MONITOR(rmdir, pathname);}
*/
ssize_t (*old_write)(int fd, const void *buf, size_t count) = NULL;
ssize_t write(int fd, const void *buf, size_t count){
    ssize_t res;
    MONITOR(write, fd, buf, count);
    return res;
}

mode_t (*old_umask)(mode_t mask) = NULL;
mode_t umask(mode_t mask){
    mode_t res;
    MONITOR(umask, mask);
    ARGPRINT("[monitor] %s(%d) = %d\n", umask, mask, res);
    return res;
}
