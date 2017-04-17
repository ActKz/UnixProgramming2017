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
#include <stddef.h>
#include <stdint.h>
#include <limits.h>

static int out;
#define typename(x) _Generic((x),        /* Get the name of a type */             \
                _Bool: 0,           unsigned char: 9,\
                 char: 1,             signed char: 10,\
            short int: 2,      unsigned short int: 11,\
                  int: 3,            unsigned int: 12,\
             long int: 4,       unsigned long int: 13,\
        long long int: 5,  unsigned long long int: 14,\
                float: 6,                  double: 15,\
          long double: 7,                  char *: 16,\
               void *: 8,                   int *: 17,\
              const char *: 19, default: 18, const void *: 20/*, struct stat*:21, FILE*:22, DIR*:23*/)
/*#define STAT(stat) do{\
        struct stat* tmp = stat;\
        dprintf("{Size: %d,Perm: %d}", tmp->st_size, tmp->st_mode);\
    }while(0)
#define GET_FILE_NAME(a) do{\
	char path[1024];\
    char result[1024];\
    int fd = fileno(a); \
    sprintf(path, "/proc/self/fd/%d", fd);\
    memset(result, 0, 1024));\
    readlink(path, result, 1023);\
    }while(0)*/
#define D(a) do{\
        char *tmp;\
        switch (typename(a)){\
            case 2:case 3:case 4:case 5:case 11:case 12:case 13:case 14: dprintf(out,"%d",a);break;\
            case 16:case 19:case 20: dprintf(out,"'%s'",a);break;\
            case 1:case 9:case 10: dprintf(out,"'%c'",a);break;\
            case 8:case 18: dprintf(out,"%p", a);break;\
            case 6:case 7:case 15: dprintf(out,"%f", a);break;\
            case 17:dprintf(out,"%d", a);break;\
            case 21:dprintf(out,"HA");break;\
            case 22:GET_FILE_NAME(a);break;\
			case 23:dprintf(out,"DIRRRRRR");break;\
        }\
    }while(0)
//#define ARGPRINT(fmt, func, ... ) dprintf(out, fmt, #func, __VA_ARGS__)
#define LDLIB(func) do{\
    if(old_ ## func == NULL) {\
        void *handle = dlopen("libc.so.6", RTLD_LAZY);\
        if(handle == NULL){\
            fprintf(stderr, "libc.so.6 load error\n");\
            exit(1);\
        }\
        old_ ## func = dlsym(handle, #func );\
    }\
    }while(0)
#define MONITOR_ARG4(func, arg1, arg2, arg3, arg4) do{\
    LDLIB(func);\
    if(old_ ## func != NULL){\
        res = old_ ## func (arg1, arg2, arg3, arg4);\
        dprintf(out,"[monitor] %s(",#func);D(arg1);dprintf(out,",");D(arg2);dprintf(out,",");D(arg3);dprintf(out,",");D(arg4);dprintf(out,") = ");D(res);\
        dprintf(out,"\n");\
        return res;\
    }\
    }while(0)
#define MONITOR_ARG3(func, arg1, arg2, arg3) do{\
        LDLIB(func);\
    if(old_ ## func != NULL){\
        res = old_ ## func (arg1, arg2, arg3);\
        dprintf(out,"[monitor] %s(",#func);D(arg1);dprintf(out,",");D(arg2);dprintf(out,",");D(arg3);dprintf(out,") = ");D(res);\
        dprintf(out,"\n");\
        return res;\
    }\
    }while(0)
#define MONITOR_ARG2_NORET(func, arg1, arg2) do{\
    LDLIB(func);\
    if(old_ ## func != NULL){\
        old_ ## func (arg1, arg2);\
        dprintf(out,"[monitor] %s(",#func);D(arg1);dprintf(out,",");D(arg2);dprintf(out,")");\
        dprintf(out,"\n");\
    }\
    }while(0)
#define MONITOR_ARG2(func, arg1, arg2) do{\
        LDLIB(func);\
    if(old_ ## func != NULL){\
        res = old_ ## func (arg1, arg2);\
        dprintf(out, "[monitor] %s(",#func);D(arg1);dprintf(out, ",");D(arg2);dprintf(out, ") = ");D(res);\
        dprintf(out, "\n");\
        return res;\
    }\
    }while(0)
#define MONITOR_ARG1_NORET(func, arg) do{\
        LDLIB(func);\
    if(old_ ## func != NULL){\
        old_ ## func (arg);\
        dprintf(out,"[monitor] %s(",#func);D(arg);dprintf(out,")");\
        dprintf(out,"\n");\
    }\
    }while(0)
#define MONITOR_ARG1(func, arg) do{\
    LDLIB(func);\
    if(old_ ## func != NULL){\
        res = old_ ## func (arg);\
        dprintf(out,"[monitor] %s(",#func);D(arg);dprintf(out,") = ");D(res);\
        dprintf(out,"\n");\
        return res;\
    }\
    }while(0)
#define MONITOR_ARG0(func) do{\
        LDLIB(func);\
    if(old_ ## func != NULL){\
        res = old_ ## func ();\
        dprintf(out,"[monitor] %s() = ",#func);D(res);\
        dprintf(out,"\n");\
        return res;\
    }\
    }while(0)
/*
#define MONITOR(func , ... ) do{\
	LDLIB(func);\
    if(old_ ## func != NULL){\
        res = old_ ## func (__VA_ARGS__);\
		dprintf(out,"[monitor] %s()",#func);\
		return res;\
    }\
    }while(0)
*/

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


int (*old_closedir)(DIR *dirp) = NULL;
int closedir(DIR *dirp){ int res;MONITOR_ARG1(closedir, dirp);}

int (*old_creat)(const char *path, mode_t mode) = NULL;
int creat(const char *path, mode_t mode){ int res;MONITOR_ARG2(creat, path, mode);}

char* (*old_tmpnam)(char *s) = NULL;
char *tmpnam(char *s){ char* res;MONITOR_ARG1(tmpnam, s);}

int (*old_setenv)(const char *name, const char *value, int overwrite) = NULL;
int setenv(const char *name, const char *value, int overwrite){ int res;MONITOR_ARG3(setenv, name, value, overwrite);}

void (*old__exit)(int status) = NULL;
void _exit(int status){ MONITOR_ARG1_NORET(_exit, status);}

int (*old_fchown)(int fd, uid_t owner, gid_t group) = NULL;
int fchown(int fd, uid_t owner, gid_t group){ int res;MONITOR_ARG3(fchown, fd, owner, group);}

uid_t (*old_getuid)(void) = NULL;
uid_t getuid(void){ uid_t res;MONITOR_ARG0(getuid);}

int (*old_setegid)(gid_t egid) = NULL;
int setegid(gid_t egid){ int res;MONITOR_ARG1(setegid, egid);}

int (*old_chmod)(const char *path, mode_t mode) = NULL;
int chmod(const char *path, mode_t mode){ int res;MONITOR_ARG2(chmod, path, mode);}

DIR *(*old_fdopendir)(int fd) = NULL;
DIR *fdopendir(int fd){ DIR* res;MONITOR_ARG1(fdopendir, fd);}

int (*old_open)(const char *path, int oflag, ... ) = NULL;
int open(const char *path, int oflag, ... ){
    int res;
    va_list args;
    va_start(args, oflag);
    mode_t mode = va_arg(args, mode_t);
    if(args == 0)
        MONITOR_ARG2(open, path, oflag);
    else
        MONITOR_ARG3(open, path, oflag, mode);
    va_end(args);
}

void (*old_exit)(int status) = NULL;
void exit(int status){ MONITOR_ARG1_NORET(exit, status);}

void (*old_srand)(unsigned int seed) = NULL;
void srand(unsigned int seed){ MONITOR_ARG1_NORET(srand, seed);}

int (*old_execl)(const char *path, const char *arg, ...) = NULL;
int execl(const char *path, const char *arg, ...){
	va_list ap;
	int res, argno = 0;
    char *array[20 +1];
	char tmp[512];
	memset(tmp,'\0',512);
    va_start(ap, arg);
	dprintf(out,"[monitor] execl(");
    while (arg != NULL && argno < 20)
    {
        array[argno++] = arg;
		dprintf(out,"'%s'",array[argno-1]);
        arg = va_arg(ap, const char *);
		if( arg != NULL )
			dprintf(out,",");
    }
    array[argno] = NULL;
    va_end(ap);
	dprintf(out,")\n");
	return execv(path, array);
}

pid_t (*old_fork)(void) = NULL;
pid_t fork(void){ pid_t res;MONITOR_ARG0(fork);}

int (*old_link)(const char *oldpath, const char *newpath) = NULL;
int link(const char *oldpath, const char *newpath){ int res;MONITOR_ARG2(link, oldpath, newpath);}

int (*old_seteuid)(uid_t euid) = NULL;
int seteuid(uid_t euid){ int res;MONITOR_ARG1(seteuid, euid);}

int (*old_fchmod)(int fd, mode_t mode) = NULL;
int fchmod(int fd, mode_t mode){ int res;MONITOR_ARG2(fchmod, fd, mode);}

DIR *(*old_opendir)(const char *name) = NULL;
DIR *opendir(const char *name){ DIR* res;MONITOR_ARG1(opendir, name);}

int (*old_remove)(const char *pathname) = NULL;
int remove(const char *pathname){ int res;MONITOR_ARG1(remove, pathname);}

char *(*old_getenv)(const char *name) = NULL;
char *getenv(const char *name){ char* res;MONITOR_ARG1(getenv, name);}

int (*old_system)(const char *command) = NULL;
int system(const char *command){ int res;MONITOR_ARG1(system, command);}

int (*old_execle)(const char *path, const char *arg, ...) = NULL;
int execle(const char *path, const char *arg,...){
    ptrdiff_t argc;
    va_list ap;
    va_start (ap, arg);
    for (argc = 1; va_arg (ap, const char *); argc++)
    {
        if (argc == INT_MAX)
        {
            va_end (ap);
            errno = E2BIG;
            return -1;
        }
    }
    va_end (ap);
    ptrdiff_t i;
    char *argv[argc + 1];
    char **envp;
    va_start (ap, arg);
    argv[0] = (char *) arg;
	dprintf(out, "[monitor] execle(");
    for (i = 1; i <= argc; i++){
        argv[i] = va_arg (ap, char *);
		dprintf(out, "%s", argv[i]);
		if(i != argc)
			dprintf(out, ",");
	}
    envp = va_arg (ap, char **);
    va_end (ap);
	dprintf(out,")\n");
	return execve(path, argv, envp);
}

int (*old_fsync)(int fd) = NULL;
int fsync(int fd){ int res;MONITOR_ARG1(fsync, fd);}

int (*old_pipe)(int pipefd[2]) = NULL;
int pipe(int pipefd[2]){ int res;MONITOR_ARG1(pipe, pipefd);}

int (*old_setgid)(gid_t gid) = NULL;
int setgid(gid_t gid){ int res;MONITOR_ARG1(setgid, gid);}

//int (*old_fstat)(int fd, struct stat *buf) = NULL;
//int fstat(int fd, struct stat *buf){ int res;MONITOR_ARG2(fstat, fd, buf);}
int (*old___fxstat)(int ver, int fildes, struct stat * stat_buf) = NULL;
int __fxstat(int ver, int fildes, struct stat * stat_buf){ int res;MONITOR_ARG3(__fxstat, ver, fildes, stat_buf);}

struct dirent *(*old_readdir)(DIR *dirp) = NULL;
struct dirent *readdir(DIR *dirp){ struct dirent* res;MONITOR_ARG1(readdir, dirp);}

int (*old_rename)(const char *oldpath, const char *newpath) = NULL;
int rename(const char *oldpath, const char *newpath){ int res;MONITOR_ARG2(rename, oldpath, newpath);}

char *(*old_mkdtemp)(char *template) = NULL;
char *mkdtemp(char *template){ char* res;MONITOR_ARG1(mkdtemp, template);}

int (*old_chdir)(const char *path) = NULL;
int chdir(const char *path){ int res;MONITOR_ARG1(chdir, path);}

int (*old_execlp)(const char *file, const char *arg, ...) = NULL;
int execlp(const char *file, const char *arg, ...){
	va_list ap;
	int res, argno = 0;
    char *array[20 +1];
	char tmp[512];
	memset(tmp,'\0',512);
    va_start(ap, arg);
	dprintf(out,"[monitor] execlp(");
    while (arg != NULL && argno < 20)
    {
        array[argno++] = arg;
		dprintf(out,"'%s'",array[argno-1]);
        arg = va_arg(ap, const char *);
		if( arg != NULL )
			dprintf(out,",");
    }
    array[argno] = NULL;
    va_end(ap);
	dprintf(out,")\n");
	return execvp(file, array);
}

int (*old_ftruncate)(int fd, off_t length) = NULL;
int ftruncate(int fd, off_t length){ int res;MONITOR_ARG2(ftruncate, fd, length);}

ssize_t (*old_pread)(int fd, void *buf, size_t count, off_t offset) = NULL;
ssize_t pread(int fd, void *buf, size_t count, off_t offset){ ssize_t res;MONITOR_ARG4(pread, fd, buf, count, offset);}

int (*old_setuid)(uid_t uid) = NULL;
int setuid(uid_t uid){ int res;MONITOR_ARG1(setuid, uid);}

//lstat
int (*old___lxstat) (int vers, const char *name, struct stat *buf) = NULL;
int __lxstat (int vers, const char *name, struct stat *buf){ int res;MONITOR_ARG3(__lxstat, vers, name, buf);}

int (*old_readdir_r)(DIR *dirp, struct dirent *entry, struct dirent **result) = NULL;
int readdir_r(DIR *dirp, struct dirent *entry, struct dirent **result){ int res;MONITOR_ARG3(readdir_r, dirp, entry, result);}

void (*old_setbuf)(FILE *stream, char *buf) = NULL;
void setbuf(FILE *stream, char *buf){ MONITOR_ARG2_NORET(setbuf, stream, buf);}

int (*old_mkstemp)(char *template) = NULL;
int mkstemp(char *template){ int res;MONITOR_ARG1(mkstemp, template);}

int (*old_chown)(const char *path, uid_t owner, gid_t group) = NULL;
int chown(const char *path, uid_t owner, gid_t group){ int res;MONITOR_ARG3(chown, path, owner, group);}

int (*old_execv)(const char *path, char *const argv[]) = NULL;
int execv(const char *path, char *const argv[]){ int res;MONITOR_ARG2(execv, path, argv);}

char *(*old_getcwd)(char *buf, size_t size) = NULL;
char *getcwd(char *buf, size_t size){ char* res;MONITOR_ARG2(getcwd, buf, size);}

ssize_t (*old_pwrite)(int fd, const void *buf, size_t count, off_t offset) = NULL;
ssize_t pwrite(int fd, const void *buf, size_t count, off_t offset){ ssize_t res;MONITOR_ARG4(pwrite, fd, buf, count, offset);}

unsigned int (*old_sleep)(unsigned int seconds) = NULL;
unsigned int sleep(unsigned int seconds){ unsigned int res;MONITOR_ARG1(sleep, seconds);}

int (*old_mkdir)(const char *pathname, mode_t mode) = NULL;
int mkdir(const char *pathname, mode_t mode){ int res;MONITOR_ARG2(mkdir, pathname, mode);}

void (*old_rewinddir)(DIR *dirp) = NULL;
void rewinddir(DIR *dirp){ MONITOR_ARG1_NORET(rewinddir, dirp);}

int (*old_setvbuf)(FILE *stream, char *buf, int mode, size_t size) = NULL;
int setvbuf(FILE *stream, char *buf, int mode, size_t size){ int res;MONITOR_ARG4(setvbuf, stream, buf, mode, size);}

int (*old_putenv)(char *string) = NULL;
int putenv(char *string){ int res;MONITOR_ARG1(putenv, string);}

int (*old_close)(int fd) = NULL;
int close(int fd){ int res;MONITOR_ARG1(close, fd);}

int (*old_execve)(const char *filename, char *const argv[],
        char *const envp[]) = NULL;
int execve(const char *filename, char *const argv[],
        char *const envp[]){ int res;MONITOR_ARG3(execve, filename, argv, envp);}

gid_t (*old_getegid)(void) = NULL;
gid_t getegid(void){ gid_t res;MONITOR_ARG0(getegid);}

ssize_t (*old_read)(int fd, void *buf, size_t count) = NULL;
ssize_t read(int fd, void *buf, size_t count){ ssize_t res;MONITOR_ARG3(read, fd, buf, count);}

int (*old_symlink)(const char *oldpath, const char *newpath) = NULL;
int symlink(const char *oldpath, const char *newpath){ int res;MONITOR_ARG2(symlink, oldpath, newpath);}

int (*old_mkfifo)(const char *pathname, mode_t mode) = NULL;
int mkfifo(const char *pathname, mode_t mode){ int res;MONITOR_ARG2(mkfifo, pathname, mode);}

void (*old_seekdir)(DIR *dirp, long offset) = NULL;
void seekdir(DIR *dirp, long offset){ MONITOR_ARG2_NORET(seekdir, dirp, offset);}

char *(*old_tempnam)(const char *dir, const char *pfx) = NULL;
char *tempnam(const char *dir, const char *pfx){ char* res;MONITOR_ARG2(tempnam, dir, pfx);}

int (*old_rand)(void) = NULL;
int rand(void){ int res;MONITOR_ARG0(rand);}

int (*old_dup)(int oldfd) = NULL;
int dup(int oldfd){ int res;MONITOR_ARG1(dup, oldfd);}

int (*old_execvp)(const char *file, char *const argv[]) = NULL;
int execvp(const char *file, char *const argv[]){ int res;MONITOR_ARG2(execvp, file, argv);}

uid_t (*old_geteuid)(void) = NULL;
uid_t geteuid(void){ uid_t res;MONITOR_ARG0(geteuid);}

ssize_t (*old_readlink)(const char *path, char *buf, size_t bufsiz) = NULL;
ssize_t readlink(const char *path, char *buf, size_t bufsiz){ ssize_t res;MONITOR_ARG3(readlink, path, buf, bufsiz);}

int (*old_unlink)(const char *pathname) = NULL;
int unlink(const char *pathname){ int res;MONITOR_ARG1(unlink, pathname);}

int (*old___xstat)(int ver, const char * path, struct stat * stat_buf) = NULL;
int __xstat(int ver, const char * path, struct stat * stat_buf){ int res;MONITOR_ARG3(__xstat, ver, path, stat_buf);}

long (*old_telldir)(DIR *dirp) = NULL;
long telldir(DIR *dirp){ long res;MONITOR_ARG1(telldir, dirp);}

FILE *(*old_tmpfile)(void) = NULL;
FILE *tmpfile(void){ FILE* res;MONITOR_ARG0(tmpfile);}

int (*old_rand_r)(unsigned int *seedp) = NULL;
int rand_r(unsigned int *seedp){ int res;MONITOR_ARG1(rand_r, seedp);}

int (*old_dup2)(int oldfd, int newfd) = NULL;
int dup2(int oldfd, int newfd){ int res;MONITOR_ARG2(dup2, oldfd, newfd);}

int (*old_fchdir)(int fd) = NULL;
int fchdir(int fd){ int res;MONITOR_ARG1(fchdir, fd);}

gid_t (*old_getgid)(void) = NULL;
gid_t getgid(void){ gid_t res;MONITOR_ARG0(getgid);}

int (*old_rmdir)(const char *pathname) = NULL;
int rmdir(const char *pathname){ int res;MONITOR_ARG1(rmdir, pathname);}

ssize_t (*old_write)(int fd, const void *buf, size_t count) = NULL;
ssize_t write(int fd, const void *buf, size_t count){ ssize_t res; MONITOR_ARG3(write, fd, buf, count);}

mode_t (*old_umask)(mode_t mask) = NULL;
mode_t umask(mode_t mask){ mode_t res; MONITOR_ARG1(umask, mask);}

// Extra
char *(*old_strcpy)(char *dest, const char *src) = NULL;
char *strcpy(char *dest, const char *src){ char* res;MONITOR_ARG2(strcpy, dest, src);}

char *(*old_gets) ( char * str ) = NULL;
char * gets ( char * str ){ char* res; MONITOR_ARG1(gets, str);}

char *(*old_strcat) ( char * destination, const char * source ) = NULL;
char * strcat ( char * dest, const char * src ){ char* res; MONITOR_ARG2(strcat, dest, src);}

char *(*old_getwd)(char *buf) = NULL;
char *getwd(char *buf){ char* res;MONITOR_ARG1(getwd, buf);}

char *(*old_realpath)(const char *path, char *resolved_path) = NULL;
char *realpath(const char *path, char *resol){ char* res;MONITOR_ARG2(realpath, path, resol);}
