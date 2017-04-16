#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>
#include <fcntl.h>
#include <stdio.h>

int main(){
    printf("%d\n", umask(0));
    write(STDERR_FILENO, "GG", 2);
    return 0;
}
