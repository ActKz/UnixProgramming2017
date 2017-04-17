#include<stdio.h>
#include<stdlib.h>
#include <unistd.h>
int main(){
    char buf[30],str[30],cpy[30],wd[1024],path[1024];
    gets(buf);
    printf("GETS: %s\n",buf);
    gets(str);
    printf("GETS: %s\n",str);
    strcat(buf, str);
    printf("STRCAT: %s\n", buf);
    strcpy(cpy,buf);
    printf("STRCPY: %s\n", cpy);
    printf("GETWD: %s\n", getwd(wd));
    printf("REALPATH: %s\n", realpath(".",path));
}
