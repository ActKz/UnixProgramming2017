#include <iostream>
#include <unistd.h>
#include <getopt.h>
#include <stdio.h>
#include <string.h>

#define TCP "/proc/net/tcp"
#define UDP "/proc/net/udp"
#define PROC "/proc"

char *l_opt_arg;
char* const short_options = "tu";
struct option long_options[] = {
    { "tcp", 0, NULL, 't' },
    { "udp", 0, NULL, 'u' },
    {      0,     0,     0,     0},
};
void traverse_proc(bool tcp, bool udp, char *filt_str){

}
int main(int argc, char *argv[])
{
    bool tcp = false, udp = false;
    int c;
    char arg[50];
    while((c = getopt_long (argc, argv, short_options, long_options, NULL)) != -1)
    {
        switch (c)
        {
        case 't':
            tcp = true;
            break;
        case 'u':
            udp = true;
            break;
        }
    }
    if(argv[optind] != NULL){
        strncpy(arg, argv[optind], 50);
        printf("%s\n", arg);
    }
    traverse_proc(tcp,udp,arg);
    return 0;
}
