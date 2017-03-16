#include <iostream>
#include <sys/types.h>
#include <dirent.h>
#include <unistd.h>
#include <getopt.h>
#include <stdio.h>
#include <string.h>
#include <map>
#include <fstream>
#include <regex>
using namespace std;

#define TCP "/proc/net/tcp"
#define UDP "/proc/net/udp"
#define TCP6 "/proc/net/tcp6"
#define UDP6 "/proc/net/udp6"
#define PROC "/proc"

class sock_info{
    public:
        string local_addr;
        string rem_addr;
        int pid;
        string cmd;
};
typedef map<string, sock_info> Sock;

char *l_opt_arg;
char* const short_options = "tu";
struct option long_options[] = {
    { "tcp", 0, NULL, 't' },
    { "udp", 0, NULL, 'u' },
    {      0,     0,     0,     0},
};
void traverse_proc(Sock &tcp, Sock &udp, Sock &tcp6, Sock &udp6){
    DIR *dir_proc, *dir_ps;
    struct dirent *ptr1, *ptr2;
    char ps_path[100], ps_fd_path[100], link[100], fds[100], cmd[100];
    int pid;
    char inode[20];
    dir_proc = opendir(PROC);
    while((ptr1 = readdir(dir_proc))!=NULL) {
        memset(ps_path, 0, 100);
        sprintf(ps_path,"/proc/%s", ptr1->d_name);
        pid = strtol( ptr1->d_name, NULL, 10);
        if(pid > 0){
            sprintf(ps_fd_path, "%s/fd", ps_path);
            sprintf(cmd, "%s/cmdline", ps_path);
            dir_ps = opendir(ps_fd_path);
            while((ptr2 = readdir(dir_ps))!=NULL){
                memset(link, 0, 100 );
                memset(fds, 0, 100 );
                sprintf(fds, "%s/%s", ps_fd_path, ptr2->d_name);
                readlink(fds, link, 100);
                string s(link);
                if(s.compare(0, 8, "socket:[") == 0){
                    size_t len = s.find(']')-8;
                    s = s.substr(8, len);
                    ifstream cmdline(cmd, ifstream::in);
                    string cmd_arg = "", tmp;
                    while(getline(cmdline, tmp, '\0'))
                        cmd_arg += tmp + " ";
                    if(tcp.find(s) != tcp.end()){
                        tcp[s].pid = pid;
                        tcp[s].cmd = cmd_arg;
                    }else if(udp.find(s) != udp.end()){
                        udp[s].pid = pid;
                        udp[s].cmd = cmd_arg;
                    }else if(tcp6.find(s) != tcp6.end()){
                        tcp6[s].pid = pid;
                        tcp6[s].cmd = cmd_arg;
                    }else if(udp6.find(s) != udp6.end()){
                        udp6[s].pid = pid;
                        udp6[s].cmd = cmd_arg;
                    }
                }
            }
            closedir(dir_ps);
        }
    }
    closedir(dir_proc);

}
void build_conninfo(Sock &connInfo, ifstream &file){
    string s, local_addr, rem_addr, socket;
    file.ignore(512,'\n');
    while(file >> s){
        file >> local_addr >> rem_addr;
        for(int i = 0; i<6; i++)
            file >> s;
        file >> socket;
        file.ignore(512,'\n');
        connInfo[socket].local_addr = local_addr;
        connInfo[socket].rem_addr = rem_addr;
    }
}
void netstat_nap(bool tcp, bool udp, char *filt_str){
    Sock tcp_conn, udp_conn, tcp6_conn, udp6_conn;
    ifstream net_tcp, net_tcp6, net_udp, net_udp6;
    bool both = !(tcp ^ udp);
    if(tcp | both){
        net_tcp.open(TCP, ifstream::in);
        net_tcp6.open(TCP6, ifstream::in);
    }
    if(udp | both){
        net_udp.open(UDP, ifstream::in);
        net_udp6.open(UDP6, ifstream::in);
    }

    if(net_tcp.is_open()){
        build_conninfo(tcp_conn, net_tcp);
    }
    if(net_tcp6.is_open()){
        build_conninfo(tcp6_conn, net_tcp6);
    }
    if(net_udp.is_open()){
        build_conninfo(udp_conn, net_udp);
    }
    if(net_udp6.is_open()){
        build_conninfo(udp6_conn, net_udp6);
    }
    traverse_proc(tcp_conn, udp_conn, tcp6_conn, udp6_conn);
    for(auto it = tcp_conn.begin(); it != tcp_conn.end(); it++){
        cout<<"tcp_conn["<<it->first<<"]= "<<it->second.local_addr<<", "<<it->second.rem_addr<<", "<<it->second.pid<<", "<<it->second.cmd<<endl;
    }

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
    netstat_nap(tcp,udp,arg);
    return 0;
}
