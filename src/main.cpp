#include <iostream>
#include <unistd.h>
#include <getopt.h>
#include <stdio.h>
#include <string.h>
#include <map>
#include <fstream>
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

char *l_opt_arg;
char* const short_options = "tu";
struct option long_options[] = {
    { "tcp", 0, NULL, 't' },
    { "udp", 0, NULL, 'u' },
    {      0,     0,     0,     0},
};
void build_conninfo(map<string, sock_info> &connInfo, ifstream &file){
    string s, local_addr, rem_addr, socket;
    file.ignore(512,'\n');
    while(file >> s){
        file >> local_addr >> rem_addr;
        for(int i = 0; i<6; i++)
            file >> s;
        file >> socket;
        file.ignore(512,'\n');
        cout << "Socket: "<<socket<<endl;
        cout << "local: "<<local_addr<<", remote: "<<rem_addr<<endl;
        connInfo[socket].local_addr = local_addr;
        connInfo[socket].rem_addr = rem_addr;
    }
}
void netstat_nap(bool tcp, bool udp, char *filt_str){
    map<string, sock_info > tcp_conn, udp_conn, tcp6_conn, udp6_conn;
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
//  for(auto it = tcp_conn.begin(); it != tcp_conn.end(); it++){
//      cout<<"tcp_conn["<<it->first<<"]= "<<it->second.local_addr<<", "<<it->second.rem_addr<<endl;
//  }

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
