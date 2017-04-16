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
#include <arpa/inet.h>
#include <endian.h>
#include <string>

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
        int local_port;
        int rem_port;
        int pid;
        string cmd;
};
typedef map<string, sock_info> Sock;

void traverse_proc(Sock &tcp, Sock &udp, Sock &tcp6, Sock &udp6){
    DIR *dir_proc, *dir_ps;
    struct dirent *ptr1, *ptr2;
    char ps_path[100], ps_fd_path[100], link[100], fds[100], cmd[100];
    int pid;
    if((dir_proc = opendir(PROC)) != NULL){
        while((ptr1 = readdir(dir_proc))!=NULL) {
            sprintf(ps_path,"/proc/%s", ptr1->d_name);
            pid = strtol( ptr1->d_name, NULL, 10);
            if(pid > 0){
                sprintf(ps_fd_path, "%s/fd", ps_path);
                sprintf(cmd, "%s/cmdline", ps_path);
                if((dir_ps = opendir(ps_fd_path)) != NULL){
                    while((ptr2 = readdir(dir_ps))!=NULL){
                        memset(link, 0, 100 );
                        sprintf(fds, "%s/%s", ps_fd_path, ptr2->d_name);
                        readlink(fds, link, 100);
                        string s(link);
                        if(s.compare(0, 8, "socket:[") == 0){
                            s = s.substr(8, s.find(']')-8);
                            ifstream cmdline(cmd, ifstream::in);
                            string cmd_arg = "", tmp, s1, s2;
                            size_t pos;
                            getline(cmdline, tmp, '\0');
                            if( (pos = tmp.find_first_of(' ')) != string::npos){
                                s1 = tmp.substr(0, pos);
                                s2 = tmp.substr(pos);
                                cmd_arg += s1.substr(s1.find_last_of('/')+1) + s2;
                            }else
                                cmd_arg += tmp.substr(tmp.find_last_of('/')+1);
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
        }
        closedir(dir_proc);
    }

}
string hexIP_intIP(string hexIP){
    struct in6_addr tmp_ip6;
    struct in_addr tmp_ip;
    char ip_str[128];
    unsigned int ip;
    if(sscanf(hexIP.data(),
            "%2hhx%2hhx%2hhx%2hhx%2hhx%2hhx%2hhx%2hhx%2hhx%2hhx%2hhx%2hhx%2hhx%2hhx%2hhx%2hhx",
            &tmp_ip6.s6_addr[3], &tmp_ip6.s6_addr[2], &tmp_ip6.s6_addr[1], &tmp_ip6.s6_addr[0],
            &tmp_ip6.s6_addr[7], &tmp_ip6.s6_addr[6], &tmp_ip6.s6_addr[5], &tmp_ip6.s6_addr[4],
            &tmp_ip6.s6_addr[11], &tmp_ip6.s6_addr[10], &tmp_ip6.s6_addr[9], &tmp_ip6.s6_addr[8],
            &tmp_ip6.s6_addr[15], &tmp_ip6.s6_addr[14], &tmp_ip6.s6_addr[13], &tmp_ip6.s6_addr[12]) == 16){
        inet_ntop(AF_INET6, &tmp_ip6, ip_str, sizeof ip_str);
        return string(ip_str);
    }else{
        ip = (int)strtol(hexIP.data(), NULL, 16 );
        tmp_ip.s_addr = htonl(htobe32(ip));
        return string(inet_ntoa(tmp_ip));
    }
}
void build_conninfo(Sock &connInfo, ifstream &file){
    string s, local_addr, rem_addr, socket, local_port, rem_port;
    file.ignore(512,'\n');
    while(file >> s){
        getline(file, local_addr, ':');
        getline(file, local_port, ' ');
        getline(file, rem_addr, ':');
        getline(file, rem_port, ' ');
        for(int i = 0; i<6; i++)
            file >> s;
        file >> socket;
        file.ignore(512,'\n');
        connInfo[socket].local_addr = hexIP_intIP(local_addr);
        connInfo[socket].rem_addr = hexIP_intIP(rem_addr);
        connInfo[socket].local_port = stoul(local_port, nullptr, 16);
        connInfo[socket].rem_port = stoul(rem_port, nullptr, 16);
    }
}
bool regex_filt(string s1, string filt_str){
//  filt_str = ".*" + filt_str + ".*";
    regex e(filt_str);
    if(regex_search(s1, e))
        return true;
    else
        return false;
}
void print_conns(Sock &conn, Sock &conn6, string type, string filt_str){
    cout << "List of "<<type<<" connections:" << endl;
    cout << "Proto Local Address                       Foreign Address                     PID/Program name and arguments" << endl;
    for(auto it = conn.begin(); it != conn.end(); it++){
        if(regex_filt(it->second.cmd, filt_str)){
        string l_port = it->second.local_port == 0? "*":to_string(it->second.local_port),
               r_port = it->second.rem_port == 0? "*":to_string(it->second.rem_port);
        string l_addr = it->second.local_addr + ":" + l_port,
               r_addr = it->second.rem_addr + ":" + r_port,
               pid_cmd = to_string(it->second.pid) + "/" + it->second.cmd;
            if(pid_cmd.compare("0/") == 0)
                pid_cmd = "-";
            printf("%-6s%-36s%-36s%s\n", type.data(), l_addr.data(), r_addr.data(), pid_cmd.data());
        }
    }
    type += "6";
    for(auto it = conn6.begin(); it != conn6.end(); it++){

        if(regex_filt(it->second.cmd, filt_str)){
        string l_port = it->second.local_port == 0? "*":to_string(it->second.local_port),
               r_port = it->second.rem_port == 0? "*":to_string(it->second.rem_port);
        string l_addr = it->second.local_addr + ":" + l_port,
               r_addr = it->second.rem_addr + ":" + r_port,
               pid_cmd = to_string(it->second.pid) + "/" + it->second.cmd;
            if(pid_cmd.compare("0/") == 0)
                pid_cmd = "-";
            printf("%-6s%-36s%-36s%s\n", type.data(), l_addr.data(), r_addr.data(), pid_cmd.data());
        }
    }
    cout<<endl;

}
void netstat_nap(bool tcp, bool udp, string filt_str){
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
    if(tcp | both){
        print_conns(tcp_conn, tcp6_conn, "tcp", filt_str);
    }
    if(udp | both){
        print_conns(udp_conn, udp6_conn, "udp", filt_str);
    }
}
char *l_opt_arg;
char const short_options[] = "tu";
struct option long_options[] = {
    { "tcp"  , 0, NULL, 't' },
    { "udp"  , 0, NULL, 'u' },
    { 0      , 0,    0,  0  },
};
int main(int argc, char *argv[])
{
    bool tcp = false, udp = false;
    int c;
    string filt_str;
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
        default:
            fprintf(stderr, "Usage: %s [-t|--tcp] [-u|--udp] [filter-string]\n", argv[0]);
            exit(EXIT_FAILURE);
        }
    }
    if(argv[optind] != NULL){
        filt_str = argv[optind];
    }
    netstat_nap(tcp,udp,filt_str);
    return 0;
}
