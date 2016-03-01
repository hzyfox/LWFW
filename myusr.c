#include <stdio.h>
#include <errno.h>
#include <getopt.h>
#include <sys/ioctl.h>
#include <fcntl.h>
#include "mylwfw.h"

char* const short_options = "oangs:d:u:v:x:y:p:";
struct option long_options[] =
{
    {"version",0,NULL,'o'},
    { "active" , 0, NULL, 'a' },
    { "deactive"  , 0, NULL, 'n' },
    { "getstatus"  , 0, NULL, 'g' },
    { "denysip" , 1, NULL, 's' },
    {"denydip",1,NULL,'d'},
    {"denysport",1,NULL,'u'},
    { "denydport"  , 1, NULL, 'v' },
    {"timestart",1,NULL,'x'},
    {"timeend",1,NULL,'y'},
    {"denyprotocol",1,NULL,'p'},
    { 0   , 0, NULL, 0 },
};
int main(int argc, char *argv[])
{
    int c;
    int fd;
    char*str;
    struct lwfw_stats status;
    DENY_IN   deny_in;
    fd = open("/dev/mylwfw",O_RDWR);
    if(fd == -1 )
    {
        return 0;
    }
    while((c = getopt_long (argc, argv, short_options, long_options, NULL)) != -1)
    {
        switch(c)
        {
        case 'o':
            ioctl(fd,LWFW_GET_VERS);
            break;
        case 'a':
            ioctl(fd,LWFW_ACTIVATE);
            printf("active successfully\n");
            break;
        case 'n':
            ioctl(fd,LWFW_DEACTIVATE);
            break;
        case 'g':
            ioctl(fd,LWFW_GET_STATS,status);
            printf("if_dropped is %x\n",status.if_dropped);
            printf("ip_dropped is %x\n",status.ip_dropped);
            printf("tcp_dropped is %x\n",status.tcp_dropped);
            printf("total_dropped is %x\n",status.total_dropped);
            printf("total_seen is %x\n",status.total_seen);
            break;

        case 's':
            deny_in.sip=optarg;
            ioctl(fd,LWFW_DENY_SIP,deny_in.sip);
            printf("sip is %s\n",deny_in.sip);
            break;
        case 'd':
            deny_in.dip=optarg;
            ioctl(fd,LWFW_DENY_DIP,deny_in.dip);
            printf("dip is %s\n",deny_in.dip);
            break;
        case 'u':
            deny_in.sport=strtol(optarg,&str,10);
            ioctl(fd,LWFW_DENY_SPORT,deny_in.sport);
            printf("sport is %d\n",deny_in.sport);
            break;
        case 'v':
            deny_in.dport=strtol(optarg,&str,10);
            ioctl(fd,LWFW_DENY_DPORT,deny_in.dport);
            printf("dport is %d\n",deny_in.dport);
            break;
        case 'x':
            deny_in.timestart=strtol(optarg,&str,10);
            ioctl(fd,LWFW_DENY_TIME_START,deny_in.timestart);
            printf("timestart is %u\n",deny_in.timestart);
            break;
        case 'y':
            deny_in.timeend=strtol(optarg,&str,10);
            ioctl(fd,LWFW_DENY_TIME_END,deny_in.timeend);
            printf("timeend is %u\n",deny_in.timeend);
            break;
        case 'p':
        {
            deny_in.protocl=strtol(optarg,&str,10);
            if(deny_in.protocl==1)
            {
                deny_in.protocl=LWFW_TCP;
                ioctl(fd,LWFW_DENY_PROTOCOL,deny_in.protocl);
                printf("deny protocol is %d\n",deny_in.protocl);
            }
            else
            {
                if(deny_in.protocl==0)
                {
                    deny_in.protocl==LWFW_UDP;
                    ioctl(fd,LWFW_DENY_PROTOCOL,deny_in.protocl);
                    printf("deny protocol is %d\n",deny_in.protocl);
                }
                else
                {
                    printf("无效协议类型%d ",deny_in.protocl);
                }
            }
            break;
        }


        default:
            printf("no useful information\n");
        }

    }
    close(fd);
    return 0;
}
