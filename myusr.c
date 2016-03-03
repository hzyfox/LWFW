#include <stdio.h>
#include <errno.h>
#include <getopt.h>
#include <sys/ioctl.h>
#include <fcntl.h>
#include<stdio.h>
#include<stdlib.h>
#include<string.h>
#include "mylwfw.h"

char* const short_options = "RSioangs:d:u:v:x:y:p:D:";
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
    {"view all the rule",0,NULL,'i'},
    {"Delete Inode",1,NULL,'D'},
    {"SaveRule",0,NULL,'S'},
    {"ReadRule",0,NULL,'R'},
    { 0   , 0, NULL, 0 },
};
unsigned int inet_addr(char *str);
int main(int argc, char *argv[])
{
    int c;
    DENY_IN  rule[20];
    int i=0,j=0;
    int fd;
    char*str;
    unsigned int rule_num;
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
            ioctl(fd,LWFW_GET_STATS,&status);
            printf("sip_dropped is %d\n",status.sip_dropped);
            printf("dip_dropped is %d\n",status.dip_dropped);
            printf("tcp_dropped is %d\n",status.tcp_dropped);
            printf("udp_dropped is %d\n",status.udp_dropped);
            printf("sport_dropped is %d\n",status.sport_dropped);
            printf("dport_dropped is %d\n",status.dport_dropped);
            printf("time_dropped is %d\n",status.time_dropped);
            printf("total_dropped is %d\n",status.total_dropped);
            printf("total_seen is %d\n",status.total_seen);
            break;

        case 's':

            ioctl(fd,LWFW_DENY_SIP,optarg);
            printf("sip is %s\n",optarg);
            break;
        case 'd':

            ioctl(fd,LWFW_DENY_DIP,optarg);
            printf("dip is %s\n",optarg);
            break;
        case 'u':

            deny_in.sport=strtol(optarg,&str,10);
            ioctl(fd,LWFW_DENY_SPORT,deny_in.sport);
            printf("sport is %lu\n",deny_in.sport);
            break;
        case 'v':

            deny_in.dport=strtol(optarg,&str,10);
            ioctl(fd,LWFW_DENY_DPORT,deny_in.dport);
            printf("dport is %lu\n",deny_in.dport);
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
                printf("deny protocol is tcp");
            }
            else
            {
                if(deny_in.protocl==0)
                {
                    deny_in.protocl=LWFW_UDP;
                    ioctl(fd,LWFW_DENY_PROTOCOL,deny_in.protocl);
                    printf("deny protocl is udp");
                }
                else
                {
                    printf("无效协议类型%d ",deny_in.protocl);
                }
            }
            break;
        }
        case 'i':
        {
            ioctl(fd,LWFW_COPY_TO_USER);
            break;
        }
        case 'D':
        {
            rule_num=strtol(optarg,&str,10);
            ioctl(fd,LWFW_DELETE_INODE,rule_num);
            break;
        }
        case 'S':
        {

            ioctl(fd,LWFW_SAVE_RULE,rule);
            if(rule[0].copy_flag==COPY_END_EMPTY)
            {
                printf("no rule to save\n");
                break;
            }
            i=0,j=0;
            while(1)
            {

                if( rule[i].copy_flag==COPY_END_FULL)
                    break;
                i++;

            }
            i=0,j=0;
            while(1)
            {
                if(rule[i].dport==LWFW_ANY_DPORT)
                    printf("\n\nthe %d rule: dport :any ",j++);
                else
                    printf("\n\nthe %d rule dport :%u ",j++,rule[i].dport);
                if(rule[i].dport==LWFW_ANY_DPORT)
                    printf(" sport :any ");
                else
                    printf("sport :%u ",rule[i].sport);
                if(rule[i].protocl==1)
                {
                    printf(" protocol : tcp ");
                }
                if(rule[i].protocl==0)
                {
                    printf(" protocol : udp ");
                }
                if(rule[i].protocl==LWFW_ANY_PROTOCOL)
                {
                    printf(" protocl: any ");
                }
                if(rule[i].sip==0x00000000)
                    printf("sip:any ");
                else
                    printf("sip  address: %d.%d.%d.%d ",
                           rule[i].sip & 0x000000FF, (rule[i].sip & 0x0000FF00) >> 8,
                           (rule[i].sip & 0x00FF0000) >> 16, (rule[i].sip & 0xFF000000) >> 24);
                if(rule[i].dip==0x00000000)
                    printf("dip:any ");
                else
                    printf("dip  address: %d.%d.%d.%d ",
                           rule[i].dip & 0x000000FF, (rule[i].dip & 0x0000FF00) >> 8,
                           (rule[i].dip & 0x00FF0000) >> 16, (rule[i].dip & 0xFF000000) >> 24);
                if(rule[i].timestart==LWFW_ANY_TIME)
                {
                    printf("starttime:any ");
                }
                else
                {
                    printf(" start time:%u ",rule[i].timestart);
                }
                if(rule[i].timeend==LWFW_ANY_TIME)
                {
                    printf("end time:any \n");
                }
                else
                {
                    printf(" end time:%u \n",rule[i].timeend);
                }
                if(rule[i].copy_flag==COPY_END_FULL)
                    break;
                i++;

            }
            i=0;
            FILE*out;
            out=fopen("/home/foxub/MY_LWFW/rule.txt","w");
            while(rule[i].copy_flag!=COPY_END_FULL)
            {
                fwrite(&rule[i],sizeof(DENY_IN),1,out);
                i++;
            }
            fwrite(&rule[i],sizeof(DENY_IN),1,out);
            fclose(out);


            break;
        }
        case 'R':
        {
            FILE*in;
            i=0;
            in=fopen("/home/foxub/MY_LWFW/rule.txt","r");
            while(!feof(in)){
                fread(&rule[i++],sizeof(DENY_IN),1,in);

            }
            i=0;
            while(rule[i].copy_flag!=COPY_END_FULL){
                ioctl(fd,LWFW_READ_RULE,&rule[i]);
                i++;
            }
             ioctl(fd,LWFW_READ_RULE,&rule[i]);
        break;
        }


        default:
            printf("no useful information\n");
        }

    }
    close(fd);
    return 0;
}

unsigned int inet_addr(char *str)
{
    int a,b,c,d;
    char arr[4];
    if(str==NULL)
        return 0;
    sscanf(str,"%d.%d.%d.%d",&a,&b,&c,&d);
    arr[0] = a;
    arr[1] = b;
    arr[2] = c;
    arr[3] = d;
    return *(unsigned int*)arr;
}
