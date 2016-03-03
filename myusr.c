#include <stdio.h>
#include <errno.h>
#include <getopt.h>
#include <sys/ioctl.h>
#include <fcntl.h>
#include<stdio.h>
#include<stdlib.h>
#include<string.h>
#include "mylwfw.h"

char* const short_options = "GHRSioangs:d:u:v:x:y:p:D:z:";
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
    {"help",0,NULL,'H'},
    {"act",1,NULL,'z'},
    {"GetLog",0,NULL,'G'},
    { 0   , 0, NULL, 0 },
};
unsigned int inet_addr(char *str);
int main(int argc, char *argv[])
{
    int c;
    DENY_IN  rule[20];
    DENY_IN log[100];
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
            printf("time_dropped is %u\n",status.time_dropped);
            printf("total_dropped is %lu\n",status.total_dropped);
            printf("total_seen is %lu\n",status.total_seen);
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
            if(deny_in.protocl==LWFW_TCP)
            {
                deny_in.protocl=LWFW_TCP;
                ioctl(fd,LWFW_DENY_PROTOCOL,deny_in.protocl);
                printf("deny protocol is tcp\n");
            }
            else
            {
                if(deny_in.protocl==LWFW_UDP)
                {
                    deny_in.protocl=LWFW_UDP;
                    ioctl(fd,LWFW_DENY_PROTOCOL,deny_in.protocl);
                    printf("deny protocl is udp\n");
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
                    printf("\n\nthe %d rule dport :%lu ",j++,rule[i].dport);
                if(rule[i].sport==LWFW_ANY_SPORT)
                    printf(" sport :any ");
                else
                    printf("sport :%lu ",rule[i].sport);
                if(rule[i].protocl==LWFW_TCP)
                {
                    printf(" protocol : tcp ");
                }
                if(rule[i].protocl==LWFW_UDP)
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
            FILE*out,*out_see;
            out=fopen("/home/foxub/MY_LWFW/rule.txt","w");
            out_see=fopen("/home/foxub/MY_LWFW/rule_see.txt","w");
            while(rule[i].copy_flag!=COPY_END_FULL)
            {
                fwrite(&rule[i],sizeof(DENY_IN),1,out);
                fprintf(out_see,"sip: %u.%u.%u.%u dip: %u.%u.%u.%u ",rule[i].dip & 0x000000FF, (rule[i].dip & 0x0000FF00) >> 8,
                        (rule[i].dip & 0x00FF0000) >> 16, (rule[i].dip & 0xFF000000) >> 24,rule[i].sip & 0x000000FF, (rule[i].sip & 0x0000FF00) >> 8,
                        (rule[i].sip & 0x00FF0000) >> 16, (rule[i].sip & 0xFF000000) >> 24);
                if(rule[i].protocl==LWFW_UDP)
                {
                    fprintf(out_see,"protocl:UDP  ");
                }
                if(rule[i].protocl==LWFW_TCP)
                {
                    fprintf(out_see,"protocl:TCP ");
                }
                if(rule[i].protocl==LWFW_ANY_PROTOCOL)
                {
                    fprintf(out_see,"any protocl  ");
                }
                if(rule[i].dport==LWFW_ANY_DPORT)
                {
                    fprintf(out_see,"dport: any port");
                }
                else
                {
                    fprintf(out_see,"dport:%lu",rule[i].dport);
                }
                if(rule[i].sport==LWFW_ANY_SPORT)
                {
                    fprintf(out_see,"sport: any port ");
                }
                else
                {
                    fprintf(out_see,"sport:%lu ",rule[i].sport);
                }
                if(rule[i].timestart==LWFW_ANY_TIME)
                {
                    fprintf(out_see,"timestart: any ");
                }
                else
                {
                    fprintf(out_see,"timestart: %d",rule[i].timestart);
                }

                    if(rule[i].timeend==LWFW_ANY_TIME)
                    {
                        fprintf(out_see,"timeend: any \n");
                    }
                    else
                    {
                        fprintf(out_see,"timeend: %d\n",rule[i].timeend);
                    }


                    i++;
                }
                fwrite(&rule[i],sizeof(DENY_IN),1,out);
                fprintf(out_see,"sip: %u.%u.%u.%u dip: %u.%u.%u.%u ",rule[i].dip & 0x000000FF, (rule[i].dip & 0x0000FF00) >> 8,
                        (rule[i].dip & 0x00FF0000) >> 16, (rule[i].dip & 0xFF000000) >> 24,rule[i].sip & 0x000000FF, (rule[i].sip & 0x0000FF00) >> 8,
                        (rule[i].sip & 0x00FF0000) >> 16, (rule[i].sip & 0xFF000000) >> 24);
                if(rule[i].protocl==LWFW_UDP)
                {
                    fprintf(out_see,"protocl:UDP  ");
                }
                if(rule[i].protocl==LWFW_TCP)
                {
                    fprintf(out_see,"protocl:TCP ");
                }
                if(rule[i].protocl==LWFW_ANY_PROTOCOL)
                {
                    fprintf(out_see,"any protocl  ");
                }
                if(rule[i].dport==LWFW_ANY_DPORT)
                {
                    fprintf(out_see,"dport: any port ");
                }
                else
                {
                    fprintf(out_see,"dport:%lu ",rule[i].dport);
                }
                if(rule[i].sport==LWFW_ANY_SPORT)
                {
                    fprintf(out_see,"sport: any port ");
                }
                else
                {
                    fprintf(out_see,"sport:%lu ",rule[i].sport);
                }
                if(rule[i].timestart==LWFW_ANY_TIME)
                {
                    fprintf(out_see,"timestart: any ");
                }
                else
                {
                    fprintf(out_see,"timestart: %d ",rule[i].timestart);
                }

                if(rule[i].timeend==LWFW_ANY_TIME)
                {
                    fprintf(out_see,"timeend: any \n");
                }
                else
                {
                    fprintf(out_see,"timeend: %d\n",rule[i].timeend);
                }
                fclose(out);
                fclose(out_see);


                break;
            }
            case 'R':
            {
                FILE*in;
                i=0;
                in=fopen("/home/foxub/MY_LWFW/rule.txt","r");
                if(feof(in))
                {
                    printf("rule is empty\n");
                }
                while(!feof(in))
                {
                    fread(&rule[i++],sizeof(DENY_IN),1,in);
                }
                i=0;
                while(rule[i].copy_flag!=COPY_END_FULL)
                {
                    ioctl(fd,LWFW_READ_RULE,&rule[i]);
                    i++;
                }
                ioctl(fd,LWFW_READ_RULE,&rule[i]);
                fclose(in);
                break;
            }
            case 'H':
            {
                printf("\n************************************简易防火墙使用说明********************************************\n");
                printf("1:   本防火墙是基于命令的格式配置修改加载规则的\n");
                printf("2:    -a 命令是激活防火墙，同时创建一个链表节点，因此要输入新规则必须要使用-a\n");
                printf("3:    -s 后面跟源ip地址\n");
                printf("4:    -d 后面跟目的ip地址 \n");
                printf("5:   -u 后面源端口     输入十进制数\n");
                printf("6:   -v  后面跟目的端口  输入十进制数\n");
                printf("7:   -x  要禁用的起始时间 0-23之间的数\n");
                printf("8:   -y  要禁用的终止时间 0-23之间的数\n");
                printf("9:    本防火墙是一个默认拒绝的防火墙，所有输入的规则都将是视为您将要禁止的rule\n");
                printf("10: -p 1代表tcp协议，0代表udp协议\n");
                break;
            }
            case 'z':
            {
                deny_in.act=strtol(optarg,&str,10);
                if(deny_in.act==0)
                {
                    printf("你设置的是拒绝\n");
                }
                if(deny_in.act==1)
                {
                    printf("你设置的是接受\n");
                }
                else
                {
                    printf("你设置的act %u不合法\n",deny_in.act);
                }
                ioctl(fd,LWFW_ACT,deny_in.act);
                break;
            }
            case 'G':
            {
                ioctl(fd,LWFW_GET_LOG,log);
                if(log[0].copy_flag==COPY_END_EMPTY)
                {
                    printf("no log to get\n");
                    break;
                }
                i=0,j=0;
                FILE*log_out;
                log_out=fopen("/home/foxub/MY_LWFW/log.txt","w");
                while(log[i].copy_flag!=COPY_END_FULL)
                {

                    fprintf(log_out,"sip: %u.%u.%u.%u dip: %u.%u.%u.%u sport: %lu dport: %lu ",log[i].dip & 0x000000FF, (log[i].dip & 0x0000FF00) >> 8,
                            (log[i].dip & 0x00FF0000) >> 16, (log[i].dip & 0xFF000000) >> 24,log[i].sip & 0x000000FF, (log[i].sip & 0x0000FF00) >> 8,
                            (log[i].sip & 0x00FF0000) >> 16, (log[i].sip & 0xFF000000) >> 24,log[i].sport,log[i].dport);
                    if(log[i].protocl==LWFW_UDP)
                    {
                        fprintf(log_out,"protocl:UDP\n");
                    }
                    if(log[i].protocl==LWFW_TCP)
                    {
                        fprintf(log_out,"protocl:TCP\n");
                    }
                    if(log[i].protocl==LWFW_ANY_PROTOCOL)
                    {
                        fprintf(log_out,"any protocl\n");
                    }


                    i++;
                }

                fprintf(log_out,"sip: %u.%u.%u.%u dip: %u.%u.%u.%u sport: %lu dport: %lu " ,log[i].dip & 0x000000FF, (log[i].dip & 0x0000FF00) >> 8,
                        (log[i].dip & 0x00FF0000) >> 16, (log[i].dip & 0xFF000000) >> 24,log[i].sip & 0x000000FF, (log[i].sip & 0x0000FF00) >> 8,
                        (log[i].sip & 0x00FF0000) >> 16, (log[i].sip & 0xFF000000) >> 24,log[i].sport,log[i].dport);
                if(log[i].protocl==LWFW_UDP)
                {
                    fprintf(log_out,"protocl:UDP\n");
                }
                if(log[i].protocl==LWFW_TCP)
                {
                    fprintf(log_out,"protocl:TCP\n");
                }
                if(log[i].protocl==LWFW_ANY_PROTOCOL)
                {
                    fprintf(log_out,"any protocl\n");
                }
                fclose(log_out);
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
