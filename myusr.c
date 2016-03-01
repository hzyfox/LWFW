#include <stdio.h>
#include <errno.h>
#include <getopt.h>
#include <sys/ioctl.h>
#include <fcntl.h>
#include "mylwfw.h"

char* const short_options = "oangs:d:u:v:t:p";
struct option long_options[] = {
    {"version",0,NULL,'o'},
	{ "active" , 0, NULL, 'a' },
	{ "deactive"  , 0, NULL, 'd' },
	{ "getstatus"  , 0, NULL, 'g' },
	{ "denysip" , 1, NULL, 's' },
	{"denydip",1,NULL,'d'},
	{"denysport",1,NULL,'u'},
	{ "denydport"  , 1, NULL, 'v' },
	{"denytime",1,NULL,'t'},
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
	if(fd == -1 ){
	return 0;
	}
	while((c = getopt_long (argc, argv, short_options, long_options, NULL)) != -1) {
	switch(c){
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
        deny_in.sport=strtol(optarg,&str,16);
        ioctl(fd,LWFW_DENY_SPORT,deny_in.sport);
        printf("sport is %d\n",deny_in.sport);
        break;
     case 'v':
         deny_in.dport=strtol(optarg,&str,16);
         ioctl(fd,LWFW_DENY_DPORT,deny_in.dport);
         printf("dport is %d\n",deny_in.dport);
         break;
     case 't':
        deny_in.time=optarg;
        ioctl(fd,LWFW_DENY_TIME,deny_in.time);
        printf("time is %d\n",deny_in.time);
        break;
     case 'p':
        deny_in.protocl=strtol(optarg,&str,10);
        if(deny_in.protocl==1){
        deny_in.protocl=LWFW_TCP;
        ioctl(fd,LWFW_DENY_PROTOCOL,deny_in.protocl);
        printf("deny protocol is %d\n",deny_in.protocl);
        }else{
            if(deny_in.protocl==0){
                deny_in.protocl==LWFW_UDP;
                ioctl(fd,LWFW_DENY_PROTOCOL,deny_in.protocl);
        printf("deny protocol is %d\n",deny_in.protocl);
            }
        else{
        printf("无效协议类型%d ",deny_in.protocl);}
        }



        default:
        printf("no useful information\n");
    }

  }
  close(fd);
  return 0;
}
