#include <stdio.h>
#include <errno.h>
#include <getopt.h>
#include <sys/ioctl.h>
#include <fcntl.h>
#include "mylwfw.h"

char* const short_options = "oangf:s:d:u:v:t:";
struct option long_options[] = {
    {"version",0,NULL,'o'},
	{ "active" , 0, NULL, 'a' },
	{ "deactive"  , 0, NULL, 'd' },
	{ "getstatus"  , 0, NULL, 'g' },
	{ "denyif" , 1, NULL, 'f' },
	{ "denysip" , 1, NULL, 's' },
	{"denydip",1,NULL,'d'},
	{"denysport",1,NULL,'u'},
	{ "denydport"  , 1, NULL, 'v' },
	{"denytime",1,NULL,'t'},
	{ 0   , 0, NULL, 0 },
};
int main(int argc, char *argv[])
{
	int c;
	int fd;
	struct lwfw_stats status;
	DENY_IN   deny_in;
	fd = open("/dev/mylwfw",O_RDWR);
	if(fd == -1 ){
	printf("open %s failed ,error: %s\n",LWFW_NAME,strerror(errno));
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
      case 'f':
       deny_in.interface=optarg;
        ioctl(fd,LWFW_DENY_IF,deny_in.interface);
        printf("interface is %s\n",deny_in.interface);
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
        deny_in.sport=optarg;
        ioctl(fd,LWFW_DENY_SPORT,deny_in.sport);
        printf("sport is %s\n",deny_in.sport);
        break;
     case 'v':
        deny_in.dport=optarg;
         ioctl(fd,LWFW_DENY_DPORT,deny_in.dport);
         printf("dport is %s\n",deny_in.dport);
         break;
     case 't':
        deny_in.time=optarg;
        ioctl(fd,LWFW_DENY_TIME,deny_in.time);
        printf("time is %s\n",deny_in.time);
        break;
        default:
        printf("no useful information\n");
    }

  }
  close(fd);
}
