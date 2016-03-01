#include <linux/kernel.h>
#include <linux/init.h>
#include <linux/module.h>
#include <linux/version.h>
#include <linux/string.h>
#include <linux/kmod.h>
#include <linux/vmalloc.h>
#include <linux/workqueue.h>
#include <linux/spinlock.h>
#include <linux/socket.h>
#include <linux/net.h>
#include <linux/in.h>
#include <linux/skbuff.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include<linux/udp.h>
#include <linux/netfilter.h>
#include <linux/netfilter_ipv4.h>
#include <linux/icmp.h>
#include <net/sock.h>
#include<linux/timer.h>
#include <linux/timex.h>
#include<linux/rtc.h>
#include <asm/uaccess.h>
#include <asm/unistd.h>
#include <linux/if_arp.h>
#include <linux/cdev.h>           /// struct cdev
#include "mylwfw.h"
#include <linux/ktime.h>

//static int set_if_rule(char * interface);
static int set_sip_rule(char *isp);
static int set_dip_rule(char *dip);
//static int set_sport_rule(char *sport);
//static int set_dport_rule(char *dport);
//static int set_time_rule(char *time);
//static int check_tcp_packet(struct sk_buff *skb);
//static int check_udp_packet(struct sk_buff *skb);
static int check_sip_packet(struct sk_buff *skb);
static int check_dip_packet(struct sk_buff *skb);
static int check_protocol_sport(struct sk_buff*skb,DENY_IN*p);
static int check_protocol_dport(struct sk_buff*skb,DENY_IN*p);
static int check_time(struct sk_buff*skb,DENY_IN*p);
//static int check_sport_packet(struct sk_buff *skb);
//static int check_dport_packet(struct sk_buff *skb);
//static int check_time_packet(struct sk_buff *skb);

static int lwfw_ioctl( struct file *file, unsigned int cmd, unsigned long arg);
static int lwfw_open(struct inode *inode, struct file *file);
static int lwfw_release(struct inode *inode, struct file *file);

/* Various flags used by the module */
/* This flag makes sure that only one instance of the lwfw device
* can be in use at any one time. */
static int lwfw_ctrl_in_use = 0;

/* This flag marks whether LWFW should actually attempt rule checking.
 * If this is zero then LWFW automatically allows all packets. */
static int active = 0;

/* Specifies options for the LWFW module */
static unsigned int lwfw_options = (LWFW_IF_DENY_ACTIVE
                                    | LWFW_IP_DENY_ACTIVE
                                    | LWFW_PORT_DENY_ACTIVE|LWFW_TIME_DENY_ACTIVE|LWFW_PROTOCOL_DENY_ACTIVE);
static int major = 0;               /* Control device major number */

/* This struct will describe our hook procedure. */
struct nf_hook_ops nfkiller,nfkiller1;

/* Module statistics structure */
static struct lwfw_stats lwfw_statistics = {0, 0, 0, 0, 0};

/* Actual rule 'definitions'. */
/* TODO:  One day LWFW might actually support many simultaneous rules.
* Just as soon as I figure out the list_head mechanism... */
//static char *deny_if = NULL;                 /* Interface to deny */
static unsigned int deny_sip = 0x00000000;    /* IP address to deny */
static  unsigned int deny_dip=0x00000000;
//static unsigned short deny_port = 0x0000;   /* TCP port to deny */
//static unsigned int time=0x00000000;

struct cdev cdev_m;
DENY_IN  *head,*currentp;
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
/*
* This is the interface device's file_operations structure
 */
struct file_operations  lwfw_fops =
{
    .owner = THIS_MODULE,

    .unlocked_ioctl = lwfw_ioctl,

    .open = lwfw_open,

    .release = lwfw_release,
};

/*
* This is the function that will be called by the hook
*/

unsigned int lwfw_hookfn(unsigned int hooknum,
                         struct sk_buff *skb,
                         const struct net_device *in,
                         const struct net_device *out,
                         int (*okfn)(struct sk_buff *))
{
    unsigned int ret = NF_DROP;
    unsigned int check_sport=NF_DROP;
     unsigned int check_dport=NF_DROP;
     unsigned int check_t=NF_DROP;
    DENY_IN *p=head;
    /* If LWFW is not currently active, immediately return ACCEPT */
    if (!active)
        return NF_ACCEPT;

    lwfw_statistics.total_seen++;

    /* Check the interface rule first */


    /* Check the IP address rule */
    if(p==NULL){
        printk("p is NULL");
        return NF_ACCEPT;
    }
    while (p  /*&& DENY_IP_ACTIVE*/ )
    {
        set_sip_rule(p->sip);
        ret = check_sip_packet(skb);
        check_sport=check_protocol_sport(skb,p);
        check_t=check_time(skb,p);
        if (!ret && !check_sport&&!check_t) return NF_DROP;
        else{
        p=p->next;
        }
    }
    p=head;
    while(p  /*&& DENY_IP_ACTIVE*/ )
    {
        set_dip_rule(p->dip);
        ret = check_dip_packet(skb);
        check_dport=check_protocol_dport(skb,p);
        check_t=check_time(skb,p);
        if (!ret&&!check_dport&&!check_t ) return NF_DROP;
        else{
        p=p->next;
        }
    }

    /* Finally, check the TCP port rule */


    return NF_ACCEPT;               /* We are happy to keep the packet */
}

static int copy_stats(struct lwfw_stats *statbuff)
{
    NULL_CHECK(statbuff);

    copy_to_user(statbuff, &lwfw_statistics,
                 sizeof(struct lwfw_stats));

    return 0;
}

static int check_sip_packet(struct sk_buff *skb)
{
    struct sk_buff*sk=skb_copy(skb,1);
    struct iphdr *ip;
    if(!sk)
        return NF_ACCEPT;
    ip=ip_hdr(sk);
    if(ip->saddr==deny_sip||deny_sip==0x00000000)
        return NF_DROP;
    else{

        return NF_ACCEPT;}

    return NF_ACCEPT;
}

static int check_dip_packet(struct sk_buff *skb)
{
    struct sk_buff*sk=skb_copy(skb,1);
    struct iphdr *ip;
    if(!sk)
        return NF_ACCEPT;
    ip=ip_hdr(sk);
    if(ip->daddr==deny_dip||deny_dip==0x00000000)
        return NF_DROP;
    else
        return NF_ACCEPT;

    return NF_ACCEPT;
}

static int check_protocol_sport(struct sk_buff*skb,DENY_IN*p)
{
    struct sk_buff *sk=skb_copy(skb,1);
    struct tcphdr*tcph=NULL;
    struct udphdr*udph=NULL;
    const struct iphdr*iph=NULL;
    struct iphdr*ip;

    if(!skb)
    return NF_ACCEPT;
    ip=ip_hdr(sk);
    iph=ip_hdr(skb);
    if(p->protocl==LWFW_ANY_PROTOCOL&&p->sport==LWFW_ANY_SPORT)
    return NF_DROP;
    if(ip->protocol==IPPROTO_TCP&&p->protocl==LWFW_TCP){
        tcph=(void *)iph+iph->ihl*4;

        if(ntohs( tcph->source)==p->sport){
          printk("sport %d is drop",p->sport);
                return NF_DROP;
            }
    }else{
    if(ip->protocol==IPPROTO_UDP&&p->protocl==LWFW_UDP){
        udph=(void*)iph+iph->ihl*4;

        if(ntohs( tcph->source)==p->sport){
            printk("sport %d is drop",p->sport);
            return NF_DROP;
            }
            }
    }
    return NF_ACCEPT;
}

static int check_protocol_dport(struct sk_buff*skb,DENY_IN*p)
{
    struct sk_buff *sk=skb_copy(skb,1);
    struct tcphdr*tcph=NULL;
    struct udphdr*udph=NULL;
    const struct iphdr*iph=NULL;
    struct iphdr*ip;

    if(!skb)
    return NF_ACCEPT;
    ip=ip_hdr(sk);
    iph=ip_hdr(skb);
    if(p->protocl==LWFW_ANY_PROTOCOL&&p->dport==LWFW_ANY_DPORT)
    return NF_DROP;
    if(ip->protocol==IPPROTO_TCP&&p->protocl==LWFW_TCP){
        tcph=(void *)iph+iph->ihl*4;

        if(ntohs( tcph->dest)==p->dport){
          printk("dport %d is drop",p->dport);
                return NF_DROP;
            }
    }else{
    if(ip->protocol==IPPROTO_UDP&&p->protocl==LWFW_UDP){
        udph=(void*)iph+iph->ihl*4;

        if(ntohs( tcph->dest)==p->dport){
            printk("sport %d is drop",p->dport);
            return NF_DROP;
            }
            }
    }
    return NF_ACCEPT;
}
static int check_time(struct sk_buff*skb,DENY_IN*p){
    struct timex txc;
    struct rtc_time tm;
    do_gettimeofday(&(txc.time));
    rtc_time_to_tm(txc.time.tv_sec,&tm);
    printk("the system time is %d\n",tm.tm_hour);
    if(p->timeend==LWFW_ANY_TIME&&p->timestart==LWFW_ANY_TIME)
    return NF_DROP;
    if((tm.tm_hour+8)<=p->timeend&&(tm.tm_hour+8)>=p->timestart){
        return NF_DROP;
    }
    return NF_ACCEPT;
}


static int set_sip_rule(char * ip)
{
    deny_sip = inet_addr(ip);
    lwfw_statistics.ip_dropped = 0;     /* Reset drop count for IP rule */

    printk("LWFW: Set  sIP address: %d.%d.%d.%d\n",
           deny_sip & 0x000000FF, (deny_sip & 0x0000FF00) >> 8,
           (deny_sip & 0x00FF0000) >> 16, (deny_sip & 0xFF000000) >> 24);

    return 0;
}
static int set_dip_rule(char * ip)
{
    deny_dip = inet_addr(ip);
    lwfw_statistics.ip_dropped = 0;     /* Reset drop count for IP rule */

    printk("LWFW: Set dip  address: %d.%d.%d.%d\n",
           deny_dip & 0x000000FF, (deny_dip & 0x0000FF00) >> 8,
           (deny_dip & 0x00FF0000) >> 16, (deny_dip & 0xFF000000) >> 24);

    return 0;
}
static int lwfw_ioctl(struct file *file,unsigned int cmd, unsigned long arg)
{
    DENY_IN *pre,*p;
    int ret=0;
    char buff[32];
    switch (cmd)
    {
    case LWFW_GET_VERS:
        return LWFW_VERS;
    case LWFW_ACTIVATE:
    {
        active=1;
        printk("LWFW: Activated.\n");
            p=kmalloc(sizeof(DENY_IN),GFP_KERNEL);
            p->next=NULL;
            p->dip=NULL;
            p->dport=LWFW_ANY_DPORT;
            p->protocl=LWFW_ANY_PROTOCOL;
            p->sip=NULL;
            p->sport=LWFW_ANY_SPORT;
            p->timestart=LWFW_ANY_TIME;
            p->timeend=LWFW_ANY_TIME;
            if(head==NULL){
            currentp=head=p;
            }else{
                currentp->next=p;
                currentp=p;
            }
        break;
    }
    case LWFW_DEACTIVATE:
    {
        active ^= active;
        printk("LWFW: Deactivated.\n");
        break;
    }
    case LWFW_GET_STATS:
    {
        ret=copy_stats((struct lwfw_stats*)arg);
        break;
    }
    case LWFW_DENY_SIP:
    {
        copy_from_user(buff,arg,32);
        currentp->sip=(char *)kmalloc(sizeof(buff),GFP_KERNEL);
        //  memccpy(currentp->sip,buff,'!',sizeof(buff));
        memmove(currentp->sip,buff,sizeof(buff));

        break;
    }
    case LWFW_DENY_DIP:
    {
        copy_from_user(buff,arg,32);
        currentp->dip=kmalloc(sizeof(buff),GFP_KERNEL);
        //  memccpy(currentp->sip,buff,'!',sizeof(buff));
        memmove(currentp->dip,buff,sizeof(buff));
        break;
    }
    case LWFW_DENY_PROTOCOL:
    {
        currentp->protocl=arg;
        break;
    }
    case  LWFW_DENY_SPORT:
    {
        currentp->sport=arg;
        break;
    }
    case LWFW_DENY_DPORT:
    {
        currentp->dport=arg;
        break;

    }
    case LWFW_DENY_TIME_START:
    {
        currentp->timestart=(unsigned)arg;
        break;
    }
    case LWFW_DENY_TIME_END:
    {
        currentp->timeend=(unsigned)arg;
        break;
    }
    default:
        ret=-EBADRQC;
    };
    return ret;
}

static int lwfw_open(struct inode *inode, struct file *file)
{
    if(lwfw_ctrl_in_use)
    {
        return -EBUSY;
    }
    else
    {
        lwfw_ctrl_in_use++;
        return 0;
    }
    return 0;
}
static int lwfw_release(struct inode *inode,struct file *file)
{
    lwfw_ctrl_in_use^=lwfw_ctrl_in_use;
    return 0;
}

int init(void)
{
    int result,err;
    dev_t devno,devno_m;
    result=alloc_chrdev_region(&devno,0,1,LWFW_NAME);
    major=MAJOR(devno);
    if(result<0)
        return result;
    devno_m=MKDEV(major,0);
    printk("major is %d\n",MAJOR(devno_m));
    printk("minor is %d\n",MINOR(devno_m));
    cdev_init(&cdev_m, &lwfw_fops);
    cdev_m.owner = THIS_MODULE;
    cdev_m.ops = &lwfw_fops;
    err = cdev_add(&cdev_m, devno_m, 1);
    if(err != 0 )
    {
        printk("cdev_add error\n");
    }

    lwfw_ctrl_in_use^=lwfw_ctrl_in_use;
    printk("\n LWFW:COntrol device successfully registered.\n");
    nfkiller.hook=lwfw_hookfn;
    nfkiller.hooknum=NF_INET_PRE_ROUTING;
    nfkiller.pf=PF_INET;
    nfkiller.priority=NF_IP_PRI_FIRST;
    nf_register_hook(&nfkiller);
    nfkiller1.hook=lwfw_hookfn;
    nfkiller1.hooknum=NF_INET_LOCAL_OUT;
    nfkiller1.pf=PF_INET;
    nfkiller1.priority=NF_IP_PRI_FIRST;
    nf_register_hook(&nfkiller1);
    printk("LWFW: Network hooks successfully installed.\n");
    printk("LWFW: Module installation successfully.\n");
    return 0;
}

void cleanup(void)
{
    int ret;
    nf_unregister_hook(&nfkiller);
    nf_unregister_hook(&nfkiller1);
    cdev_del(&cdev_m);
    unregister_chrdev_region(MKDEV(major,0),1);
    printk("LWFW:Removal of module successfully.\n");


}

module_init(init);
module_exit(cleanup);

MODULE_LICENSE("GPL");
MODULE_AUTHOR("hzy");





