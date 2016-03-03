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
#include<linux/string.h>

//static int set_if_rule(char * interface);
static int set_sip_rule(char *isp);
static int set_dip_rule(char *dip);
//static int set_sport_rule(char *sport);
//static int set_dport_rule(char *dport);
//static int set_time_rule(char *time);
//static int check_tcp_packet(struct sk_buff *skb);
//static int check_udp_packet(struct sk_buff *skb);
static int check_sip_packet(struct sk_buff *skb,DENY_IN *p);
static int check_dip_packet(struct sk_buff *skb,DENY_IN*p);
static int check_protocol_sport(struct sk_buff*skb,DENY_IN*p);
static int check_protocol_dport(struct sk_buff*skb,DENY_IN*p);
static int check_time(struct sk_buff*skb,DENY_IN*p);
static int  check_protocol(struct sk_buff*skb,DENY_IN *p);
static int copy_log(struct sk_buff*skb,DENY_IN*temp);
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
/**static unsigned int lwfw_options = (LWFW_IF_DENY_ACTIVE
                                    | LWFW_IP_DENY_ACTIVE
                                    | LWFW_PORT_DENY_ACTIVE|LWFW_TIME_DENY_ACTIVE|LWFW_PROTOCOL_DENY_ACTIVE);*/
static int major = 0;               /* Control device major number */

/* This struct will describe our hook procedure. */
struct nf_hook_ops nfkiller,nfkiller1;

/* Module statistics structure */
static struct lwfw_stats lwfw_statistics = {0, 0, 0, 0, 0, 0, 0, 0, 0};

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
DENY_IN *read_head;
DENY_IN*read_currentp;
DENY_IN *log_head,*log_currentp;
unsigned int inet_addr(char *str)
{
    unsigned int a ,b,c,d,e;
    unsigned int flag;
    unsigned int flag1=0;
    int i=0;
    char arr[4];
    if(str==NULL)
        return 0;
    char example;
    while(i<strlen(str))
    {
        if((example=str[i++])=='/')
        {
            flag1=1;
            break;
        }

    }
    if(flag1!=1)
    {
        str=strcat(str,"/32");

    }


    sscanf(str,"%u.%u.%u.%u/%u",&a,&b,&c,&d,&e);
    printk("************a:%u b %u c %u d %u e %u***************************",a,b,c,d,e);
    flag=(~0)>>(32-e);
    arr[0]=a;
    arr[1]=b;
    arr[2]=c;
    arr[3]=d;
    return( (*(unsigned int *)arr)&flag);


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
    unsigned int check_dip = 0;
    unsigned int check_sport=0;
    unsigned int check_dport=0;
    unsigned int check_t=0;
    unsigned int check_sip=0;
    unsigned int check_pro=0;
    DENY_IN *p=head;
    DENY_IN*temp;
    /* If LWFW is not currently active, immediately return ACCEPT */
    if (!active)
        return NF_ACCEPT;

    lwfw_statistics.total_seen++;

    /* Check the interface rule first */


    /* Check the IP address rule */
    if(p==NULL)
    {
        printk("p is NULL");
        return NF_ACCEPT;
    }

    while (p  /*&& DENY_IP_ACTIVE*/ )
    {
        check_sip = check_sip_packet(skb,p);
        check_sport=check_protocol_sport(skb,p);
        check_t=check_time(skb,p);
        check_dip = check_dip_packet(skb,p);
        check_dport=check_protocol_dport(skb,p);
        check_pro=check_protocol(skb,p);
        printk("check_sip is %u check_sport is %u check_time is %u check_t is %u check_dip is %u check_dport is %u\n",check_sip,check_sport,check_t,check_dip,check_dport);
        if (!check_sip && !check_sport&&!check_t&&!check_dip&&!check_dport&&!p->act&&!check_pro)
        {
            temp=kmalloc(sizeof(DENY_IN),GFP_KERNEL);
            copy_log(skb,temp);
                   if(log_head==NULL)
            {
                log_currentp=log_head=temp;
            }
            else
            {
                log_currentp->next=temp;
                log_currentp=temp;
            }

            return NF_DROP;
        }
        else
        {
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

static int copy_log(struct sk_buff*skb,DENY_IN*temp){
            struct iphdr *ip;
            struct tcphdr*tcph=NULL;
            struct udphdr*udph=NULL;
            if(!skb)
            {
                printk("skb is empty\n");
                return 0;
            }
            ip=ip_hdr(skb);
            if(ip->protocol==IPPROTO_TCP){
            tcph=(void *)ip+ip->ihl*4;
            temp->sport=ntohs( tcph->source);
            temp->dport=ntohs(tcph->dest);
            temp->protocl=LWFW_TCP;
            }
            else{
                if(ip->protocol==IPPROTO_UDP){
                    udph=(void*)ip+ip->ihl*4;
                    temp->sport=ntohs(udph->source);
                    temp->dport=ntohs(udph->dest);
                    temp->protocl=LWFW_UDP;
                }
                else{
                    temp->sport=LWFW_ANY_SPORT;
                    temp->dport=LWFW_ANY_DPORT;
                    temp->protocl=LWFW_ANY_PROTOCOL;
                }
            }
            temp->act=0;
            temp->copy_flag=0;
            temp->sip=ip->saddr;
            temp->dip=ip->daddr;
            temp->timeend=LWFW_ANY_TIME;
            temp->timestart=LWFW_ANY_TIME;
            return 0;

}
static int check_sip_packet(struct sk_buff *skb,DENY_IN*p)
{

    struct iphdr *ip;
    if(!skb)
    {
        printk("skb is empty\n");
        return 1;
    }
    ip=ip_hdr(skb);
    if(ip->saddr==p->sip||p->sip==0x00000000)
    {
        printk("ip->saddr= %d.%d.%d.%d ",
               ip->saddr & 0x000000FF, (ip->saddr & 0x0000FF00) >> 8,
               (ip->saddr & 0x00FF0000) >> 16, (ip->saddr & 0xFF000000) >> 24);
        printk("p->sip= %d.%d.%d.%d",
               p->sip & 0x000000FF, (p->sip & 0x0000FF00) >> 8,
               (p->sip & 0x00FF0000) >> 16, (p->sip & 0xFF000000) >> 24);
        if(p->sip!=0x00000000)
        {
            lwfw_statistics.sip_dropped++;
            lwfw_statistics.total_dropped++;
        }
        printk(" return 0 \n");
        return 0;
    }
    else
    {

        printk("sip is not in the rule return 1\n");
        return 1;
    }

    return 1;
}

static int check_dip_packet(struct sk_buff *skb,DENY_IN*p)
{

    struct iphdr *ip;
    if(!skb)
        return 1;
    ip=ip_hdr(skb);
    if(ip->daddr==p->dip||p->dip==0x00000000)
    {
        if(p->dip!=0x00000000)
        {
            lwfw_statistics.dip_dropped++;
            lwfw_statistics.total_dropped++;
        }
        printk("ip->daddr= %d.%d.%d.%d ",
               ip->daddr & 0x000000FF, (ip->daddr & 0x0000FF00) >> 8,
               (ip->daddr & 0x00FF0000) >> 16, (ip->daddr & 0xFF000000) >> 24);
        printk("p->dip= %d.%d.%d.%d",
               p->dip & 0x000000FF, (p->dip & 0x0000FF00) >> 8,
               (p->dip & 0x00FF0000) >> 16, (p->dip & 0xFF000000) >> 24);
        printk(" return 0 \n");
        return 0;
    }
    else
    {
        printk("dip is not in the rule return 1 \n");
        return 1;
    }


    return 0;
}

static int check_protocol_sport(struct sk_buff*skb,DENY_IN*p)
{
    struct tcphdr*tcph=NULL;
    struct udphdr*udph=NULL;
    const struct iphdr*iph=NULL;

    if(!skb)
        return 1;

    iph=ip_hdr(skb);
    if(p->protocl==LWFW_ANY_PROTOCOL||p->sport==LWFW_ANY_SPORT)
        return 0;
    if(iph->protocol==IPPROTO_TCP&&p->protocl==LWFW_TCP)
    {
        tcph=(void *)iph+iph->ihl*4;

        if(ntohs( tcph->source)==p->sport)
        {
            printk("tcp sport %lu is drop return 0\n",p->sport);
            lwfw_statistics.tcp_dropped++;
            lwfw_statistics.sport_dropped++;
            lwfw_statistics.total_dropped++;
            return 0;
        }
    }
    else
    {
        if(iph->protocol==IPPROTO_UDP&&p->protocl==LWFW_UDP)
        {
            udph=(void*)iph+iph->ihl*4;

            if(ntohs( tcph->source)==p->sport)
            {
                printk("udp sport %lu is drop return 0 \n ",p->sport);
                lwfw_statistics.udp_dropped++;
                lwfw_statistics.sport_dropped++;
                lwfw_statistics.total_dropped++;
                return 0;
            }
        }
    }
    return 1;
}
static int  check_protocol(struct sk_buff*skb,DENY_IN *p)
{
    struct iphdr* iph;

    if(!skb)
        return 1;

    iph=ip_hdr(skb);
    if(p->protocl==LWFW_ANY_PROTOCOL)
        return 0;
    if(iph->protocol==IPPROTO_TCP&&p->protocl==LWFW_TCP)
    {
        lwfw_statistics.tcp_dropped++;
        lwfw_statistics.total_dropped++;
        return 0;
    }
    if(iph->protocol==IPPROTO_UDP&&p->protocl==LWFW_UDP)
    {
        lwfw_statistics.udp_dropped++;
        lwfw_statistics.total_dropped++;
        return 0;
    }
    return 1;
}

static int check_protocol_dport(struct sk_buff*skb,DENY_IN*p)
{

    struct tcphdr*tcph=NULL;
    struct udphdr*udph=NULL;
    const struct iphdr*iph=NULL;


    if(!skb)
        return 1;
    iph=ip_hdr(skb);
    if(p->protocl==LWFW_ANY_PROTOCOL||p->dport==LWFW_ANY_DPORT)
        return 0;
    if(iph->protocol==IPPROTO_TCP&&p->protocl==LWFW_TCP)
    {
        tcph=(void *)iph+iph->ihl*4;

        if(ntohs( tcph->dest)==p->dport)
        {
            printk(" tcp dport %lu is drop return 0\n",p->dport);
            lwfw_statistics.tcp_dropped++;
            lwfw_statistics.dport_dropped++;
            lwfw_statistics.total_dropped++;
            return 0;
        }
    }
    else
    {
        if(iph->protocol==IPPROTO_UDP&&p->protocl==LWFW_UDP)
        {
            udph=(void*)iph+iph->ihl*4;

            if(ntohs( tcph->dest)==p->dport)
            {
                lwfw_statistics.tcp_dropped++;
                lwfw_statistics.dport_dropped++;
                lwfw_statistics.total_dropped++;
                printk("udp dport %lu is drop return 0\n",p->dport);
                return 0;
            }
        }
    }
    return 1;
}
static int check_time(struct sk_buff*skb,DENY_IN*p)
{
    struct timex txc;
    struct rtc_time tm;
    do_gettimeofday(&(txc.time));
    rtc_time_to_tm(txc.time.tv_sec,&tm);

    if(p->timeend==LWFW_ANY_TIME&&p->timestart==LWFW_ANY_TIME)
    {
        printk("time any return 0\n");
        return 0;
    }
    if((tm.tm_hour+8)<=p->timeend&&(tm.tm_hour+8)>=p->timestart)
    {
        printk("time in the rule return 0\n");
        lwfw_statistics.time_dropped++;
        lwfw_statistics.total_dropped++;
        return 0;
    }
    printk("time is not in the rule and not empty return 1\n");
    return 1;
}


static int set_sip_rule(char * ip)
{
    deny_sip = inet_addr(ip);
    printk("LWFW: Set  sIP address: %d.%d.%d.%d\n",
           deny_sip & 0x000000FF, (deny_sip & 0x0000FF00) >> 8,
           (deny_sip & 0x00FF0000) >> 16, (deny_sip & 0xFF000000) >> 24);

    return 0;
}
static int set_dip_rule(char * ip)
{
    deny_dip = inet_addr(ip);
    printk("LWFW: Set dip  address: %d.%d.%d.%d\n",
           deny_dip & 0x000000FF, (deny_dip & 0x0000FF00) >> 8,
           (deny_dip & 0x00FF0000) >> 16, (deny_dip & 0xFF000000) >> 24);

    return 0;
}
static int lwfw_ioctl(struct file *file,unsigned int cmd, unsigned long arg)
{

    int ret=0;
    int i=0;
    char buff[32];
    char* deny_buff;
    DENY_IN *p;

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
        p->sip=0x00000000;
        p->dip=0x00000000;
        p->dport=LWFW_ANY_DPORT;
        p->protocl=LWFW_ANY_PROTOCOL;
        p->copy_flag=0;
        p->act=0;
        p->sport=LWFW_ANY_SPORT;
        p->timestart=LWFW_ANY_TIME;
        p->timeend=LWFW_ANY_TIME;
        if(head==NULL)
        {
            currentp=head=p;
        }
        else
        {
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
        copy_from_user(buff,(void*)arg,32);
        deny_buff=(char *)kmalloc(sizeof(buff),GFP_KERNEL);
        //  memccpy(currentp->sip,buff,'!',sizeof(buff));
        memmove(deny_buff,buff,sizeof(buff));
        set_sip_rule(deny_buff);
        currentp->sip=deny_sip;

        break;
    }
    case LWFW_DENY_DIP:
    {
        copy_from_user(buff,(void*)arg,32);
        deny_buff=kmalloc(sizeof(buff),GFP_KERNEL);
        //  memccpy(currentp->sip,buff,'!',sizeof(buff));
        memmove(deny_buff,buff,sizeof(buff));
        set_dip_rule(deny_buff);
        currentp->dip=deny_dip;
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
    case LWFW_COPY_TO_USER:
    {
        p=head;
        if(p==NULL)
        {
            printk("*************rule is NULL******************\n");
            break;
        }
        while(p)
        {
            if(p->dport==LWFW_ANY_DPORT)
                printk("\n\nthe %d rule: dport :any ",i++);
            else
                printk("\n\nthe %d rule dport :%lu ",i++,p->dport);
            if(p->dport==LWFW_ANY_DPORT)
                printk(" sport :any ");
            else
                printk("sport :%lu ",p->sport);
            if(p->protocl==1)
            {
                printk(" protocol : tcp ");
            }
            if(p->protocl==0)
            {
                printk(" protocol : udp ");
            }
            if(p->protocl==LWFW_ANY_PROTOCOL)
            {
                printk(" protocl: any ");
            }
            if(p->sip==0x00000000)
                printk("sip:any ");
            else
                printk("sip  address: %d.%d.%d.%d ",
                       p->sip & 0x000000FF, (p->sip & 0x0000FF00) >> 8,
                       (p->sip & 0x00FF0000) >> 16, (p->sip & 0xFF000000) >> 24);
            if(p->dip==0x00000000)
                printk("dip:any ");
            else
                printk("dip  address: %d.%d.%d.%d ",
                       p->dip & 0x000000FF, (p->dip & 0x0000FF00) >> 8,
                       (p->dip & 0x00FF0000) >> 16, (p->dip & 0xFF000000) >> 24);
            if(p->timestart==LWFW_ANY_TIME)
            {
                printk("starttime:any ");
            }
            else
            {
                printk(" start time:%u ",p->timestart);
            }
            if(p->timeend==LWFW_ANY_TIME)
            {
                printk("end time:any \n");
            }
            else
            {
                printk(" end time:%u \n",p->timeend);
            }
            p=p->next;

        }

        break;
    }
    case LWFW_DELETE_INODE:
    {
        DENY_IN*pre;
        DENY_IN*Next;
        p=head;
        i=0;
        if(p==NULL)
        {
            printk("\n\n************** no rule to print*****************************");
            break;
        }
        while(p)
        {
            if(arg==0)
            {
                pre=head;
                head=head->next;
                kfree(pre);
                break;
            }
            if(i+1==arg&&p->next!=NULL)
            {
                pre=p;
                Next=p->next->next;
                pre->next=Next;
                kfree(p->next);
                break;
            }
            i++;
            p=p->next;
        }


    }
    case LWFW_SAVE_RULE:
    {
        DENY_IN* temp;
        temp=(DENY_IN*)arg;
        i=0;
        p=head;
        if(p==NULL)
        {
            p=kmalloc(sizeof(DENY_IN),GFP_KERNEL);
            p->copy_flag=COPY_END_EMPTY;
            copy_to_user(temp, p,sizeof(DENY_IN));
            printk("**********************no rule!!!!**********************************************\n\n");
            break;
        }

        while(p)
        {
            if(p->next==NULL)
            {
                p->copy_flag=COPY_END_FULL;

            }
            copy_to_user(temp, p,sizeof(DENY_IN));
            p->copy_flag=0;
            i++;
            temp=temp+1;
            if(i>=20)
                break;
            p=p->next;
        }
        break;

    }
    case LWFW_READ_RULE:
    {

        p=kmalloc(sizeof(DENY_IN),GFP_KERNEL);
        copy_from_user(p,(void*)arg,sizeof(DENY_IN));
        if(read_head==NULL)
        {

            read_currentp=read_head=p;
        }
        else
        {
            read_currentp->next=p;
            read_currentp=p;

        }
        head=read_head;
        currentp=read_currentp;
        break;
    }
    case LWFW_ACT:
    {
        currentp->act=arg;
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





