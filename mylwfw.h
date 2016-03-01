/* Include file for the Light-weight Fire Wall LKM.
 *
* A very simple Netfilter module that drops backets based on either
* their incoming interface or source IP address.
*
* Written by hzy  -  FEB 2016
*/

#ifndef __LWFW_INCLUDE__
#define __LWFW_INCLUDE__

/* NOTE: The LWFW_MAJOR symbol is only made available for kernel code.
* Userspace code has no business knowing about it. */
# define LWFW_NAME        "mylwfw"

/* Version of LWFW */
# define LWFW_VERS        0x0001       /* 0.1 */
/* Definition of the LWFW_TALKATIVE symbol controls whether LWFW will
* print anything with printk(). This is included for debugging purposes.
*/
#define LWFW_TALKATIVE

#define  LWFW_TCP 0x0001
#define LWFW_UDP 0x0002

/* These are the IOCTL codes used for the control device */
#define LWFW_CTRL_SET   0xFEED0000     /* The 0xFEED... prefix is arbitrary */
#define LWFW_GET_VERS   0xFEED0001     /* Get the version of LWFM */
#define LWFW_ACTIVATE   0xFEED0002
#define LWFW_DEACTIVATE 0xFEED0003
#define LWFW_GET_STATS  0xFEED0004
#define LWFW_DENY_IF    0xFEED0005
#define LWFW_DENY_SIP    0xFEED0006
#define LWFW_DENY_DIP  0xFEED0007
#define LWFW_DENY_SPORT  0xFEED0008
#define  LWFW_DENY_DPORT 0xFEED0009
#define LWFW_DENY_TIME 0xFEED000A
#define LWFW_DENY_PROTOCOL 0xFEED000B


/* Control flags/Options */
#define LWFW_IF_DENY_ACTIVE   0x00000001
#define LWFW_IP_DENY_ACTIVE   0x00000002
#define LWFW_PORT_DENY_ACTIVE 0x00000004
#define LWFW_TIME_DENY_ACTIVE 0x00000008
#define LWFW_PROTOCOL_DENY_ACTIVE 0x00000010


#define  LWFW_ANY_SPORT    0xFFFFFFF2
#define  LWFW_ANY_DPORT    0xFFFFFFF3
#define  LWFW_ANY_TIME    0xFFFFFFF4
#define  LWFW_ANY_PROTOCOL  0xFFFFFFF5


/* Statistics structure for LWFW.
* Note that whenever a rule's condition is changed the related
* xxx_dropped field is reset.
*/
struct lwfw_stats {
   unsigned int if_dropped;           /* Packets dropped by interface rule */
   unsigned int ip_dropped;           /* Packets dropped by IP addr. rule */
   unsigned int tcp_dropped;           /* Packets dropped by TCP port rule */
   unsigned long total_dropped;   /* Total packets dropped */
   unsigned long total_seen;      /* Total packets seen by filter */
};

typedef struct deny_information{
    char * sip;
    char* dip;
    unsigned int  protocl;
    unsigned long sport;
    unsigned long dport;
    unsigned long   time;

    struct deny_information*next;
}DENY_IN;

/*
* From here on is used solely for the actual kernel module
*/
# define LWFW_MAJOR       241   /* This exists in the experimental range */

/* This macro is used to prevent dereferencing of NULL pointers. If
* a pointer argument is NULL, this will return -EINVAL */
#define NULL_CHECK(ptr)    if ((ptr) == NULL)  return -EINVAL
/* Macros for accessing options */
#define DENY_IF_ACTIVE    (lwfw_options & LWFW_IF_DENY_ACTIVE)
#define DENY_IP_ACTIVE    (lwfw_options & LWFW_IP_DENY_ACTIVE)
#define DENY_PORT_ACTIVE  (lwfw_options & LWFW_PORT_DENY_ACTIVE)
#define DENY_TIME_ACTIVE (lwfw_options &LWFW_TIME_DENY_ACTIVE)
#define  DENY_PROTOCOL_ACTIVE (lwfw_options &LWFW_PROTOCOL_DENY_ACTIVE)
#endif
