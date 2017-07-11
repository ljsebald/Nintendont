/* Large portions of this file borrowed from libogc's gc/network.h */

#ifndef __NETWORK_H__
#define __NETWORK_H__

#include "global.h"

#define SOCK_STREAM     1
#define SOCK_DGRAM      2
#define SOCK_RAW        3

/*
 * Option flags per-socket.
 */
#define  SO_DEBUG			0x0001    /* turn on debugging info recording */
#define  SO_ACCEPTCONN		0x0002    /* socket has had listen() */
#define  SO_REUSEADDR		0x0004    /* allow local address reuse */
#define  SO_KEEPALIVE		0x0008    /* keep connections alive */
#define  SO_DONTROUTE		0x0010    /* just use interface addresses */
#define  SO_BROADCAST		0x0020    /* permit sending of broadcast msgs */
#define  SO_USELOOPBACK		0x0040    /* bypass hardware when possible */
#define  SO_LINGER			0x0080    /* linger on close if data present */
#define  SO_OOBINLINE		0x0100    /* leave received OOB data in line */
#define	 SO_REUSEPORT		0x0200		/* allow local address & port reuse */

#define SO_DONTLINGER		(int)(~SO_LINGER)

/*
 * Additional options, not kept in so_options.
 */
#define SO_SNDBUF			0x1001    /* send buffer size */
#define SO_RCVBUF			0x1002    /* receive buffer size */
#define SO_SNDLOWAT			0x1003    /* send low-water mark */
#define SO_RCVLOWAT			0x1004    /* receive low-water mark */
#define SO_SNDTIMEO			0x1005    /* send timeout */
#define SO_RCVTIMEO			0x1006    /* receive timeout */
#define  SO_ERROR			0x1007    /* get error status and clear */
#define  SO_TYPE			0x1008    /* get socket type */

/*
 * Level number for (get/set)sockopt() to apply to socket itself.
 */
#define  SOL_SOCKET			0xffff    /* options for socket level */

#define AF_UNSPEC			0
#define AF_INET				2
#define PF_INET				AF_INET
#define PF_UNSPEC			AF_UNSPEC

#define IPPROTO_IP			0
#define IPPROTO_TCP			6
#define IPPROTO_UDP			17

#define INADDR_ANY			0
#define INADDR_BROADCAST	0xffffffff

#ifndef socklen_t
#define socklen_t u32
#endif

#ifndef htons
#define htons(x) (x)
#endif
#ifndef ntohs
#define ntohs(x) (x)
#endif
#ifndef htonl
#define htonl(x) (x)
#endif
#ifndef ntohl
#define ntohl(x) (x)
#endif

#ifndef F_GETFL
#define F_GETFL 3
#endif
#ifndef F_SETFL
#define F_SETFL 4
#endif

#define IOS_O_NONBLOCK  0x04

#ifndef IP4_ADDR
#define IP4_ADDR(ipaddr, a,b,c,d) (ipaddr)->s_addr = htonl(((u32)(a&0xff)<<24)|((u32)(b&0xff)<<16)|((u32)(c&0xff)<<8)|(u32)(d&0xff))
#define ip4_addr1(ipaddr) ((u32)(ntohl((ipaddr)->s_addr) >> 24) & 0xff)
#define ip4_addr2(ipaddr) ((u32)(ntohl((ipaddr)->s_addr) >> 16) & 0xff)
#define ip4_addr3(ipaddr) ((u32)(ntohl((ipaddr)->s_addr) >> 8) & 0xff)
#define ip4_addr4(ipaddr) ((u32)(ntohl((ipaddr)->s_addr)) & 0xff)
#endif

#ifndef HAVE_IN_ADDR
#define HAVE_IN_ADDR
struct in_addr {
  u32 s_addr;
};
#endif

struct sockaddr_in {
  u8 sin_len;
  u8 sin_family;
  u16 sin_port;
  struct in_addr sin_addr;
  s8 sin_zero[8];
};

struct sockaddr {
  u8 sa_len;
  u8 sa_family;
  s8 sa_data[14];
};

s32 net_init(void);
void net_deinit(void);

s32 net_socket(u32 domain, u32 type, u32 protocol);
s32 net_shutdown(s32 s, u32 how);
s32 net_connect(s32 s, struct sockaddr *addr, socklen_t addrlen);
s32 net_sendto(s32 s, const void *data, s32 len, u32 flags, struct sockaddr *to,
               socklen_t tolen);

s32 net_recvfrom(s32 s, void *mem, s32 len, u32 flags, struct sockaddr *from,
                 socklen_t *fromlen);
s32 net_close(s32 s);
s32 net_setsockopt(s32 s, u32 level, u32 optname, const void *optval,
                   socklen_t optlen);
s32 net_fcntl(s32 s, u32 cmd, u32 flags);

#endif /* !__NETWORK_H__ */
