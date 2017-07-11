/*-------------------------------------------------------------

network_wii.c -- Wii network subsystem

Copyright (C) 2008 bushing

This software is provided 'as-is', without any express or implied
warranty.  In no event will the authors be held liable for any
damages arising from the use of this software.

Permission is granted to anyone to use this software for any
purpose, including commercial applications, and to alter it and
redistribute it freely, subject to the following restrictions:

1.	The origin of this software must not be misrepresented; you
must not claim that you wrote the original software. If you use
this software in a product, an acknowledgment in the product
documentation would be appreciated but is not required.

2.	Altered source versions must be plainly marked as such, and
must not be misrepresented as being the original software.

3.	This notice may not be removed or altered from any source
distribution.

-------------------------------------------------------------*/
/* Stripped down nintendont port
    This assumes that the network has already been brought up on the PPC side,
    so all the init stuff is gone from here, along with the pieces we don't
    need for modem emulation. */


#define MAX_IP_RETRIES		100
#define MAX_INIT_RETRIES	32

#include "global.h"
#include "ipc.h"
#include "network.h"
#include "alloc.h"
#include "string.h"

enum {
	IOCTL_SO_ACCEPT	= 1,
	IOCTL_SO_BIND,
	IOCTL_SO_CLOSE,
	IOCTL_SO_CONNECT,
	IOCTL_SO_FCNTL,
	IOCTL_SO_GETPEERNAME, // todo
	IOCTL_SO_GETSOCKNAME, // todo
	IOCTL_SO_GETSOCKOPT,  // todo    8
	IOCTL_SO_SETSOCKOPT,
	IOCTL_SO_LISTEN,
	IOCTL_SO_POLL,        // todo    b
	IOCTLV_SO_RECVFROM,
	IOCTLV_SO_SENDTO,
	IOCTL_SO_SHUTDOWN,    // todo    e
	IOCTL_SO_SOCKET,
	IOCTL_SO_GETHOSTID,
	IOCTL_SO_GETHOSTBYNAME,
	IOCTL_SO_GETHOSTBYADDR,// todo
	IOCTLV_SO_GETNAMEINFO, // todo   13
	IOCTL_SO_UNK14,        // todo
	IOCTL_SO_INETATON,     // todo
	IOCTL_SO_INETPTON,     // todo
	IOCTL_SO_INETNTOP,     // todo
	IOCTLV_SO_GETADDRINFO, // todo
	IOCTL_SO_SOCKATMARK,   // todo
	IOCTLV_SO_UNK1A,       // todo
	IOCTLV_SO_UNK1B,       // todo
	IOCTLV_SO_GETINTERFACEOPT, // todo
	IOCTLV_SO_SETINTERFACEOPT, // todo
	IOCTL_SO_SETINTERFACE,     // todo
	IOCTL_SO_STARTUP,           // 0x1f
	IOCTL_SO_ICMPSOCKET =	0x30, // todo
	IOCTLV_SO_ICMPPING,         // todo
	IOCTL_SO_ICMPCANCEL,        // todo
	IOCTL_SO_ICMPCLOSE          // todo
};

struct connect_params {
	u32 socket;
	u32 has_addr;
	u8 addr[28];
};

struct sendto_params {
	u32 socket;
	u32 flags;
	u32 has_destaddr;
	u8 destaddr[28];
};

struct setsockopt_params {
	u32 socket;
	u32 level;
	u32 optname;
	u32 optlen;
	u8 optval[20];
};

static s32 net_ip_top_fd = -1;

static char __iptop_fs[] __attribute((aligned(32))) = "/dev/net/ip/top";

s32 net_init(void) {
	if (net_ip_top_fd >= 0)
		return 0;

	if((net_ip_top_fd = IOS_Open(__iptop_fs, IPC_OPEN_NONE)) < 0)
		return -1;

	return 0;
}

void net_deinit(void) {
	if (net_ip_top_fd >= 0) IOS_Close(net_ip_top_fd);
	net_ip_top_fd = -1;
}

s32 net_socket(u32 domain, u32 type, u32 protocol)
{
	s32 ret;
	u32 params[3] ALIGNED(32);

	if (net_ip_top_fd < 0) return -1;

	params[0] = domain;
	params[1] = type;
	params[2] = protocol;

	ret = IOS_Ioctl(net_ip_top_fd, IOCTL_SO_SOCKET, params, 12, NULL, 0);
	if(ret>=0) // set tcp window size to 16kb
	{
		int window_size = 16384;
		net_setsockopt(ret, SOL_SOCKET, SO_RCVBUF, (char *) &window_size, sizeof(window_size));
	}
	return ret;
}

s32 net_shutdown(s32 s, u32 how)
{
	s32 ret;
	u32 params[2] ALIGNED(32);

	if (net_ip_top_fd < 0) return -1;

	params[0] = s;
	params[1] = how;
	ret = IOS_Ioctl(net_ip_top_fd, IOCTL_SO_SHUTDOWN, params, 8, NULL, 0);

	return ret;
}

s32 net_connect(s32 s, struct sockaddr *addr, socklen_t addrlen)
{
	s32 ret;
	struct connect_params params[1] ALIGNED(32);

	if (net_ip_top_fd < 0) return -1;
	if (addr->sa_family != AF_INET) return -2;
	if (addrlen < 8) return -3;

	addr->sa_len = 8;

	memset(params, 0, sizeof(struct connect_params));
	params->socket = s;
	params->has_addr = 1;
	memcpy(&params->addr, addr, addrlen);

	ret = IOS_Ioctl(net_ip_top_fd, IOCTL_SO_CONNECT, params, sizeof(struct connect_params), NULL, 0);

	return ret;
}

s32 net_sendto(s32 s, const void *data, s32 len, u32 flags, struct sockaddr *to, socklen_t tolen)
{
	s32 ret;
	u8 * message_buf = NULL;
	struct sendto_params params[1] ALIGNED(32);
	ioctlv iop[2] ALIGNED(32);

	if (net_ip_top_fd < 0) return -1;
	if (tolen > 28) return -4;

	message_buf = malloca(len, 32);
	if (message_buf == NULL) {
		return -5;
	}

	if (to && to->sa_len != tolen) {
		to->sa_len = tolen;
	}

	memset(params, 0, sizeof(struct sendto_params));
	memcpy(message_buf, data, len);   // ensure message buf is aligned

	params->socket = s;
	params->flags = flags;
	if (to) {
		params->has_destaddr = 1;
		memcpy(params->destaddr, to, to->sa_len);
	} else {
		params->has_destaddr = 0;
	}

	/* Input (2) */
	iop[0].data = message_buf;
	iop[0].len = len;
	iop[1].data = params;
	iop[1].len = sizeof(struct sendto_params);

	ret = IOS_Ioctlv(net_ip_top_fd, IOCTLV_SO_SENDTO, 2, 0, iop);

	if(message_buf!=NULL) free(message_buf);
	return ret;
}

s32 net_recvfrom(s32 s, void *mem, s32 len, u32 flags, struct sockaddr *from, socklen_t *fromlen)
{
	s32 ret;
	u8* message_buf = NULL;
	u32 params[2] ALIGNED(32);
	ioctlv iop[3] ALIGNED(32);

	if (net_ip_top_fd < 0) return -1;
	if (len<=0) return -3;

	if (fromlen && from->sa_len != *fromlen) {
		from->sa_len = *fromlen;
	}

	message_buf = malloca(len, 32);
	if (message_buf == NULL) {
		return -5;
	}

	memset(message_buf, 0, len);
	params[0] = s;
	params[1] = flags;

	/* Input (1) */
	iop[0].data = params;
	iop[0].len = 8;
	/* Output (2) */
	iop[1].data = message_buf;
	iop[1].len = len;
	iop[2].data = from;
	iop[2].len = fromlen ? *fromlen : 0;

	ret = IOS_Ioctlv(net_ip_top_fd, IOCTLV_SO_RECVFROM, 1, 2, iop);

	if (ret > 0) {
		if (ret > len) {
			ret = -4;
			goto done;
		}

		memcpy(mem, message_buf, ret);
	}

	if (fromlen && from) *fromlen = from->sa_len;

done:
	if(message_buf!=NULL) free(message_buf);
	return ret;
}

s32 net_close(s32 s)
{
	s32 ret;
	u32 _socket[1] ALIGNED(32);

	if (net_ip_top_fd < 0) return -1;

	*_socket = s;
	ret = IOS_Ioctl(net_ip_top_fd, IOCTL_SO_CLOSE, _socket, 4, NULL, 0);

	return ret;
}

s32 net_setsockopt(s32 s, u32 level, u32 optname, const void *optval, socklen_t optlen)
{
	s32 ret;
	struct setsockopt_params params[1] ALIGNED(32);

	if (net_ip_top_fd < 0) return -1;
	if (optlen < 0 || optlen > 20) return -4;

	memset(params, 0, sizeof(struct setsockopt_params));
	params->socket = s;
	params->level = level;
	params->optname = optname;
	params->optlen = optlen;
	if (optval && optlen) memcpy (params->optval, optval, optlen);

	ret = IOS_Ioctl(net_ip_top_fd, IOCTL_SO_SETSOCKOPT, params, sizeof(struct setsockopt_params), NULL, 0);

	return ret;
}

s32 net_fcntl(s32 s, u32 cmd, u32 flags)
{
	s32 ret;
	u32 params[3] ALIGNED(32);

	if (net_ip_top_fd < 0) return -1;
	if (cmd != F_GETFL && cmd != F_SETFL) return -4;


	params[0] = s;
	params[1] = cmd;
	params[2] = flags;

	ret = IOS_Ioctl(net_ip_top_fd, IOCTL_SO_FCNTL, params, 12, NULL, 0);

	return ret;
}
