/*
 * Copyright (c) 2006-2014 Erik Ekman <yarrick@kryo.se>,
 * 2006-2009 Bjorn Andersson <flex@kryo.se>
 *
 * Permission to use, copy, modify, and/or distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
 * WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
 * ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 * WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
 * ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
 * OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 */

#ifndef __FIX_WINDOWS_H__
#define __FIX_WINDOWS_H__

typedef unsigned int in_addr_t;

#include <stdlib.h>
#include <winsock2.h>
#include <windows.h>
#include <windns.h>
#include <ws2tcpip.h>
#include <iphlpapi.h>
#include <time.h>

/* Missing from the mingw headers */
#ifndef DNS_TYPE_SRV
# define DNS_TYPE_SRV 33
#endif
#ifndef DNS_TYPE_TXT
# define DNS_TYPE_TXT 16
#endif

#define T_A DNS_TYPE_A
#define T_NS DNS_TYPE_NS
#define T_NULL DNS_TYPE_NULL
#define T_CNAME DNS_TYPE_CNAME
#define T_MX DNS_TYPE_MX
#define T_TXT DNS_TYPE_TXT
#define T_SRV DNS_TYPE_SRV

#define C_IN 1

#define FORMERR 1
#define SERVFAIL 2
#define NXDOMAIN 3
#define NOTIMP 4
#define REFUSED 5

#define sleep(seconds) Sleep((seconds)*1000)

typedef struct {
        unsigned        id :16;         /* query identification number */
                        /* fields in third byte */
        unsigned        rd :1;          /* recursion desired */
        unsigned        tc :1;          /* truncated message */
        unsigned        aa :1;          /* authoritive answer */
        unsigned        opcode :4;      /* purpose of message */
        unsigned        qr :1;          /* response flag */
                        /* fields in fourth byte */
        unsigned        rcode :4;       /* response code */
        unsigned        cd: 1;          /* checking disabled by resolver */
        unsigned        ad: 1;          /* authentic data from named */
        unsigned        unused :1;      /* unused bits (MBZ as of 4.9.3a3) */
        unsigned        ra :1;          /* recursion available */
                        /* remaining bytes */
        unsigned        qdcount :16;    /* number of question entries */
        unsigned        ancount :16;    /* number of answer entries */
        unsigned        nscount :16;    /* number of authority entries */
        unsigned        arcount :16;    /* number of resource entries */
} HEADER;

struct ip
{
    unsigned int ip_hl:4;               /* header length */
    unsigned int ip_v:4;                /* version */
    u_char ip_tos;                      /* type of service */
    u_short ip_len;                     /* total length */
    u_short ip_id;                      /* identification */
    u_short ip_off;                     /* fragment offset field */
#define IP_RF 0x8000                    /* reserved fragment flag */
#define IP_DF 0x4000                    /* dont fragment flag */
#define IP_MF 0x2000                    /* more fragments flag */
#define IP_OFFMASK 0x1fff               /* mask for fragmenting bits */
    u_char ip_ttl;                      /* time to live */
    u_char ip_p;                        /* protocol */
    u_short ip_sum;                     /* checksum */
    struct in_addr ip_src, ip_dst;      /* source and dest address */
};

/* Convenience macros for operations on timevals.
   NOTE: `timercmp' does not work for >= or <=.  */
#define timerisset(tvp)	((tvp)->tv_sec || (tvp)->tv_usec)

#ifndef timerclear
#define timerclear(tvp)	((tvp)->tv_sec = (tvp)->tv_usec = 0)
#endif
#ifndef timercmp
#define timercmp(a, b, CMP) 						      \
	(((a)->tv_sec == (b)->tv_sec) ? 					      \
	 ((a)->tv_usec CMP (b)->tv_usec) : 					      \
	 ((a)->tv_sec CMP (b)->tv_sec))
#endif
#define timeradd(a, b, result)						      \
	do {									      \
		(result)->tv_sec = (a)->tv_sec + (b)->tv_sec;			      \
		(result)->tv_usec = (a)->tv_usec + (b)->tv_usec;			      \
		if ((result)->tv_usec >= 1000000)					      \
		{									      \
			++(result)->tv_sec;						      \
			(result)->tv_usec -= 1000000;					      \
		}									      \
	} while (0)
#define timersub(a, b, result)						      \
	do {									      \
		(result)->tv_sec = (a)->tv_sec - (b)->tv_sec;			      \
		(result)->tv_usec = (a)->tv_usec - (b)->tv_usec;			      \
		if ((result)->tv_usec < 0) {					      \
			--(result)->tv_sec;						      \
			(result)->tv_usec += 1000000;					      \
		}									      \
	} while (0)

#if 0
inline int
gettimeofday(struct timeval *tv, struct timezone *tz)
{
	FILETIME ft;
	unsigned __int64 tmpres = 0;
	int tzflag = 0;

	if (NULL != tv)
		{
		GetSystemTimeAsFileTime(&ft);

		tmpres |= ft.dwHighDateTime;
		tmpres <<= 32;
		tmpres |= ft.dwLowDateTime;

		/* convert into microseconds */
		tmpres /= 10;
		/* converting file time to unix epoch */
		tmpres -= DELTA_EPOCH_IN_MICROSECS;
		tv->tv_sec = (long) (tmpres / 1000000UL);
		tv->tv_usec = (long) (tmpres % 1000000UL);
	}

	if (NULL != tz)
		{
		if (!tzflag)
		{
			_tzset();
			tzflag++;
		}
		tz->tz_minuteswest = _timezone / 60;
		tz->tz_dsttime = _daylight;
	}

	return 0;
}
#endif

DWORD WINAPI tun_reader(LPVOID arg);
struct tun_data {
	HANDLE tun;
	int sock;
	struct sockaddr_storage addr;
	int addrlen;
};

#endif
