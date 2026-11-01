#include "config.h"

#include <signal.h>
#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <unistd.h>

#ifdef WINDOWS
#include "windows_dns.h"
#include <ws2def.h>
#else
#include <arpa/inet.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#endif

#include "tun.h"
#include "ui.h"

#define ICMP_ECHO_REQUEST	8
#define ICMP_ECHO_REPLY		0

static const char *myaddr = "172.23.53.53";
static const char *peeraddr = "172.23.53.1";
static const int netbits = 26;
static int running = 1;

static void
sighandler(int sig)
{
	(void)sig;
	running = 0;
}

int
inet_checksum(char* addr, int len) {
	uint32_t sum = 0;
	while( len > 1 ){
		sum += ntohs(*(uint16_t*)addr);
		len -= 2;
		addr += 2;
	}
	if( len > 0 ){
		sum += * (uint8_t*) addr;
	}
	while( sum >> 16 ){
		sum = (sum & 0xffff) + (sum >> 16);
	}
	return (~sum) & 0xFFFF;
}

static void
packet_read(int fd, struct in_addr peer)
{
    /* Reads packets from the tun device, and prints
     * the reason they are not processed, or ECHO
     * if it responds to a ping. */
	do {
		char buf[2048];
		int len = read_tun(fd, buf, sizeof(buf));
		if (len < 0)
			break;
		/* Skip 4 byte header */
		char *iphdr = &buf[4];
		int iplen = len - 4;
		if ((iphdr[0] & 0xF0) != 0x40) {
			ui_log("DROP Not IPv4\n");
			continue;
		}
		uint32_t *addrs = (uint32_t*) iphdr;
		int hdrlen = (iphdr[0] & 0xF) << 2;
		if (inet_checksum(iphdr, hdrlen)) {
			ui_log("DROP Bad IP checksum\n");
			continue;
		}
		uint32_t dstaddr = addrs[4];
		if (dstaddr != peer.s_addr) {
			ui_log("DROP Bad destination\n");
			continue;
		}
		/* Swap IP addresses */
		addrs[4] = addrs[3];
		addrs[3] = dstaddr;
		char *payload = &iphdr[hdrlen];
		int innerlen = iplen - hdrlen;
		if (iphdr[9] != IPPROTO_ICMP) {
			ui_log("DROP Not ICMP\n");
			continue;
		}
		if (inet_checksum(payload, innerlen)) {
			ui_log("DROP Bad ICMP checksum\n");
			continue;
		}
		if (payload[0] != ICMP_ECHO_REQUEST) {
			ui_log("DROP Not Echo request\n");
			continue;
		}
		/* Flip ICMP type */
		payload[0] = ICMP_ECHO_REPLY;
		uint16_t *icmp_csum = ((uint16_t*)payload) + 1;
		*icmp_csum = 0;
		*icmp_csum = htons(inet_checksum(payload, innerlen));
		ui_log("ECHO\n");
		write_tun(fd, buf, len);
	} while (1);
}

int
main(int argc, char **argv)
{
	int fd;
	struct in_addr host, peer;

	if (argc < 2) {
		ui_log("Missing device name as argument\n");
		return 1;
	}
	fd = open_tun(argv[1]);
	if (fd < 0) {
		exit(-1);
	}

	inet_pton(AF_INET, myaddr, &host);
	inet_pton(AF_INET, peeraddr, &peer);
	if (tun_setip(&host.s_addr, &peer.s_addr, netbits)) {
		close(fd);
		return -1;
	}

	ui_log("OPEN '%s'\n", argv[1]);

	signal(SIGINT, sighandler);
	do {
		packet_read(fd, peer);
		usleep(5353);
	} while (running);
	ui_log("END\n");
	return 0;
}
