#include "config.h"

#include <signal.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#ifdef WINDOWS
#include <winsock2.h>
#include <ws2tcpip.h>
#include <iphlpapi.h>
#else
#include <ifaddrs.h>
#include <net/if.h>
#include <netdb.h>
#include <netinet/in.h>
#include <sys/select.h>
#include <sys/socket.h>
#endif

#include "common.h"
#include "compat.h"
#include "server.h"
#include "udp.h"
#include "ui.h"
#include "user.h"

static int running = 1;

static void
sighandler(int sig)
{
	(void)sig;
	running = 0;
}

static void
print_sockaddr(struct sockaddr *sa)
{
	if (sa == NULL)
		return;
	if (sa->sa_family == AF_INET) {
		ui_log("ADDR %s\n", format_addr((struct sockaddr_storage *)sa, sizeof(struct sockaddr_in)));
	} else if (sa->sa_family == AF_INET6) {
		struct sockaddr_in6 *s6 = (struct sockaddr_in6 *)sa;
		if (s6->sin6_scope_id == 0 && !IN6_IS_ADDR_LINKLOCAL(&s6->sin6_addr)) {
			ui_log("ADDR %s\n", format_addr((struct sockaddr_storage *)sa, sizeof(struct sockaddr_in6)));
		}
	}
}

static void
list_local_addrs(void (*cb)(struct sockaddr *))
{
#ifdef WINDOWS
	ULONG buflen = 32768;
	PIP_ADAPTER_ADDRESSES addrs = malloc(buflen);
	if (addrs && GetAdaptersAddresses(AF_UNSPEC, 0, NULL, addrs, &buflen) == NO_ERROR) {
		PIP_ADAPTER_ADDRESSES a;
		for (a = addrs; a != NULL; a = a->Next) {
			PIP_ADAPTER_UNICAST_ADDRESS u;
			if (a->OperStatus != IfOperStatusUp)
				continue;
			for (u = a->FirstUnicastAddress; u != NULL; u = u->Next) {
				cb(u->Address.lpSockaddr);
			}
		}
	}
	free(addrs);
#else
	struct ifaddrs *ifap, *ifa;
	if (getifaddrs(&ifap) == 0) {
		for (ifa = ifap; ifa != NULL; ifa = ifa->ifa_next) {
			if (ifa->ifa_flags & IFF_UP) {
				cb(ifa->ifa_addr);
			}
		}
		freeifaddrs(ifap);
	}
#endif
}

static int
get_bound_port(int fd)
{
	struct sockaddr_storage addr;
	socklen_t addrlen = sizeof(addr);

	if (fd < 0 || getsockname(fd, (struct sockaddr *)&addr, &addrlen) != 0)
		return 0;
	if (addr.ss_family == AF_INET)
		return ntohs(((struct sockaddr_in *)&addr)->sin_port);
	if (addr.ss_family == AF_INET6)
		return ntohs(((struct sockaddr_in6 *)&addr)->sin6_port);
	return 0;
}

int
main(int argc, char **argv)
{
	struct dnsfd dns_fds = { -1, -1 };
	struct server_params params;
	const char *topdomain = "test.iodine.code";
	char password[33] = "testpass";
	struct in_addr ns_ip;

	progname_init(argv[0]);
	network_init();
	ui_set_debuglevel(2);

	dns_fds.v4fd = open_udp_from_host(NULL, 0, AF_INET, AI_PASSIVE);
	dns_fds.v6fd = open_udp_from_host(NULL, 0, AF_INET6, AI_PASSIVE);

	if (dns_fds.v4fd < 0 && dns_fds.v6fd < 0) {
		ui_log("Failed to open any UDP socket\n");
		return 1;
	}

	ns_ip.s_addr = INADDR_ANY;
	if (argc > 1) {
		if (strcmp(argv[1], "auto") == 0) {
			if (get_external_ip(&ns_ip) != 0) {
				ui_log("Failed to get external IP\n");
				return 1;
			}
		} else if (inet_pton(AF_INET, argv[1], &ns_ip) != 1) {
			ui_log("Invalid nameserver IP: %s\n", argv[1]);
			return 1;
		}
		ui_log("NSADDR %s\n", format_inaddr(&ns_ip));
	}

	memset(&params, 0, sizeof(params));
	params.topdomain = topdomain;
	params.password = password;
	inet_pton(AF_INET, "10.0.0.1", &params.server_ip);
	params.netmask = 27;
	params.users = init_users(params.server_ip, params.netmask);
	params.check_ip = 1;
	params.tunnel_mtu = 1130;
	params.nameserver_ip = ns_ip.s_addr;
	server_init(&params);

	signal(SIGINT, sighandler);
	signal(SIGTERM, sighandler);

	list_local_addrs(print_sockaddr);
	ui_log("OPEN %s", topdomain);
	if (dns_fds.v4fd >= 0)
		ui_log(" v4=%d", get_bound_port(dns_fds.v4fd));
	if (dns_fds.v6fd >= 0)
		ui_log(" v6=%d", get_bound_port(dns_fds.v6fd));
	ui_log("\n");

	while (running) {
		fd_set fds;
		struct timeval tv;
		int maxfd = 0;
		int res;

		FD_ZERO(&fds);
		if (dns_fds.v4fd >= 0) {
			FD_SET(dns_fds.v4fd, &fds);
			maxfd = MAX(maxfd, dns_fds.v4fd);
		}
		if (dns_fds.v6fd >= 0) {
			FD_SET(dns_fds.v6fd, &fds);
			maxfd = MAX(maxfd, dns_fds.v6fd);
		}

		tv.tv_sec = 0;
		tv.tv_usec = 500000;

		res = select(maxfd + 1, &fds, NULL, NULL, &tv);
		if (res < 0) {
			if (running)
				warn("select");
			break;
		}
		if (res > 0) {
			if (dns_fds.v4fd >= 0 && FD_ISSET(dns_fds.v4fd, &fds)) {
				tunnel_dns(-1, dns_fds.v4fd, &dns_fds, -1);
			}
			if (dns_fds.v6fd >= 0 && FD_ISSET(dns_fds.v6fd, &fds)) {
				tunnel_dns(-1, dns_fds.v6fd, &dns_fds, -1);
			}
		}
	}

	if (dns_fds.v4fd >= 0)
		close_udp(dns_fds.v4fd);
	if (dns_fds.v6fd >= 0)
		close_udp(dns_fds.v6fd);

	ui_log("END\n");
	return 0;
}
