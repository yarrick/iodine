#include <check.h>
#include <common.h>
#include <sys/socket.h>
#include <netdb.h>

START_TEST(test_parse_format_ipv4)
{
	char *host = "192.168.2.10";
	char *formatted;
	struct sockaddr_storage addr;
	struct sockaddr_in *v4addr;
	int addr_len;

	addr_len = get_addr(host, 53, AF_INET, 0, &addr);
	fail_unless(addr_len == sizeof(struct sockaddr_in));

	v4addr = (struct sockaddr_in *) &addr;
	fail_unless(v4addr->sin_addr.s_addr == htonl(0xc0a8020a));
	fail_unless(v4addr->sin_port == htons(53));

	formatted = format_addr(&addr, addr_len);
	fail_if(strcmp(host, formatted));
}
END_TEST

START_TEST(test_parse_format_ipv4_listen_all)
{
	char *host = "0.0.0.0";
	char *formatted;
	struct sockaddr_storage addr;
	struct sockaddr_in *v4addr;
	int addr_len;

	addr_len = get_addr(NULL, 53, AF_INET, AI_PASSIVE, &addr);
	fail_unless(addr_len == sizeof(struct sockaddr_in));

	v4addr = (struct sockaddr_in *) &addr;
	fail_unless(v4addr->sin_addr.s_addr == htonl(0x00000000));
	fail_unless(v4addr->sin_port == htons(53));

	formatted = format_addr(&addr, addr_len);
	fail_if(strcmp(host, formatted));
}
END_TEST

TCase *
test_common_create_tests()
{
	TCase *tc;

	tc = tcase_create("Common");
	tcase_add_test(tc, test_parse_format_ipv4);
	tcase_add_test(tc, test_parse_format_ipv4_listen_all);
	return tc;
}
