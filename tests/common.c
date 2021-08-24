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

#include <check.h>
#include <common.h>
#include <unistd.h>
#include <sys/socket.h>
#include <netdb.h>

START_TEST(test_topdomain_ok)
{
	char *error = NULL;

	ck_assert(check_topdomain("foo.0123456789.qwertyuiop.asdfghjkl.zxcvbnm.com", 0, &error) == 0);
	ck_assert(error == NULL);
	/* Allowing wildcard */
	ck_assert(check_topdomain("foo.0123456789.qwertyuiop.asdfghjkl.zxcvbnm.com", 1, &error) == 0);
	ck_assert(error == NULL);

	/* Not allowed to start with dot */
	ck_assert(check_topdomain(".foo.0123456789.qwertyuiop.asdfghjkl.zxcvbnm.com", 0, &error));
	ck_assert_str_eq("Starts with a dot", error);

	/* Test missing error msg ptr */
	ck_assert(check_topdomain(".foo", 0, NULL));
}
END_TEST

START_TEST(test_topdomain_length)
{
	char *error;

	/* Test empty and too short */
	ck_assert(check_topdomain("", 0, &error));
	ck_assert_str_eq("Too short (< 3)", error);
	error = NULL;
	ck_assert(check_topdomain("a", 0, &error));
	ck_assert_str_eq("Too short (< 3)", error);
	error = NULL;
	ck_assert(check_topdomain(".a", 0, &error));
	ck_assert_str_eq("Too short (< 3)", error);
	error = NULL;
	ck_assert(check_topdomain("a.", 0, &error));
	ck_assert_str_eq("Too short (< 3)", error);
	error = NULL;
	ck_assert(check_topdomain("ab", 0, &error));
	ck_assert_str_eq("Too short (< 3)", error);
	error = NULL;
	ck_assert(check_topdomain("a.b", 0, &error) == 0);

	/* Test too long (over 128, need rest of space for data) */
	ck_assert(check_topdomain(
		"abcd12345.abcd12345.abcd12345.abcd12345.abcd12345."
		"abcd12345.abcd12345.abcd12345.abcd12345.abcd12345."
		"abcd12345.abcd12345.foo129xxx", 0, &error));
	ck_assert_str_eq("Too long (> 128)", error);
	ck_assert(check_topdomain(
		"abcd12345.abcd12345.abcd12345.abcd12345.abcd12345."
		"abcd12345.abcd12345.abcd12345.abcd12345.abcd12345."
		"abcd12345.abcd12345.foo128xx", 0, &error) == 0);
}
END_TEST

START_TEST(test_topdomain_chunks)
{
	char *error;

	/* Must have at least one dot */
	ck_assert(check_topdomain("abcde.gh", 0, &error) == 0);
	ck_assert(check_topdomain("abcdefgh", 0, &error));
	ck_assert_str_eq("No dots", error);

	/* Not two consecutive dots */
	ck_assert(check_topdomain("abc..defgh", 0, &error));
	ck_assert_str_eq("Consecutive dots", error);

	/* Not end with a dots */
	ck_assert(check_topdomain("abc.defgh.", 0, &error));
	ck_assert_str_eq("Ends with a dot", error);

	/* No chunk longer than 63 chars */
	ck_assert(check_topdomain("123456789012345678901234567890"
		"123456789012345678901234567890333.com", 0, &error) == 0);
	ck_assert(check_topdomain("123456789012345678901234567890"
		"1234567890123456789012345678904444.com", 0, &error));
	ck_assert_str_eq("Too long domain part (> 63)", error);

	ck_assert(check_topdomain("abc.123456789012345678901234567890"
		"123456789012345678901234567890333.com", 0, &error) == 0);
	ck_assert(check_topdomain("abc.123456789012345678901234567890"
		"1234567890123456789012345678904444.com", 0, &error));
	ck_assert_str_eq("Too long domain part (> 63)", error);

	ck_assert(check_topdomain("abc.123456789012345678901234567890"
		"123456789012345678901234567890333", 0, &error) == 0);
	ck_assert(check_topdomain("abc.123456789012345678901234567890"
		"1234567890123456789012345678904444", 0, &error));
	ck_assert_str_eq("Too long domain part (> 63)", error);
}
END_TEST

START_TEST(test_topdomain_wild)
{
	char *error = NULL;

	ck_assert(check_topdomain("*.a", 0, &error) == 1);
	ck_assert_str_eq("Contains illegal character (allowed: [a-zA-Z0-9-.])", error);
	error = NULL;
	ck_assert(check_topdomain("*.a", 1, &error) == 0);
	ck_assert(error == NULL);

	ck_assert(check_topdomain("b*.a", 0, &error) == 1);
	ck_assert_str_eq("Contains illegal character (allowed: [a-zA-Z0-9-.])", error);
	error = NULL;
	ck_assert(check_topdomain("b*.a", 1, &error) == 1);
	ck_assert_str_eq("Wildcard (*) only allowed as first char", error);

	ck_assert(check_topdomain("*b.a", 0, &error) == 1);
	ck_assert_str_eq("Contains illegal character (allowed: [a-zA-Z0-9-.])", error);
	error = NULL;
	ck_assert(check_topdomain("*b.a", 1, &error) == 1);
	ck_assert_str_eq("Wildcard (*) must be followed by dot", error);

	ck_assert(check_topdomain("*.*.a", 0, &error) == 1);
	ck_assert_str_eq("Contains illegal character (allowed: [a-zA-Z0-9-.])", error);
	error = NULL;
	ck_assert(check_topdomain("*.*.a", 1, &error) == 1);
	ck_assert_str_eq("Wildcard (*) only allowed as first char", error);
}
END_TEST

START_TEST(test_query_datalen)
{
	char *topdomain = "r.foo.com";
	/* With data */
	ck_assert(query_datalen("foobar.r.foo.com", topdomain) == 7);
	ck_assert(query_datalen("foobar.r.FoO.Com", topdomain) == 7);
	ck_assert(query_datalen("foo.bar.r.FoO.Com", topdomain) == 8);
	ck_assert(query_datalen(".r.foo.com", topdomain) == 1);
	/* Without data */
	ck_assert(query_datalen("r.foo.com", topdomain) == 0);
	ck_assert(query_datalen("R.foo.com", topdomain) == 0);
	/* Shorter query name */
	ck_assert(query_datalen("foo.com", topdomain) == -1);
	/* Mismatched query name */
	ck_assert(query_datalen("b.foo.com", topdomain) == -1);
	ck_assert(query_datalen("*.foo.com", topdomain) == -1);
	/* Query name overlaps topdomain, but is longer */
	ck_assert(query_datalen("bar.foo.com", topdomain) == -1);
}
END_TEST

START_TEST(test_query_datalen_wild)
{
	char *topdomain = "*.foo.com";
	/* With data */
	ck_assert(query_datalen("foobar.a.foo.com", topdomain) == 7);
	ck_assert(query_datalen("foobar.r.FoO.Com", topdomain) == 7);
	ck_assert(query_datalen("foo.bar.r.FoO.Com", topdomain) == 8);
	ck_assert(query_datalen("foo.Ab.foo.cOm", topdomain) == 4);
	ck_assert(query_datalen("foo.Abcd.Foo.com", topdomain) == 4);
	ck_assert(query_datalen("***.STARs.foo.com", topdomain) == 4);
	ck_assert(query_datalen(".a.foo.com", topdomain) == 1);
	ck_assert(query_datalen(".ab.foo.com", topdomain) == 1);
	/* Without data */
	ck_assert(query_datalen("rr.foo.com", topdomain) == 0);
	ck_assert(query_datalen("b.foo.com", topdomain) == 0);
	ck_assert(query_datalen("B.foo.com", topdomain) == 0);
	/* Shorter query name */
	ck_assert(query_datalen("foo.com", topdomain) == -1);
	/* Wildcard part of query name matching topdomain */
	ck_assert(query_datalen("aa.*.foo.com", topdomain) == -1);
	/* Mismatched query name */
	ck_assert(query_datalen("bar.r.boo.com", topdomain) == -1);
}
END_TEST

START_TEST(test_parse_format_ipv4)
{
	char *host = "192.168.2.10";
	char *formatted;
	struct sockaddr_storage addr;
	struct sockaddr_in *v4addr;
	int addr_len;

	addr_len = get_addr(host, 53, AF_INET, 0, &addr);
	ck_assert(addr_len == sizeof(struct sockaddr_in));

	v4addr = (struct sockaddr_in *) &addr;
	ck_assert(v4addr->sin_addr.s_addr == htonl(0xc0a8020a));
	ck_assert(v4addr->sin_port == htons(53));

	formatted = format_addr(&addr, addr_len);
	ck_assert_str_eq(host, formatted);
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
	ck_assert(addr_len == sizeof(struct sockaddr_in));

	v4addr = (struct sockaddr_in *) &addr;
	ck_assert(v4addr->sin_addr.s_addr == htonl(0x00000000));
	ck_assert(v4addr->sin_port == htons(53));

	formatted = format_addr(&addr, addr_len);
	ck_assert_str_eq(host, formatted);
}
END_TEST

START_TEST(test_parse_format_ipv6)
{
	char *host = "2001:0db8:0505:0::123:0abc";
	char *compact = "2001:db8:505::123:abc";
	unsigned char v6_bits[] = {
		0x20, 0x01, 0x0d, 0xb8, 0x05, 0x05, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x01, 0x23, 0x0a, 0xbc,
	};
	char *formatted;
	struct sockaddr_storage addr;
	struct sockaddr_in6 *v6addr;
	int addr_len;

	addr_len = get_addr(host, 53, AF_UNSPEC, 0, &addr);
	ck_assert(addr_len == sizeof(struct sockaddr_in6));

	v6addr = (struct sockaddr_in6 *) &addr;
	ck_assert(memcmp(&v6addr->sin6_addr, v6_bits, sizeof(v6_bits)) == 0);
	ck_assert(v6addr->sin6_port == htons(53));

	formatted = format_addr(&addr, addr_len);
	ck_assert_str_eq(compact, formatted);
}
END_TEST

START_TEST(test_parse_format_ipv4_mapped_ipv6)
{
	char *v4mapped = "::FFFF:192.168.2.10";
	char *host = "192.168.2.10";
	unsigned char v6_bits[] = {
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0xff, 0xff, 0xc0, 0xa8, 0x02, 0x0a,
	};
	char *formatted;
	struct sockaddr_storage addr;
	struct sockaddr_in6 *v6addr;
	int addr_len;

	addr_len = get_addr(v4mapped, 53, AF_INET6, 0, &addr);
	ck_assert(addr_len == sizeof(struct sockaddr_in6));

	v6addr = (struct sockaddr_in6 *) &addr;
	ck_assert(memcmp(&v6addr->sin6_addr, v6_bits, sizeof(v6_bits)) == 0);
	ck_assert(v6addr->sin6_port == htons(53));

	/* Format as IPv4 address */
	formatted = format_addr(&addr, addr_len);
	ck_assert_str_eq(host, formatted);
}
END_TEST

TCase *
test_common_create_tests()
{
	TCase *tc;
	int sock;

	tc = tcase_create("Common");
	tcase_add_test(tc, test_topdomain_ok);
	tcase_add_test(tc, test_topdomain_length);
	tcase_add_test(tc, test_topdomain_chunks);
	tcase_add_test(tc, test_topdomain_wild);
	tcase_add_test(tc, test_query_datalen);
	tcase_add_test(tc, test_query_datalen_wild);
	tcase_add_test(tc, test_parse_format_ipv4);
	tcase_add_test(tc, test_parse_format_ipv4_listen_all);

	/* Tests require IPv6 support */
	sock = socket(AF_INET6, SOCK_DGRAM, IPPROTO_UDP);
	if (sock >= 0) {
		close(sock);
		tcase_add_test(tc, test_parse_format_ipv6);
		tcase_add_test(tc, test_parse_format_ipv4_mapped_ipv6);
	}
	return tc;
}
