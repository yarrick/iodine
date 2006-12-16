#include <check.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "base32.h"
#include "test.h"

struct touple
{
	char *a;
	char *b;
} testpairs[] = {
	{ "abc123", "mfrggmjsgm" },
	{ NULL, NULL }	
};

START_TEST(test_base32_encode)
{
	size_t len;
	char *buf;
	int i;

	len = 0;
	buf = NULL;

	for (i = 0; testpairs[i].a != NULL; i++) {
		base32_encode(&buf, &len, testpairs[i].a, strlen(testpairs[i].a));

		fail_unless(strcmp(buf, testpairs[i].b) == 0, 
				va_str("'%s' != '%s'", buf, testpairs[i].b));
	}
}
END_TEST

START_TEST(test_base32_decode)
{
	size_t len;
	void *buf;
	int i;

	len = 0;
	buf = NULL;

	for (i = 0; testpairs[i].a != NULL; i++) {
		base32_decode(&buf, &len, testpairs[i].b);

		fail_unless(strcmp(buf, testpairs[i].a) == 0, 
				va_str("'%s' != '%s'", buf, testpairs[i].a));
	}
}
END_TEST

TCase *
test_base32_create_tests()
{
	TCase *tc;

	tc = tcase_create("Base32");
	tcase_add_test(tc, test_base32_encode);
	tcase_add_test(tc, test_base32_decode);

	return tc;
}
