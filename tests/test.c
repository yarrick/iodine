#include <check.h>
#include <stdio.h>
#include <stdarg.h>
#include <stdlib.h>

#include "test.h"

char *
va_str(const char *fmt, ...)
{
	static char buf[512];
	va_list ap;

	va_start(ap, fmt);
	vsnprintf(buf, sizeof(buf), fmt, ap);	
	va_end(ap);

	return buf;
}

int
main()
{
	SRunner *runner;
	Suite *iodine;
	TCase *test;
	int failed;

	iodine = suite_create("Iodine");

	test = test_base32_create_tests();
	suite_add_tcase(iodine, test);

 	test = test_read_create_tests();
	suite_add_tcase(iodine, test);

	runner = srunner_create(iodine);
	srunner_run_all(runner, CK_VERBOSE);
	failed = srunner_ntests_failed(runner);

	srunner_free(runner);

	return (failed == 0) ? EXIT_SUCCESS : EXIT_FAILURE;
}
