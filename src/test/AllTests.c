#include <stdio.h>
#include "CuTest.h"

CuSuite*
ids_event_list_get_suite();

void
run_all_tests(void)
{
	CuString *output = CuStringNew();
	CuSuite* suite = CuSuiteNew();

	CuSuiteAddSuite(suite, ids_event_list_get_suite());

	CuSuiteRun(suite);
	CuSuiteSummary(suite, output);
	CuSuiteDetails(suite, output);
	printf("%s\n", output->buffer);
}
