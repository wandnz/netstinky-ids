/*
 *
 * Copyright (c) 2020 The University of Waikato, Hamilton, New Zealand.
 *
 * This file is part of netstinky-ids.
 *
 * Use of this source code is governed by a BSD-style
 * license that can be found in the LICENSE file or at
 * https://opensource.org/licenses/BSD-2-Clause
 *
 *
 */
#include <stdio.h>
#include <string.h>

#include "CuTest.h"

//
// Suites to be included by linker. Add a function here to add a new suite,
// then call CuSuiteAddSuite in RunAllTests
//
CuSuite *StrGetSuite(void);
CuSuite *IdsEventListGetSuite(void);

void RunAllTests(void) {
    CuString *output = CuStringNew();

    CuSuite *strSuite = StrGetSuite();
    CuSuite *idsEventListSuite = IdsEventListGetSuite();

    CuSuite masterSuite;
    memset(&masterSuite, 0, sizeof(masterSuite));
    CuSuiteInit(&masterSuite);

    CuSuiteAddSuite(&masterSuite, strSuite);
    CuSuiteAddSuite(&masterSuite, idsEventListSuite);

    CuSuiteRun(&masterSuite);
    CuSuiteSummary(&masterSuite, output);
    CuSuiteDetails(&masterSuite, output);
    printf("%s\n", output->buffer);

    CuSuiteDelete(idsEventListSuite);
    CuSuiteDelete(strSuite);
    CuStringDelete(output);
}

int main(void) {
    RunAllTests();
    return 0;
}

