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
#include <string.h>

#include "CuTest.h"
#include "utils/str.h"


void testSplitString_withNullString_returnsNeg1(CuTest *tc)
{
    const char *string = NULL;
    char *header = NULL;
    char *value = NULL;
    int result = 0;

    result = split_string(':', string, 5, &header, &value);

    CuAssertIntEquals(tc, -1, result);
}

void testSplitString_withStringNotContainingSplitChar_returnsNeg1(CuTest *tc)
{
    const char *string = "Hello";
    char *header = NULL;
    char *value = NULL;

    int result = split_string(':', string, 5, &header, &value);

    CuAssertIntEquals(tc, -1, result);
}

void testSplitString_withStringNoValue_returns0(CuTest *tc)
{
    const char *string = "Hello:";
    char *header = NULL;
    char *value = NULL;

    int result = split_string(':', string, 6, &header, &value);

    CuAssertIntEquals(tc, 0, result);
}

void testSplitString_withEmptyString_returnsNeg1(CuTest *tc)
{
    const char *string = "";
    char *header = NULL;
    char *value = NULL;

    int result = split_string(':', string, 0, &header, &value);

    CuAssertIntEquals(tc, -1, result);
}

void testSplitString_withStringNoValue_assignsCorrectPointers(CuTest *tc)
{
    const char *string = "Hello:";
    const char *expected_header = "Hello";
    const char *expected_value = "";
    char *header = NULL;
    char *value = NULL;

    split_string(':', string, 6, &header, &value);

    CuAssertStrEquals(tc, header, expected_header);
    CuAssertStrEquals(tc, value, expected_value);
}

void testSplitString_withStringNoHeader_returns0(CuTest *tc)
{
    const char *string = ":Hello";
    char *header = NULL;
    char *value = NULL;

    int result = split_string(':', string, 6, &header, &value);

    CuAssertIntEquals(tc, result, 0);
}

void testSplitString_withStringNoHeader_assignsCorrectPointers(CuTest *tc)
{
    const char *string = ":Hello";
    const char *expected_header = "";
    const char *expected_value = "Hello";
    char *header = NULL;
    char *value = NULL;

    split_string(':', string, 6, &header, &value);

    CuAssertStrEquals(tc, header, expected_header);
    CuAssertStrEquals(tc, value, expected_value);
}

void testSplitString_withValidString_assignsCorrectPointers(CuTest *tc)
{
    const char *string = "Content-Type:text/json";
    const char *expected_header = "Content-Type";
    const char *expected_value = "text/json";
    char *header = NULL;
    char *value = NULL;

    split_string(':', string, strlen(string), &header, &value);

    CuAssertStrEquals(tc, expected_header, header);
    CuAssertStrEquals(tc, expected_value, value);
}

void testTrimLeadingWhitespace_wValidStr_isExpectedString(CuTest *tc)
{
    const char *input = "  Hello, world!\n";
    char actual[18];
    const char *expected = "Hello, world!\n";
    const size_t expected_size = strlen(expected);
    int result;
    char *orig_ptr = actual;

    strcpy(actual, input);

    result = trim_leading_whitespace(actual, strlen(input));

    CuAssertTrue(tc, expected_size == strlen(actual));
    CuAssertStrEquals(tc, expected, actual);
    CuAssertPtrEquals(tc, orig_ptr, actual);
}

void testTrimLeadingWhitespace_wWhitespaceOnly_createsEmptyString(CuTest *tc)
{
    const char *input = "         ";
    const char *expected = "";
    const size_t expected_len = 0;
    size_t str_len;
    char actual[18];
    char *orig_ptr = actual;

    strcpy(actual, input);

    str_len = trim_leading_whitespace(actual, strlen(input));

    CuAssertIntEquals(tc, expected_len, str_len);
    CuAssertStrEquals(tc, expected, actual);
    CuAssertPtrEquals(tc, orig_ptr, actual);
}

void testTrimLeadingWhitespace_withEmptyStr_stillEmptyString(CuTest *tc)
{
    const char *input = "";
    const char *expected = "";
    char actual[8];
    size_t str_len;
    char *orig_ptr = actual;

    strcpy(actual, input);

    str_len = trim_leading_whitespace(
            actual,
            strlen(input));

    CuAssertIntEquals(tc, 0, str_len);
    CuAssertStrEquals(tc, expected, actual);
    CuAssertPtrEquals(tc, orig_ptr, actual);
}

void testTrimLeadingWhitespace_withNullStr_returnsNeg1(CuTest *tc)
{
    int result;

    result = trim_leading_whitespace(NULL, 0);

    CuAssertIntEquals(tc, -1, result);
}

void testTrimTrailingWhitespace_withValidStr_isExpectedStr(CuTest *tc)
{
    const char *input = "Hello, world!   ";
    char actual[18];
    const char *expected = "Hello, world!";
    size_t str_len;
    char *orig_ptr = actual;

    strcpy(actual, input);

    str_len = trim_trailing_whitespace(
            actual,
            strlen(input));

    CuAssertIntEquals(tc, strlen(expected), str_len);
    CuAssertStrEquals(tc, expected, actual);
    CuAssertPtrEquals(tc, orig_ptr, actual);
}

void testTrimTrailingWhitespace_wWhitespaceOnlyStr_isEmptyString(CuTest *tc)
{
    const char *input = "    ";
    char actual[18];
    const char *expected = "";
    size_t str_len;
    char *orig_ptr = actual;

    strcpy(actual, input);

    str_len = trim_trailing_whitespace(
            actual,
            strlen(input));

    CuAssertIntEquals(tc, strlen(expected), str_len);
    CuAssertStrEquals(tc, expected, actual);
    CuAssertPtrEquals(tc, orig_ptr, actual);
}

void testTrimTrailingWhitespace_wEmptyString_createsEmptyString(CuTest *tc)
{
    const char *input = "";
    char actual[18];
    const char *expected = "";
    size_t str_len;
    char *orig_ptr = actual;

    strcpy(actual, input);

    str_len = trim_trailing_whitespace(
            actual,
            strlen(actual));

    CuAssertIntEquals(tc, strlen(expected), str_len);
    CuAssertStrEquals(tc, expected, actual);
    CuAssertPtrEquals(tc, orig_ptr, actual);
}

void testTrimTrailingWhitespace_wNullString_returnsNeg1(CuTest *tc)
{
    int result;

    result = trim_trailing_whitespace(NULL, 0);

    CuAssertIntEquals(tc, -1, result);
}

CuSuite *StrGetSuite(void)
{
    CuSuite *suite = CuSuiteNew();

    SUITE_ADD_TEST(suite,
        testSplitString_withNullString_returnsNeg1);
    SUITE_ADD_TEST(suite,
        testSplitString_withStringNotContainingSplitChar_returnsNeg1);
    SUITE_ADD_TEST(suite,
        testSplitString_withStringNoValue_returns0);
    SUITE_ADD_TEST(suite,
        testSplitString_withEmptyString_returnsNeg1);
    SUITE_ADD_TEST(suite,
        testSplitString_withStringNoValue_assignsCorrectPointers);
    SUITE_ADD_TEST(suite,
        testSplitString_withStringNoHeader_returns0);
    SUITE_ADD_TEST(suite,
        testSplitString_withStringNoHeader_assignsCorrectPointers);
    SUITE_ADD_TEST(suite,
        testSplitString_withValidString_assignsCorrectPointers);

    SUITE_ADD_TEST(suite,
        testTrimLeadingWhitespace_wValidStr_isExpectedString);
    SUITE_ADD_TEST(suite,
        testTrimLeadingWhitespace_wWhitespaceOnly_createsEmptyString);
    SUITE_ADD_TEST(suite,
        testTrimLeadingWhitespace_withEmptyStr_stillEmptyString);
    SUITE_ADD_TEST(suite,
        testTrimLeadingWhitespace_withNullStr_returnsNeg1);

    SUITE_ADD_TEST(suite,
        testTrimTrailingWhitespace_withValidStr_isExpectedStr);
    SUITE_ADD_TEST(suite,
        testTrimTrailingWhitespace_wWhitespaceOnlyStr_isEmptyString);
    SUITE_ADD_TEST(suite,
        testTrimTrailingWhitespace_wEmptyString_createsEmptyString);
    SUITE_ADD_TEST(suite,
        testTrimTrailingWhitespace_wNullString_returnsNeg1);
    return suite;
}

