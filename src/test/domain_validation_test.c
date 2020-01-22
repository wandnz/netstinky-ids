/*
 * domain_validation_test.c
 *
 *  Created on: 22/01/2020
 *      Author: amackint
 */
#include <stdio.h>
#include <string.h>

#include "../updates/domain_validation.h"


static int
test_domain_labels_too_short_returns_neg_1()
{
    const char *input = "";
    int result = is_domain_valid(input, strlen(input));

    return result < 0;
}

static int
test_domain_label_too_long_returns_neg_1()
{
    const char *input = \
"themaximumallowablelabellengthforadnslabelissixtythreecharacters.com";
    int result = is_domain_valid(input, strlen(input));

    return result < 0;
}

static int
test_domain_label_max_len_returns_0()
{
    const char *input = \
"themaxallowablelabellengthforadnslabelissixtythreecharacters63.com";
    int result = is_domain_valid(input, strlen(input));

    return result == 0;
}

static int
test_domain_too_long_returns_neg_1()
{
    const char *input = \
"bfjmwysmucznyonrwhjrstgxlcicrgfeypuky.nkosovxcvskuzrpfhfvkscoybfavh.vprxpnbhwehstjapudnmsqvgkel.eqmhooltlujbzfcxzhkimlqauoqgfjzujlyowpywjt.fjtfkoqxk.mzzqhcweggfbnv.jrkelwoehpyluuxblqvovy.idcwbmo.furqmojvyppjq.jbx.tzmjxnpfjdxsk.abqcppyrqykvakcfnp.phvcymv7y2";
    int result = is_domain_valid(input, strlen(input));

    return result < 0;
}

static int
test_domain_max_len_returns_0()
{
    const char *input = \
"bfjmwysmucznyonrwhjrstgxlcicrgfeypuky.nkosovxcvskuzrpfhfvkscoybfavh.vprxpnbhwehstjapudnmsqvgkel.eqmhooltlujbzfcxzhkimlqauoqgfjzujlyowpywjt.fjtfkoqxk.mzzqhcweggfbnv.jrkelwoehpyluuxblqvovy.idcwbmo.furqmojvyppjq.jbx.tzmjxnpfjdxsk.abqcppyrqykvakcfnp.phvcymv";
    int result = is_domain_valid(input, strlen(input));

    return result == 0;
}

static int
test_domain_invalid_chars_returns_0()
{
    const char *input = "using_an_invalid.char";
    int result = is_domain_valid(input, strlen(input));

    return result < 0;
}


int main(int argc, char **argv)
{
    int test_result = 1;
    test_result = test_result && test_domain_labels_too_short_returns_neg_1();
    test_result = test_result && test_domain_label_too_long_returns_neg_1();
    test_result = test_result && test_domain_label_max_len_returns_0();
    test_result = test_result && test_domain_too_long_returns_neg_1();
    test_result = test_result && test_domain_max_len_returns_0();
    test_result = test_result && test_domain_invalid_chars_returns_0();

    return !test_result;
}
