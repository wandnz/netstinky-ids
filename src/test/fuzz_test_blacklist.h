/*
 * fuzz_test_blacklist.h
 *
 *  Created on: 2/05/2019
 *      Author: mfletche
 */

#ifndef SRC_TEST_FUZZ_TEST_BLACKLIST_H_
#define SRC_TEST_FUZZ_TEST_BLACKLIST_H_

#include <stdlib.h>

#include "../blacklist/domain_blacklist.h"
#include "../blacklist/ids_blacklist.h"
#include "../blacklist/ip_blacklist.h"

int fuzz_test_blacklists(const char *ip_file, const char *domain_file);

#endif /* SRC_TEST_FUZZ_TEST_BLACKLIST_H_ */
