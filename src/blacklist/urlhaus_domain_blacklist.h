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
/** @file
 * @brief Process a file downloaded from https://urlhaus.abuse.ch/api/ with a single URL on each line.
 *
 * Comments are denoted by '#'.
 *
 * The URLs include the 'http://' prefix and include the complete file location instead of just the
 * domain name. e.g. 'http://proforma-invoices.com/proforma/IFYRAW_Protected887.exe'
 *
 * These functions extract the domain name portion ONLY. For example, 'proforma-invoices.com' would
 * be extracted from the above URL.
 */
#ifndef SRC_URLHAUS_DOMAIN_BLACKLIST_H_
#define SRC_URLHAUS_DOMAIN_BLACKLIST_H_

int
import_urlhaus_blacklist_file(char *path, domain_blacklist *bl);

#endif /* SRC_URLHAUS_DOMAIN_BLACKLIST_H_ */
