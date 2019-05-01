/*
 * Process a file downloaded from https://urlhaus.abuse.ch/api/ with a single URL on each line.
 *
 * Comments are denoted by '#'.
 *
 * The URLs include the 'http://' prefix and include the complete file location instead of just the
 * domain name. e.g. 'http://proforma-invoices.com/proforma/IFYRAW_Protected887.exe'
 *
 * These functions extract the domain name portion ONLY. For example, 'proforma-invoices.com' would
 * be extracted from the above URL.
 *
 * urlhaus_domain_blacklist.h
 *
 *  Created on: 11/04/2019
 *      Author: mfletche
 */

#ifndef SRC_URLHAUS_DOMAIN_BLACKLIST_H_
#define SRC_URLHAUS_DOMAIN_BLACKLIST_H_

/**
 * Get the next domain from a urlhaus file. If no more domains could be found, returns NULL.
 *
 * The returned string must be freed.
 *
 * @param fp: File pointer to the urlhaus file.
 */
char *
urlhaus_get_next_domain(FILE *fp);

#endif /* SRC_URLHAUS_DOMAIN_BLACKLIST_H_ */
