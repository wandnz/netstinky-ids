/*
 * feodo_ip_blacklist.h
 *
 *  Created on: Aug 19, 2019
 *      Author: mfletche
 */

#ifndef SRC_BLACKLIST_FEODO_IP_BLACKLIST_H_
#define SRC_BLACKLIST_FEODO_IP_BLACKLIST_H_

/**
 * Import a Feodo blacklist into an ip_blacklist structure.
 * @param path Path to the file.
 * @param bl The blacklist structure.
 * @return Number of blacklist entries imported, or -1 if unsuccessful.
 */
int
import_feodo_blacklist(char *path, ip_blacklist *bl);

#endif /* SRC_BLACKLIST_FEODO_IP_BLACKLIST_H_ */
