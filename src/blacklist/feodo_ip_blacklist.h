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
