/**
 * Manage privileges / capabilities on a *nix OS.
 */

#ifndef PRIVILEGES_H_
#define PRIVILEGES_H_

/**
 * Uses setuid to change to a non-privileged user
 *
 * @param user system username
 * @param group system group-name (set to NULL to not change group)
 *
 * @returns 0 if successful, -1 on error
 *
 */
int
ch_user(const char *user, const char *group);

/**
 * Relinquish root privileges by changing to the given user and group
 * 
 * @param user system username
 * @param group system group-name
 *
 * @returns 0 if successful, -1 on error
 */
int
drop_root(const char *user, const char *group);

#endif
