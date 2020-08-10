/*
 *  static.c
 *
 *  static idmapping functions for gss principals.
 *
 *  Copyright (c) 2008 David Härdeman <david@hardeman.nu>.
 *  All rights reserved.
 *
 *  Redistribution and use in source and binary forms, with or without
 *  modification, are permitted provided that the following conditions
 *  are met:
 *
 *  1. Redistributions of source code must retain the above copyright
 *     notice, this list of conditions and the following disclaimer.
 *  2. Redistributions in binary form must reproduce the above copyright
 *     notice, this list of conditions and the following disclaimer in the
 *     documentation and/or other materials provided with the distribution.
 *  3. Neither the name of the University nor the names of its
 *     contributors may be used to endorse or promote products derived
 *     from this software without specific prior written permission.
 *
 *  THIS SOFTWARE IS PROVIDED ``AS IS'' AND ANY EXPRESS OR IMPLIED
 *  WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF
 *  MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
 *  DISCLAIMED. IN NO EVENT SHALL THE REGENTS OR CONTRIBUTORS BE LIABLE
 *  FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
 *  CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
 *  SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR
 *  BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF
 *  LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING
 *  NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
 *  SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

#include <unistd.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <pwd.h>
#include <grp.h>
#include <errno.h>
#include <err.h>

#include "conffile.h"
#include "nfsidmap.h"
#include "nfsidmap_plugin.h"
#include "passwd_query.h"


/*
 * Static Translation Methods
 *
 * These functions use getpwnam to find uid/gid(s) for gss principals
 * which are first mapped to local user names using static mappings
 * in idmapd.conf.
 */

struct passwd_ints {
	uid_t  uid;
	gid_t  gid;
	int    return_code; // Return code from getpwnam_r or getpwuid_r.
};

struct group_ints {
	gid_t  gid;
	int    return_code; // Return code from getgrnam_r or getgrgid_r.
};

struct uid_mapping {
	LIST_ENTRY (uid_mapping) link;
	uid_t uid;
	char * principal;
	char * localname;
};

struct gid_mapping {
	LIST_ENTRY (gid_mapping) link;
	gid_t gid;
	char * principal;
	char * localgroup;
};

static __inline__ u_int8_t uid_hash (uid_t uid)
{
	return uid % 256;
}

static __inline__ u_int8_t gid_hash (gid_t gid)
{
	return gid % 256;
}

//Hash tables of uid and guids to principals mappings.
//We reuse some queue/hash functions from cfg.c.
LIST_HEAD (uid_mappings, uid_mapping) uid_mappings[256];
LIST_HEAD (gid_mappings, gid_mapping) gid_mappings[256];

static int static_inner_getpwnam(
				struct nfsutil_passwd_query *query,
				const char *name,
				const char *UNUSED(domain))
{
	char *localname = conf_get_str("Static", (char *)name);
	if (!localname)
		return ENOENT;

	// Call getpwnam_r.
	int err;
	do {
		err = nfsutil_pw_query_call_getpwnam_r(query, localname);
	}
	while ( err == EINTR );

	// Print errors.
	if ( err == EIO )
		IDMAP_LOG(0, ("static_getpwnam: "
			"I/O error while looking up local name '%s' for Static entry with name '%s'",
			localname, name));
	else
	if ( err == EMFILE )
		IDMAP_LOG(0, ("static_getpwnam: "
			"Error while looking up local name '%s' for Static entry with name '%s': "
			"All file descriptors available to the process are currently open.",
			localname, name));
	else
	if ( err == ENFILE )
		IDMAP_LOG(0, ("static_getpwnam: "
			"Error while looking up local name '%s' for Static entry with name '%s': "
			"The maximum allowable number of files is currently open in the system.",
			localname, name));
	else
	if ( err != 0 )
	{
		// Calling strerror is undesirable (thread safety and such), but this
		// branch should not get executed anyways (we have exhausted all error
		// codes returned by getpwnam_r/nfsutil_pw_query_call_getpwnam_r),
		// and if execution does reach this point, we are getting desparate
		// enough to risk it.
		const char *errmsg = strerror(err);
		IDMAP_LOG(0, ("static_getpwnam: "
			"Unknown error while looking up local name '%s' for Static entry with name '%s'. "
			"%s%s",
			localname, name,
			errmsg ? " strerror reports this: " : "",
			errmsg ? errmsg : ""));
	}

	// Error recovery/response is handled by the caller.
	if (err != 0)
		return err;

	err = 0;
	struct passwd *pw = nfsutil_pw_query_result(query);
	if (!pw)
		err = ENOENT;

	if ( err == ENOENT )
		IDMAP_LOG(0, ("static_getpwnam: localname '%s' for '%s' not found",
			localname, name));
	else
		IDMAP_LOG(4, ("static_getpwnam: name '%s' mapped to '%s'",
			name, localname));

	return err;
}

static struct passwd_ints static_getpwnam(
		const char *name,
		const char *UNUSED(domain),
		struct passwd **pw_result // NULL indicates that the caller doesn't need it.
	)
{
	char    bufptr[PASSWD_STACKMEM_SIZE_HINT];
	size_t  buflen = PASSWD_STACKMEM_SIZE_HINT;
	struct  nfsutil_passwd_query  passwd_query;
	struct  passwd       *pw_tmp    = NULL;
	struct  passwd_ints  results_lite;

	nfsutil_pw_query_init(&passwd_query, bufptr, buflen);

	int err = static_inner_getpwnam(&passwd_query, name, NULL);
	pw_tmp = nfsutil_pw_query_result(&passwd_query);
	// We won't worry about `pw_tmp` being NULL or `err` being non-zero
	// because `nfsutil_clone_passwd` effectively becomes a no-op under such conditions.

	if ( pw_result != NULL ) // true if caller requires these results
	{
		// The caller will be responsible for calling `free` on `*pw_result`.
		int oom = nfsutil_clone_passwd(pw_result, pw_tmp);
		if ( oom ) // Only ENOMEM should be possible.
			err = oom;
		// Any errors in nfsutil_clone_passwd will set `*pw_result` to NULL.
	}

	// Populate the returnable results structure.
	if ( pw_tmp ) {
		results_lite.uid = pw_tmp->pw_uid;
		results_lite.gid = pw_tmp->pw_gid;
	} else {
		results_lite.uid = (uid_t)(-1);
		results_lite.gid = (gid_t)(-1);
	}

	results_lite.return_code = err;

	// It is always safe to call the cleanup function as long as we're done
	// with the query object.
	nfsutil_pw_query_cleanup(&passwd_query);

	return results_lite;
}

static int static_inner_getgrnam(
				struct nfsutil_group_query *query,
				const char *name,
				const char *UNUSED(domain))
{
	char *localgroup = conf_get_str("Static", (char *)name);
	if (!localgroup)
		return ENOENT;

	// Call getgrnam_r.
	int err;
	do {
		err = nfsutil_grp_query_call_getgrnam_r(query, localgroup);
	}
	while ( err == EINTR );

	// Print errors.
	if ( err == EIO )
		IDMAP_LOG(0, ("static_getgrnam: "
			"I/O error while looking up local group '%s' for Static entry with name '%s'",
			localgroup, name));
	else
	if ( err == EMFILE )
		IDMAP_LOG(0, ("static_getgrnam: "
			"Error while looking up local group '%s' for Static entry with name '%s': "
			"All file descriptors available to the process are currently open.",
			localgroup, name));
	else
	if ( err == ENFILE )
		IDMAP_LOG(0, ("static_getgrnam: "
			"Error while looking up local group '%s' for Static entry with name '%s': "
			"The maximum allowable number of files is currently open in the system.",
			localgroup, name));
	else
	if ( err != 0 )
	{
		// Calling strerror is undesirable (thread safety and such), but this
		// branch should not get executed anyways (we have exhausted all error
		// codes returned by getgrnam_r/nfsutil_grp_query_call_getgrnam_r),
		// and if execution does reach this point, we are getting desparate
		// enough to risk it.
		const char *errmsg = strerror(err);
		IDMAP_LOG(0, ("static_getgrnam: "
			"Unknown error while looking up local group '%s' for Static entry with name '%s'. "
			"%s%s",
			localgroup, name,
			errmsg ? " strerror reports this: " : "",
			errmsg ? errmsg : ""));
	}

	// Error recovery/response is handled by the caller.
	if (err != 0)
		return err;

	err = 0;
	struct group *grp = nfsutil_grp_query_result(query);
	if (!grp)
		err = ENOENT;

	if ( err == ENOENT )
		IDMAP_LOG(0, ("static_getgrnam: local group '%s' for '%s' not found",
			localgroup, name));
	else
		IDMAP_LOG(4, ("static_getgrnam: group '%s' mapped to '%s'",
			name, localgroup));

	return err;
}

static struct group_ints static_getgrnam(
		const char *name,
		const char *UNUSED(domain))
{
	char    bufptr[GROUP_STACKMEM_SIZE_HINT];
	size_t  buflen = GROUP_STACKMEM_SIZE_HINT;
	struct  nfsutil_group_query  group_query;
	struct  group       *grp_tmp    = NULL;
	struct  group_ints  results_lite;

	nfsutil_grp_query_init(&group_query, bufptr, buflen);

	int err = static_inner_getgrnam(&group_query, name, NULL);
	grp_tmp = nfsutil_grp_query_result(&group_query);

	// Populate the returnable results structure.
	if ( grp_tmp )
		results_lite.gid = grp_tmp->gr_gid;
	else
		results_lite.gid = (gid_t)(-1);

	results_lite.return_code = err;

	// It is always safe to call the cleanup function as long as we're done
	// with the query object.
	nfsutil_grp_query_cleanup(&group_query);

	return results_lite;
}


static int static_gss_princ_to_ids(char *secname, char *princ,
				   uid_t *uid, uid_t *gid,
				   extra_mapping_params **UNUSED(ex))
{
	/* XXX: Is this necessary? */
	if (strcmp(secname, "krb5") != 0 && strcmp(secname, "spkm3") != 0)
		return -EINVAL;

	struct passwd_ints pw_ints = static_getpwnam(princ, NULL, NULL);
	int err = pw_ints.return_code;

	if (!err) {
		*uid = pw_ints.uid;
		*gid = pw_ints.gid;
	}

	return -err;
}

static int static_gss_princ_to_grouplist(char *secname, char *princ,
					 gid_t *groups, int *ngroups,
					 extra_mapping_params **UNUSED(ex))
{
	/* XXX: Is this necessary? */
	if (strcmp(secname, "krb5") != 0 && strcmp(secname, "spkm3") != 0)
		return -EINVAL;

	struct passwd *pw;
	struct passwd_ints pw_ints = static_getpwnam(princ, NULL, &pw);
	int err = pw_ints.return_code;

	if (pw) {
		if (getgrouplist(pw->pw_name, pw->pw_gid, groups, ngroups) < 0)
			err = -ERANGE;
		free(pw);
	}

	return -err;
}

static int static_name_to_uid(char *name, uid_t *uid)
{
	struct passwd_ints pw_ints = static_getpwnam(name, NULL, NULL);
	int err = pw_ints.return_code;

	if (!err)
		*uid = pw_ints.uid;

	return -err;
}

static int static_name_to_gid(char *name, gid_t *gid)
{
	struct group_ints grp_ints = static_getgrnam(name, NULL);
	int err = grp_ints.return_code;

	if (!err)
		*gid = grp_ints.gid;

	return -err;
}

static int static_uid_to_name(uid_t uid, char *UNUSED(domain), char *name, size_t UNUSED(len))
{
	struct uid_mapping * um;

	for (um = LIST_FIRST (&uid_mappings[uid_hash (uid)]); um;
		um = LIST_NEXT (um, link)) {
		if (um->uid == uid) {
			strcpy(name, um->principal);
			return 0;
		}
	}

	return -ENOENT;
}

static int static_gid_to_name(gid_t gid, char *UNUSED(domain), char *name, size_t UNUSED(len))
{
	struct gid_mapping * gm;

	for (gm = LIST_FIRST (&gid_mappings[gid_hash (gid)]); gm;
		gm = LIST_NEXT (gm, link)) {
		if (gm->gid == gid) {
			strcpy(name, gm->principal);
			return 0;
		}
	}

	return -ENOENT;
}

/*
 * We buffer all UID's for which static mappings is defined in advance, so the
 * uid_to_name functions will be fast enough.
 */

static int static_init(void) {	
	int err;
	struct conf_list * princ_list = NULL;
	struct conf_list_node * cln, *next;
	struct uid_mapping * unode;
	struct gid_mapping * gnode;
	unsigned int i;

	//init hash_table first
	for (i = 0; i < sizeof uid_mappings / sizeof uid_mappings[0]; i++)
		LIST_INIT (&uid_mappings[i]);

	if (nfsidmap_conf_path)
		conf_init_file(nfsidmap_conf_path);

	//get all principals for which we have mappings
	princ_list = conf_get_tag_list("Static", NULL);

	if (!princ_list) {
		return -ENOENT;
	}

	/* As we can not distinguish between mappings for users and groups, we try to
	 * resolve all mappings for both cases.
	 */

	//resolve uid of localname account for all such principals and cache it
	for (cln = TAILQ_FIRST (&princ_list->fields); cln; cln = next) 
	{ 
		next = TAILQ_NEXT (cln, link); 

		struct passwd_ints pw_ints = static_getpwnam(cln->field, NULL, NULL);
		err = pw_ints.return_code;
		if (err)
			continue;

		unode = calloc (1, sizeof *unode);
		if (!unode)
		{
			warnx("static_init: calloc (1, %lu) failed",
				(unsigned long)sizeof *unode);
			conf_free_list(princ_list);
			return -ENOMEM;
		}
		unode->uid = pw_ints.uid;
		unode->principal = strdup(cln->field);

		unode->localname = conf_get_str("Static", cln->field);
		if (!unode->localname) {
			free(unode->principal);
			free(unode);
			conf_free_list(princ_list);
			return -ENOENT;
		}

		LIST_INSERT_HEAD (&uid_mappings[uid_hash(unode->uid)], unode, link);
	}

	//resolve gid of localgroup accounts and cache it
	for (cln = TAILQ_FIRST (&princ_list->fields); cln; cln = next) 
	{ 
		next = TAILQ_NEXT (cln, link); 

		struct group_ints grp_ints = static_getgrnam(cln->field, NULL);
		err = grp_ints.return_code;
		if (err)
			continue;
		
		gnode = calloc (1, sizeof *gnode);
		if (!gnode)
		{
			warnx("static_init: calloc (1, %lu) failed",
				(unsigned long)sizeof *gnode);
			conf_free_list(princ_list);
			return -ENOMEM;
		}
		gnode->gid = grp_ints.gid;
		gnode->principal = strdup(cln->field);

		gnode->localgroup = conf_get_str("Static", cln->field);
		if (!gnode->localgroup) {
			free(gnode->principal);
			free(gnode);
			conf_free_list(princ_list);
			return -ENOENT;
		}

		LIST_INSERT_HEAD (&gid_mappings[gid_hash(gnode->gid)], gnode, link);
	}
	
	conf_free_list(princ_list);
	return 0;
}


struct trans_func static_trans = {
	.name			= "static",
	.init			= static_init,
	.name_to_uid		= static_name_to_uid,
	.name_to_gid		= static_name_to_gid,
	.uid_to_name		= static_uid_to_name,
	.gid_to_name		= static_gid_to_name,
	.princ_to_ids		= static_gss_princ_to_ids,
	.gss_princ_to_grouplist	= static_gss_princ_to_grouplist,
};

struct trans_func *libnfsidmap_plugin_init(void)
{
	return (&static_trans);
}

