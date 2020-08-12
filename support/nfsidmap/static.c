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

static void static_print_getpwnam_outcome(
		ssize_t return_code,
		const char *local_user,
		const char *entry_name
	)
{
	if ( return_code == 0 )
		IDMAP_LOG(4, ("static_getpwnam: name '%s' mapped to '%s'",
			entry_name, local_user));
	else
	if ( return_code == ENOENT ) // For compatibility with previously existing error message.
		IDMAP_LOG(0, ("static_getpwnam: localname '%s' for '%s' not found",
			local_user, entry_name));
	else
		nfsidmap_print_pwgrp_error(
			return_code, "static_getpwnam:",
			"local name", local_user,
			" for Static mapping named '", entry_name, "'");
}

static struct nfsutil_passwd_ints
	static_getpwnam( const char *name, const char *UNUSED(domain) )
{
	struct nfsutil_passwd_ints  pw_ints = nfsutil_passwd_ints_init;
	char *localname = conf_get_str("Static", (char *)name);
	if (!localname) {
		// Should this have an error message?  (It didn't have one before.)
		// Something like, for example, "static_getpwnam: user '%s' not found in config (ex: idmapd.conf)"
		// Or is this called speculatively (ex: every plugin/section called
		// with same name, and all but one are expected to return ENOENT)?
		// -- Chad Joan  2020-08-12
		pw_ints.err = ENOENT;
		return pw_ints;
	}

	// Call getpwnam_r.
	do {
		pw_ints = nfsutil_getpwnam_ints(localname);
	}
	while ( pw_ints.err == EINTR );

	static_print_getpwnam_outcome(pw_ints.err, localname, name);
	return pw_ints;
}

static void static_print_getgrnam_outcome(
		ssize_t return_code,
		const char *local_group,
		const char *entry_name
	)
{
	if ( return_code == 0 )
		IDMAP_LOG(4, ("static_getgrnam: group '%s' mapped to '%s'",
			entry_name, local_group));
	else
	if ( return_code == ENOENT ) // For compatibility with previously existing error message.
		IDMAP_LOG(0, ("static_getgrnam: local group '%s' for '%s' not found",
			local_group, entry_name));
	else
		nfsidmap_print_pwgrp_error(
			return_code, "static_getgrnam:",
			"local group", local_group,
			" for Static mapping named '", entry_name, "'");
}

static struct nfsutil_group_ints
	static_getgrnam( const char *name, const char *UNUSED(domain) )
{
	struct nfsutil_group_ints  grp_ints = nfsutil_group_ints_init;
	char *localgroup = conf_get_str("Static", (char *)name);
	if (!localgroup) {
		// Should this have an error message?  (It didn't have one before.)
		// Something like, for example, "static_getgrnam: group '%s' not found in config (ex: idmapd.conf)"
		// Or is this called speculatively (ex: every plugin/section called
		// with same name, and all but one are expected to return ENOENT)?
		// -- Chad Joan  2020-08-12
		grp_ints.err = ENOENT;
		return grp_ints;
	}

	// Call getgrnam_r.
	do {
		grp_ints = nfsutil_getgrnam_ints(localgroup);
	}
	while ( grp_ints.err == EINTR );

	static_print_getgrnam_outcome(grp_ints.err, localgroup, name);
	return grp_ints;
}

static int static_gss_princ_to_ids(char *secname, char *princ,
				   uid_t *uid, uid_t *gid,
				   extra_mapping_params **UNUSED(ex))
{
	/* XXX: Is this necessary? */
	if (strcmp(secname, "krb5") != 0 && strcmp(secname, "spkm3") != 0)
		return -EINVAL;

	struct nfsutil_passwd_ints pw_ints = static_getpwnam(princ, NULL);
	int err = pw_ints.err;

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

	struct nfsutil_passwd_ints pw_ints;
	pw_ints = static_getpwnam(princ, NULL);
	int err = pw_ints.err;

	if (err)
		return -err;

	do {
		err = nfsutil_getgrouplist_by_uid(
			pw_ints.uid, pw_ints.gid, groups, ngroups);
	}
	while ( err == EINTR );

	// Note: The caller should handle ERANGE by calling us again
	//       with a larger `groups` buffer.
	// `nfsidmap_print_pwgrp_error` might not print the right thing for
	// ERANGE anyways, because it's meaning here is pretty specific to
	// getgrouplist's array sizing.
	if ( err != ERANGE )
		nfsidmap_print_pwgrp_error(err, "static_gss_princ_to_grouplist",
			"user name", princ, "", "", "");

	return -err;
}

static int static_name_to_uid(char *name, uid_t *uid)
{
	struct nfsutil_passwd_ints  pw_ints;
	pw_ints = static_getpwnam(name, NULL);
	int err = pw_ints.err;

	if (!err)
		*uid = pw_ints.uid;

	return -err;
}

static int static_name_to_gid(char *name, gid_t *gid)
{
	struct nfsutil_group_ints  grp_ints;
	grp_ints = static_getgrnam(name, NULL);
	int err = grp_ints.err;

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

		struct nfsutil_passwd_ints pw_ints =
			static_getpwnam(cln->field, NULL);
		err = pw_ints.err;
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

		struct nfsutil_group_ints  grp_ints;
		grp_ints = static_getgrnam(cln->field, NULL);
		err = grp_ints.err;
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

