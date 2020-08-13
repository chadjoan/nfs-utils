/*
 *  nss.c
 *
 *  nsswitch idmapping functions.
 *
 *  Copyright (c) 2004 The Regents of the University of Michigan.
 *  All rights reserved.
 *
 *  J. Bruce Fields <bfields@umich.edu>
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

#include <sys/types.h>
#include <errno.h>
#include <unistd.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <pwd.h>
#include <grp.h>
#include <netdb.h>
#include <err.h>
#include <grp.h>
#include <limits.h>
#include <ctype.h>
#include "nfsidmap.h"
#include "nfsidmap_plugin.h"
#include "nfsidmap_private.h"
#include "passwd_query.h"
#include <syslog.h>

static char *get_default_domain(void)
{
	static char default_domain[NFS4_MAX_DOMAIN_LEN] = "";
	if (default_domain[0] == 0) {
		nfs4_get_default_domain(NULL, default_domain, NFS4_MAX_DOMAIN_LEN);
	}
	return default_domain;
}

/*
 * NSS Translation Methods
 *
 * These are all just wrappers around getpwnam and friends;
 * we tack on the given domain to the results of getpwnam when looking up a uid,
 * and ignore the domain entirely when looking up a name.
 */

static int write_name(char *dest, char *localname, char *domain, size_t len,
		      int doappend)
{
	if (doappend || !strchr(localname,'@')) {
		if (strlen(localname) + 1 + strlen(domain) + 1 > len)
			return ENOMEM; /* XXX: Is there an ETOOLONG? */
		strcpy(dest, localname);
		strcat(dest, "@");
		strcat(dest, domain);
	} else {
		if (strlen(localname) + 1 > len)
			return ENOMEM;
		strcpy(dest, localname);
	}
	return 0;
}

static int nss_uid_to_name(uid_t uid, char *domain, char *name, size_t len)
{
	char    bufptr[PASSWD_STACKMEM_SIZE_HINT];
	size_t  buflen = PASSWD_STACKMEM_SIZE_HINT;
	struct  nfsutil_passwd_query  passwd_query;
	struct  passwd                *pw = NULL;

	// Slurp up those starter buffers.
	nfsutil_pw_query_init(&passwd_query, bufptr, buflen);

	// Query the `passwd` database for the user name.
	int err;
	do {
		err = nfsutil_pw_query_call_getpwuid_r(&passwd_query, uid);
	}
	while ( err == EINTR );
	pw = nfsutil_pw_query_result(&passwd_query);

	// Identify ENOENT to make `nfsidmap_print_pwgrp_error` print that outcome
	// and to ensure that (err == 0) implies (pw != NULL).
	if ( err == 0 && pw == NULL )
		err = ENOENT;

	// Ensure that we have SOME domain string.
	// This will be used for either error printing or for writing our results.
	if (domain == NULL)
		domain = get_default_domain();

	// Print any errors.
	if ( err )
	{
		char uidstr[24];
		(void)snprintf(uidstr, 24, "%d", uid);
		nfsidmap_print_pwgrp_error(err, "nss_uid_to_name",
			"user with UID", uidstr, " in domain '", domain, "'");
	}
	else // (err == 0) -> (pw != NULL)
	{
		// success; Write the name found into the caller's buffer.
		if (get_nostrip() & IDTYPE_USER)
			err = write_name(name, pw->pw_name, domain, len, 0);
		else
			err = write_name(name, pw->pw_name, domain, len, 1);
	}

	// It is always safe to call the cleanup function as long as we're done
	// with the query object.
	nfsutil_pw_query_cleanup(&passwd_query);

	return -err;
}

static int nss_gid_to_name(gid_t gid, char *domain, char *name, size_t len)
{
	char    bufptr[GROUP_STACKMEM_SIZE_HINT];
	size_t  buflen = GROUP_STACKMEM_SIZE_HINT;
	struct  nfsutil_group_query  group_query;
	struct  group                *grp = NULL;

	// Slurp up those starter buffers.
	nfsutil_grp_query_init(&group_query, bufptr, buflen);

	// Query the `group` database for the group name.
	int err;
	do {
		err = nfsutil_grp_query_call_getgrgid_r(&group_query, gid);
	}
	while ( err == EINTR );
	grp = nfsutil_grp_query_result(&group_query);

	// Identify ENOENT to make `nfsidmap_print_pwgrp_error` print that outcome
	// and to ensure that (err == 0) implies (grp != NULL).
	if ( err == 0 && grp == NULL )
		err = ENOENT;

	// Ensure that we have SOME domain string.
	// This will be used for either error printing or for writing our results.
	if (domain == NULL)
		domain = get_default_domain();

	// Print any errors.
	if ( err )
	{
		char gidstr[24];
		(void)snprintf(gidstr, 24, "%d", gid);
		nfsidmap_print_pwgrp_error(err, "nss_gid_to_name",
			"group with GID", gidstr, " in domain '", domain, "'");
	}
	else // (err == 0) -> (grp != NULL)
	{
		// success; Write the name found into the caller's buffer.
		if (get_nostrip() & IDTYPE_GROUP)
			err = write_name(name, grp->gr_name, domain, len, 0);
		else
			err = write_name(name, grp->gr_name, domain, len, 1);
	}

	// It is always safe to call the cleanup function as long as we're done
	// with the query object.
	nfsutil_grp_query_cleanup(&group_query);

	return -err;
}

/* XXX: actually should return error, so can distinguish between
 * memory allocation failure and failure to match domain */
static char *strip_domain(const char *name, const char *domain)
{
	const char *c;
	char *l = NULL;
	int len;

	if (name == NULL)
		goto out;

	c = strrchr(name, '@');
	if (c == NULL && domain != NULL)
		goto out;
	if (c == NULL && domain == NULL) {
		len = strlen(name) + 1;
	} else {
		if (domain && strcasecmp(c + 1, domain) != 0)
			goto out;
		len = c - name;
	}

	l = malloc(len + 1);
	if (l == NULL)
		goto out;
	memcpy(l, name, len);
	l[len] = '\0';
out:
	return l;
}

static struct nfsutil_passwd_ints
	nss_getpwnam(const char *name, const char *domain, int dostrip)
{
	struct nfsutil_passwd_ints  pw_ints = nfsutil_passwd_ints_init;

	if (dostrip) {
		// Attempt domain stripping.
		char *localname = strip_domain(name, domain);
		IDMAP_LOG(4, ("nss_getpwnam: name '%s' domain '%s': "
			  "resulting localname '%s'", name, domain, localname));
		if (localname == NULL) {
			IDMAP_LOG(0, ("nss_getpwnam: name '%s' does not map "
				"into domain '%s'", name,
				domain ? domain : "<not-provided>"));
			pw_ints.err = EINVAL;
			return pw_ints;
		}

		// Do the `getpwnam` lookup to get the uid+gid for this
		// local user name from the `passwd` database.
		do {
			pw_ints = nfsutil_getpwnam_ints(localname);
		}
		while ( pw_ints.err == EINTR );

		// Print any error messages.
		int err = pw_ints.err;
		if ( err == ENOENT && domain != NULL )
			IDMAP_LOG(1,
				("nss_getpwnam: name '%s' not found in domain '%s'",
					localname, domain));
		else
		if ( err && domain != NULL )
			nfsidmap_print_pwgrp_error(err, "nss_getpwnam",
				"name", localname, " in domain '", domain, "'");
		else
		if ( err )
			nfsidmap_print_pwgrp_error(err, "nss_getpwnam",
				"name", localname, "", "", "");

		// Cleanup.
		free(localname);
	} else {

		// If there's no stripping to do, we can directly engage in
		// looking up the uid+gid from the `passwd` database.
		do {
			pw_ints = nfsutil_getpwnam_ints(name);
		}
		while ( pw_ints.err == EINTR );

		// Print any error messages.
		int err = pw_ints.err;
		if ( err == ENOENT )
			IDMAP_LOG(1,
				("nss_getpwnam: name '%s' not found (domain not stripped)", name));
		else
			nfsidmap_print_pwgrp_error(err, "nss_getpwnam",
				"name", name, " (domain not stripped) ", "", "");
	}

	return pw_ints;
}


static int nss_name_to_uid(char *name, uid_t *uid)
{
	struct nfsutil_passwd_ints  pw_ints;

	char *domain = get_default_domain();
	if (get_nostrip() & IDTYPE_USER) {
		pw_ints = nss_getpwnam(name, domain, 0);
		if ( pw_ints.err )
			pw_ints = nss_getpwnam(name, domain, 1);
	}
	else
		pw_ints = nss_getpwnam(name, domain, 1);

	int err = pw_ints.err;
	if ( err )
		return -err;

	*uid = pw_ints.uid;
	IDMAP_LOG(4, ("nss_name_to_uid: name '%s' uid %u", name, *uid));
	return 0;
}

static char *reformat_name(const char *name)
{
	const char *domain;
	const char *c;
	const char *d;
	char *l = NULL;
	int len;
	int dlen = 0;
	int i;

	c = strchr(name, '@');
	if (c == NULL)
		goto out;
	len = c - name;
	domain = ++c;
	d = strchr(domain, '.');
	if (d == NULL)
		goto out;
	dlen = d - domain;
	l = malloc(dlen + 1 + len + 1);
	if (l == NULL)
		goto out;
	for (i = 0; i < dlen; i++)
		l[i] = toupper(domain[i]);
	l[dlen] = '\\';
	memcpy(l + dlen + 1, name, len);
	l[dlen + 1 + len] = '\0';
out:
	return l;
}

static int nss_name_to_gid_inner_02(
	char *name, gid_t *gid, char **localname, char **ref_name, int dostrip)
{
	// Perform any domain stripping or reformatting.
	char *domain = get_default_domain();
	if (dostrip) {
		*localname = strip_domain(name, domain);
		IDMAP_LOG(4, ("nss_name_to_gid: name '%s' domain '%s': "
			"resulting localname '%s'", name, domain, *localname));
		if (!*localname) {
			IDMAP_LOG(0, ("nss_name_to_gid: name '%s' does not map "
				"into domain '%s'", name, domain));
			return -EINVAL;
		}
	} else if (get_reformat_group()) {
		*ref_name = reformat_name(name);
		if (*ref_name == NULL) {
			IDMAP_LOG(1, ("nss_name_to_gid: failed to reformat name '%s'",
				name));
			return -ENOENT;
		}
	}

	// The above yielded one of three possible names.
	// Pick the one that we will use for querying the `group` database.
	const char *lookup_name;
	if (dostrip)
		lookup_name = *localname;
	else if (get_reformat_group())
		lookup_name = *ref_name;
	else
		lookup_name = name;

	// Query the `group` database to get the group's gid.
	struct nfsutil_group_ints  grp_ints;
	do {
		grp_ints = nfsutil_getgrnam_ints(lookup_name);
	}
	while ( grp_ints.err == EINTR );

	// Print any error messages.
	int err = grp_ints.err;
	if (err == ENOENT) {
		// These error messages existed before `nfsidmap_print_pwgrp_error`
		// was written and were left as-is to minimize unnecessary changes.
		if (dostrip)
			IDMAP_LOG(1, ("nss_name_to_gid: name '%s' not found "
				  "in domain '%s'", *localname, domain));
		else if (get_reformat_group())
			IDMAP_LOG(1, ("nss_name_to_gid: name '%s' not found "
				  "(reformatted)", *ref_name));
		else
			IDMAP_LOG(1, ("nss_name_to_gid: name '%s' not found "
				  "(domain not stripped)", name));
	}
	else
	if ( err ) {
		// `nfsidmap_print_pwgrp_error` can handle all possible errors that
		// arise from querying the `group` database, so it will handle
		// anything that wasn't already checked in this function.
		if (dostrip)
			nfsidmap_print_pwgrp_error(err, "nss_name_to_gid",
				"name", *localname, " in domain '", domain, "'");
		else if (get_reformat_group())
			nfsidmap_print_pwgrp_error(err, "nss_name_to_gid",
				"name", *ref_name, " (reformatted) ", "", "");
		else
			nfsidmap_print_pwgrp_error(err, "nss_name_to_gid",
				"name", name, " (domain not stripped) ", "", "");
	}

	if (err)
		return -err;

	*gid = grp_ints.gid;
	IDMAP_LOG(4, ("nss_name_to_gid: name '%s' gid %u", name, *gid));
	return 0;
}

static int nss_name_to_gid_inner_01(char *name, gid_t *gid, int dostrip)
{
	// This intermediate function guarantees
	// that local_name and ref_name are free'd after use.
	char *local_name = NULL;
	char *ref_name   = NULL;

	int err = nss_name_to_gid_inner_02(name, gid, &local_name, &ref_name, dostrip);

	if ( local_name )
		free(local_name);
	if ( ref_name )
		free(ref_name);

	return err;
}


static int nss_name_to_gid(char *name, gid_t *gid)
{
	int err = 0;

	if (get_nostrip() & IDTYPE_GROUP) {
		err = nss_name_to_gid_inner_01(name, gid, 0);
		if (!err)
			goto out;
	}
	err = nss_name_to_gid_inner_01(name, gid, 1);
out:
	return err;
}

static int nss_gss_princ_to_ids(char *secname, char *princ,
				uid_t *uid, uid_t *gid,
				extra_mapping_params **UNUSED(ex))
{
	char *princ_realm;
	struct conf_list *realms;
	struct conf_list_node *r;
	int found = 0;

	if (strcmp(secname, "spkm3") == 0)
		return -ENOENT;

	if (strcmp(secname, "krb5") != 0)
		return -EINVAL;

	/* get princ's realm */
	princ_realm = strstr(princ, "@");
	if (princ_realm == NULL)
		return -EINVAL;
	princ_realm++;

	/* get list of "local-equivalent" realms and
	 * check against the principal's realm */
	realms = get_local_realms();
	TAILQ_FOREACH(r, &realms->fields, link) {
		if (strcmp(r->field, princ_realm) == 0) {
			found = 1;
			break;
		}
	}
	if (!found) {
		IDMAP_LOG(1, ("nss_gss_princ_to_ids: Local-Realm '%s': NOT FOUND", 
			princ_realm));
		return -ENOENT;
	}
	/* XXX: this should call something like getgssauthnam instead? */
	struct nfsutil_passwd_ints  pw_ints;
	pw_ints = nss_getpwnam(princ, NULL, 1);

	if (!pw_ints.err) {
		*uid = pw_ints.uid;
		*gid = pw_ints.gid;
	}

	return -pw_ints.err;
}

static int nss_gss_princ_to_grouplist(char *secname, char *princ,
			       gid_t *groups, int *ngroups,
			       extra_mapping_params **UNUSED(ex))
{
	if (strcmp(secname, "krb5") != 0)
		return -EINVAL;
	/* XXX: not quite right?  Need to know default realm? */
	/* XXX: this should call something like getgssauthnam instead? */
	struct nfsutil_passwd_ints  pw_ints;
	pw_ints = nss_getpwnam(princ, NULL, 1);
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
		nfsidmap_print_pwgrp_error(err, "nss_gss_princ_to_grouplist",
			"user name", princ, "", "", "");

	return -err;
}

static int nss_plugin_init(void)
{
	if (nfsidmap_conf_path)
		conf_init_file(nfsidmap_conf_path);
	return 0;
}

/*
 * Called by dlclose(). See dlopen(3) man page
 */
__attribute__((destructor))
static int nss_plugin_term(void)
{
	free_local_realms();
	conf_cleanup();
	return 0;
}


struct trans_func nss_trans = {
	.name		= "nsswitch",
	.init		= nss_plugin_init,
	.princ_to_ids	= nss_gss_princ_to_ids,
	.name_to_uid	= nss_name_to_uid,
	.name_to_gid	= nss_name_to_gid,
	.uid_to_name	= nss_uid_to_name,
	.gid_to_name	= nss_gid_to_name,
	.gss_princ_to_grouplist = nss_gss_princ_to_grouplist,
};

struct trans_func *libnfsidmap_plugin_init(void)
{
	return (&nss_trans);
}
