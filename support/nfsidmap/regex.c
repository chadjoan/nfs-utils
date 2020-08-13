/*
 *  regex.c
 *
 *  regex idmapping functions.
 *
 *  Copyright (c) 2017-2020 Stefan Walter <stefan.walter@inf.ethz.ch>.
 *  Copyright (c) 2008 David H?rdeman <david@hardeman.nu>.
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
#include <stdio.h>  // For snprintf.
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <pwd.h>
#include <grp.h>
#include <errno.h>
#include <err.h>
#include <regex.h>

#include "nfsidmap.h"
#include "nfsidmap_plugin.h"
#include "passwd_query.h"

#define CONFIG_GET_STRING nfsidmap_config_get
extern const char *nfsidmap_config_get(const char *, const char *);

#define MAX_MATCHES 100

regex_t group_re;
regex_t user_re;
regex_t gpx_re;
int use_gpx;
const char * group_prefix;
const char * group_name_prefix;
const char * group_suffix;
const char * user_prefix;
const char * user_suffix;
const char * group_map_file;
const char * group_map_section;
char empty = '\0';
size_t group_name_prefix_length;

static char *get_default_domain(void)
{
        static char default_domain[NFS4_MAX_DOMAIN_LEN] = "";
        if (default_domain[0] == 0) {
                nfs4_get_default_domain(NULL, default_domain, NFS4_MAX_DOMAIN_LEN);
        }
        return default_domain;
}

/*
 * Regexp Translation Methods
 *
 */

// Forward declaring this so that the whole algorithm can read top-to-bottom.
static struct nfsutil_passwd_ints
	regex_getpwnam_inner(
		const char *name,
		const char *UNUSED(domain),
		const char *localname
	);

// ----- regex_getpwnam -----
static struct nfsutil_passwd_ints
	regex_getpwnam( const char *name, const char *UNUSED(domain) )
{
	struct nfsutil_passwd_ints  pw_ints = nfsutil_passwd_ints_init;
	regmatch_t matches[MAX_MATCHES];

	// Execute the regular expression.
	int status = regexec(&user_re, name, MAX_MATCHES, matches, 0);
	if (status) {
		IDMAP_LOG(4, ("regexp_getpwnam: user '%s' did not match regex", name));
		pw_ints.err = ENOENT;
		return pw_ints;
	}

	// Scan the resulting matches for a hit.
	size_t index;
	for (index = 1; index < MAX_MATCHES ; index++)
	{
		if (matches[index].rm_so >= 0)
			break;
	}

	if (index == MAX_MATCHES) {
		IDMAP_LOG(4, ("regexp_getpwnam: user '%s' did not match regex", name));
		pw_ints.err = ENOENT;
		return pw_ints;
	}

	// Extract the substring's position/length from the match.
	size_t namelen = matches[index].rm_eo - matches[index].rm_so;
	const char *localname_start = name+matches[index].rm_so;

	// Allocate memory for the `localname` string.
	char buf[128];
	char *localname = buf;
	if ( sizeof(buf) < namelen+1 ) {
		localname = malloc(namelen+1);
		if ( localname == NULL ) {
			pw_ints.err = ENOMEM;
			nfsidmap_print_pwgrp_error(pw_ints.err, "regex_getpwnam",
				"user", name, "", "", "");
			return pw_ints;
		}
	}

	// Copy the substring matched by the regex into the `localname` string.
	strncpy(localname, localname_start, namelen);
	localname[namelen] = '\0';

	// Delegate the rest of the job to a separate function.
	// This separates the regex match retrieval logic from the `passwd`
	// database querying logic, and also allows us to keep our deallocation
	// deduplicated and close to our initialization.
	pw_ints = regex_getpwnam_inner(name, NULL, localname);

	// Cleanup.
	if ( localname != buf )
		free(localname);

	// Done.
	return pw_ints;
}

// ----- inner -----
static struct nfsutil_passwd_ints
	regex_getpwnam_inner(
		const char *name,
		const char *UNUSED(domain),
		const char *localname
	)
{
	// Do the lookup in the system's `passwd` database.
	struct nfsutil_passwd_ints  pw_ints;
	do {
		pw_ints = nfsutil_getpwnam_ints(localname);
	}
	while ( pw_ints.err == EINTR );

	// Print/log any errors.
	int err = pw_ints.err;
	if ( err == ENOENT ) // For compatibility with previously existing error message.
		IDMAP_LOG(4, ("regex_getpwnam: local user '%s' for '%s' not found",
		  localname, name));
	else
	if ( err != 0 )
		nfsidmap_print_pwgrp_error(err, "regex_getpwnam",
			"local user", localname, " for '", name, "'");
	else {
		// success
		IDMAP_LOG(4, ("regexp_getpwnam: name '%s' mapped to '%s'",
			name, localname));
	}

	// Done.
	return pw_ints;
}

// Forward declaring this so that the whole algorithm can read top-to-bottom.
static struct nfsutil_group_ints
	regex_getgrnam_inner(
		const char *name,
		const char *UNUSED(domain),
		const char *localgroup
	);

// ----- regex_getgrnam -----
static struct nfsutil_group_ints
	regex_getgrnam( const char *name, const char *UNUSED(domain) )
{
	struct nfsutil_group_ints  grp_ints = nfsutil_group_ints_init;
	regmatch_t matches[MAX_MATCHES];

	// Execute the regular expression.
	int status = regexec(&group_re, name, MAX_MATCHES, matches, 0);
	if (status) {
		IDMAP_LOG(4, ("regexp_getgrnam: group '%s' did not match regex", name));
		grp_ints.err = ENOENT;
		return grp_ints;
	}

	// Scan the resulting matches for a hit.
	size_t index;
	for (index = 1; index < MAX_MATCHES ; index++)
	{
		if (matches[index].rm_so >= 0)
			break;
	}

	if (index == MAX_MATCHES) {
		IDMAP_LOG(4, ("regexp_getgrnam: group '%s' did not match regex", name));
		grp_ints.err = ENOENT;
		return grp_ints;
	}

	// Extract the substring's position/length from the match.
	size_t namelen = matches[index].rm_eo - matches[index].rm_so;
	const char *localgroup_start = name+matches[index].rm_so;

	// Allocate memory for the `localgroup` string.
	char buf[128];
	char *localgroup = buf;
	if ( sizeof(buf) < namelen+1 ) {
		localgroup = malloc(namelen+1);
		if ( localgroup == NULL ) {
			grp_ints.err = ENOMEM;
			nfsidmap_print_pwgrp_error(grp_ints.err, "regex_getgrnam",
				"group", name, "", "", "");
			return grp_ints;
		}
	}

	// Copy the substring matched by the regex into the `localgroup` string.
	strncpy(localgroup, localgroup_start, namelen);
	localgroup[namelen] = '\0';

	// Delegate the rest of the job to a separate function.
	// This separates the regex match retrieval logic from the `group`
	// database querying logic, and also allows us to keep our deallocation
	// deduplicated and close to our initialization.
	grp_ints = regex_getgrnam_inner(name, NULL, localgroup);

	// Cleanup.
	if ( localgroup != buf )
		free(localgroup);

	// Done.
	return grp_ints;
}

// ----- inner -----
static struct nfsutil_group_ints
	regex_getgrnam_inner(
		const char *name,
		const char *UNUSED(domain),
		const char *localgroup
	)
{
	IDMAP_LOG(4, ("regexp_getgrnam: group '%s' after match of regex", localgroup));

	// Check the name against the group prefix exclusion regex.
	// If it matches, then remove the prefix.
	int err;
	const char *groupname = localgroup;
	if (group_name_prefix_length && ! strncmp(group_name_prefix, localgroup, group_name_prefix_length))
	{
		err = 1;
		if (use_gpx)
			err = regexec(&gpx_re, localgroup, 0, NULL, 0);

		if (err)
		{
			IDMAP_LOG(4, ("regexp_getgrnam: removing prefix '%s' (%d long) from group '%s'",
				group_name_prefix, group_name_prefix_length, localgroup));
			groupname += group_name_prefix_length;
		}
		else
		{
			IDMAP_LOG(4, ("regexp_getgrnam: not removing prefix from group '%s'", localgroup));
		}
	}

	// Now we have the group name that we want to look up in the `group` database.
	IDMAP_LOG(4, ("regexp_getgrnam: will use '%s'", groupname));

	// Do the lookup in the `group` database.
	struct nfsutil_group_ints  grp_ints;
	do {
		grp_ints = nfsutil_getgrnam_ints(groupname);
	}
	while( grp_ints.err == EINTR );

	// Print/log any errors.
	err = grp_ints.err;
	if ( err == ENOENT ) // For compatibility with previously existing error message.
		IDMAP_LOG(4, ("regex_getgrnam: local group '%s' for '%s' not found", groupname, name));
	else
	if ( err != 0 )
		nfsidmap_print_pwgrp_error(err, "regex_getgrnam",
			"local group", groupname, " for '", name, "'");
	else {
		// success
		IDMAP_LOG(4, ("regex_getgrnam: group '%s' mapped to '%s'", name, groupname));
	}

	// Done.
	return grp_ints;
}

static int regex_gss_princ_to_ids(char *secname, char *princ,
				   uid_t *uid, uid_t *gid,
				   extra_mapping_params **UNUSED(ex))
{
	/* XXX: Is this necessary? */
	if (strcmp(secname, "krb5") != 0 && strcmp(secname, "spkm3") != 0)
		return -EINVAL;

	struct nfsutil_passwd_ints  pw_ints;
	pw_ints = regex_getpwnam(princ, NULL);

	int err = pw_ints.err;
	if (!err) {
		*uid = pw_ints.uid;
		*gid = pw_ints.gid;
	}

	return -err;
}

static int regex_gss_princ_to_grouplist(char *secname, char *princ,
					 gid_t *groups, int *ngroups,
					 extra_mapping_params **UNUSED(ex))
{
	/* XXX: Is this necessary? */
	if (strcmp(secname, "krb5") != 0 && strcmp(secname, "spkm3") != 0)
		return -EINVAL;

	struct nfsutil_passwd_ints pw_ints = regex_getpwnam(princ, NULL);
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
		nfsidmap_print_pwgrp_error(err, "regex_gss_princ_to_grouplist",
			"user name", princ, "", "", "");

	return -err;
}

static int regex_name_to_uid(char *name, uid_t *uid)
{
	struct nfsutil_passwd_ints  pw_ints;
	pw_ints = regex_getpwnam(name, NULL);

	int err = pw_ints.err;
	if (!err)
		*uid = pw_ints.uid;

	return -err;
}

static int regex_name_to_gid(char *name, gid_t *gid)
{
	struct nfsutil_group_ints  grp_ints;
	grp_ints = regex_getgrnam(name, NULL);

	int err = grp_ints.err;
	if (!err)
		*gid = grp_ints.gid;

	return -err;
}

static int write_name(char *dest, char *localname, const char* name_prefix, const char *prefix, const char *suffix, size_t len)
{
	if (strlen(localname) + strlen(name_prefix) + strlen(prefix) + strlen(suffix) + 1 > len) {
		return -ENOMEM; /* XXX: Is there an -ETOOLONG? */
	}
	strcpy(dest, prefix);
	strcat(dest, name_prefix);
	strcat(dest, localname);
	strcat(dest, suffix);

   	IDMAP_LOG(4, ("write_name: will use '%s'", dest));

	return 0;
}

static int regex_uid_to_name(uid_t uid, char *domain, char *name, size_t len)
{
	char    bufptr[PASSWD_STACKMEM_SIZE_HINT];
	size_t  buflen = PASSWD_STACKMEM_SIZE_HINT;
	struct  nfsutil_passwd_query  passwd_query;
	struct  passwd                *pw = NULL;

	// BUG: This statement had no effect originally.
	// (Now I'm using it for printing the error message, but that could still be wrong.)
	// Is `domain` supposed to be unused, or is this supposed to be strcpy'ed
	// to fill the caller's buffer for that string? If so, what's that buffer's length?
	// -- Chad Joan  2020-08-12
	if (domain == NULL)
		domain = get_default_domain();

	// Slurp up those starter buffers.
	nfsutil_pw_query_init(&passwd_query, bufptr, buflen);

	// Query the system's `passwd` database for the user name.
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

	// Print any errors.
	if ( err )
	{
		const char *domain_pre = " in domain '";
		const char *domain_post = "'";
		if ( !domain || domain[0] == '\0' ) {
			domain_pre = "";
			domain = "";
			domain_post = "";
		}

		char uidstr[24];
		(void)snprintf(uidstr, 24, "%d", uid);
		nfsidmap_print_pwgrp_error(err, "regex_uid_to_name",
			"user with UID", uidstr, domain_pre, domain, domain_post);
	}
	else // (err == 0) -> (pw != NULL)
	{
		// success; Write the name found into the caller's buffer.
		err = write_name(name, pw->pw_name, &empty, user_prefix, user_suffix, len);
	}

	// It is always safe to call the cleanup function as long as we're done
	// with the query object.
	nfsutil_pw_query_cleanup(&passwd_query);

	return -err;
}

static int regex_gid_to_name(gid_t gid, char *UNUSED(domain), char *name, size_t len)
{
	char    bufptr[GROUP_STACKMEM_SIZE_HINT];
	size_t  buflen = GROUP_STACKMEM_SIZE_HINT;
	struct  nfsutil_group_query  group_query;
	struct  group                *grp = NULL;

	// Slurp up those starter buffers.
	nfsutil_grp_query_init(&group_query, bufptr, buflen);

	// Query the system's `group` database for the group name.
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

	// Print any errors.
	if ( err )
	{
		char gidstr[24];
		(void)snprintf(gidstr, 24, "%d", gid);
		nfsidmap_print_pwgrp_error(err, "regex_gid_to_name",
			"group with GID", gidstr, "", "", "");
	}
	else // (err == 0) -> (grp != NULL)
	{
		// success

		// Next, add a group_name_prefix if the regex matches.
		char       *groupname   = grp->gr_name;
		const char *name_prefix = group_name_prefix;
    	if (group_name_prefix_length)
		{
			if(! strncmp(group_name_prefix, groupname, group_name_prefix_length))
			{
				name_prefix = &empty;
			}
			else if (use_gpx)
			{
				err = regexec(&gpx_re, groupname, 0, NULL, 0);
				if (!err)
				{
					IDMAP_LOG(4, ("regex_gid_to_name: not adding prefix to group '%s'", groupname));
					name_prefix = &empty;
				}
			}
		}

		// Write the name found into the caller's buffer.
		err = write_name(name, groupname, name_prefix, group_prefix, group_suffix, len);
	}

	// It is always safe to call the cleanup function as long as we're done
	// with the query object.
	nfsutil_grp_query_cleanup(&group_query);

	return -err;
}

static int regex_init(void) {	
	const char *string;
	int status;


        string = CONFIG_GET_STRING("Regex", "User-Regex");
	if (!string)
	{
		warnx("regex_init: regex for user mapping missing");
		goto error1;
	}
    
	status = regcomp(&user_re, string, REG_EXTENDED|REG_ICASE); 
	if (status)
	{
		warnx("regex_init: compiling regex for user mapping failed with status %u", status);
		goto error1;
	}

	string = CONFIG_GET_STRING("Regex", "Group-Regex");
	if (!string)
	{
		warnx("regex_init: regex for group mapping missing");
		goto error2;
	}
    
    status = regcomp(&group_re, string, REG_EXTENDED|REG_ICASE); 
    if (status)
    {
		warnx("regex_init: compiling regex for group mapping failed with status %u", status);
		goto error2;
    }

	group_name_prefix = CONFIG_GET_STRING("Regex", "Group-Name-Prefix");
    if (!group_name_prefix)
    {
        group_name_prefix = &empty;
    }
    group_name_prefix_length = strlen(group_name_prefix);

    user_prefix = CONFIG_GET_STRING("Regex", "Prepend-Before-User");
    if (!user_prefix)
    {
        user_prefix = &empty;
    }

    user_suffix = CONFIG_GET_STRING("Regex", "Append-After-User"); 
    if (!user_suffix)
    {
        user_suffix = &empty;
    }

    group_prefix = CONFIG_GET_STRING("Regex", "Prepend-Before-Group"); 
    if (!group_prefix)
    {
        group_prefix = &empty;
    }

    group_suffix = CONFIG_GET_STRING("Regex", "Append-After-Group"); 
    if (!group_suffix)
    {
        group_suffix = &empty;
    }

    string = CONFIG_GET_STRING("Regex", "Group-Name-No-Prefix-Regex");
    use_gpx = 0;
    if (string)
    {
        status = regcomp(&gpx_re, string, REG_EXTENDED|REG_ICASE); 

        if (status)
        {
	    	warnx("regex_init: compiling regex for group prefix exclusion failed with status %u", status);
		    goto error3;
        }

        use_gpx = 1;
    }

    return 0;

error3:
	regfree(&group_re);
error2:
	regfree(&user_re);
error1:
	return 0;
 /* return -EINVAL; */
}


struct trans_func regex_trans = {
	.name			= "regex",
	.init			= regex_init,
	.name_to_uid		= regex_name_to_uid,
	.name_to_gid		= regex_name_to_gid,
	.uid_to_name		= regex_uid_to_name,
	.gid_to_name		= regex_gid_to_name,
	.princ_to_ids		= regex_gss_princ_to_ids,
	.gss_princ_to_grouplist	= regex_gss_princ_to_grouplist,
};

struct trans_func *libnfsidmap_plugin_init()
{
	return (&regex_trans);
}

