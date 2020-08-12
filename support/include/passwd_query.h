/*
 *  passwd_query.h
 *
 *  Types and functions that improve upon standard passwd and group
 *  retrieval functions such as getpwnam_r and getgrnam_r.
 *
 *  Copyright (c) 2020 Chad Joan <chadjoan@gmail.com>
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

#ifndef PASSWD_QUERY_H
#define PASSWD_QUERY_H

#include <grp.h>
#include <pwd.h>
#include <stddef.h>
#include <stdint.h>
#include <sys/types.h>

// The STACKMEM_SIZE_HINT definitions should be large enough to store
// the `buf_query_realloc_loop` object (privately declared in the .c file),
// any passwd/group struct, and also have some reasonable amount of space
// left over (~1024 bytes) to give to the `getpw***_r` and `getgr***_r`
// functions for scratch space and string returns.

/// The recommended number of bytes to stack-allocate and provide to
/// `nfsutil_pw_query_init` when using its `optional_stack_memory` and
/// `stack_memory_size` parameters.
#define PASSWD_STACKMEM_SIZE_HINT (1024)


/// The recommended number of bytes to stack-allocate and provide to
/// `nfsutil_grp_query_init` when using its `optional_stack_memory` and
/// `stack_memory_size` parameters.
#define GROUP_STACKMEM_SIZE_HINT  (1024)

/// The `PWGRP_KEYTYPE_*` definitions are used to describe the type of
/// lookup performed to any functions accepting a stringized key.
#define PWGRP_KEYTYPE_USERNAME   (1)
#define PWGRP_KEYTYPE_UID        (2) /// ditto
#define PWGRP_KEYTYPE_GROUPNAME  (3) /// ditto
#define PWGRP_KEYTYPE_GID        (4) /// ditto

/// The integer type for `PWGRP_KEYTYPE` constants.
#define pwgrp_keytype_t          int8_t

/// This object stores return values and memory management state used
/// by the functions in this module that wrap the `getpwnam_r` and
/// `getpwuid_r` functions.
struct nfsutil_passwd_query { void  *internals; };

/// This object stores return values and memory management state used
/// by the functions in this module that wrap the `getgrnam_r` and
/// `getgrgid_r` functions.
struct nfsutil_group_query { void  *internals; };


/// The `nfsutil_pw_query_init` function prepares a `struct nfsutil_passwd_query`
/// variable for use and ensures that it has predictable contents.
///
/// This function must be called before any other `nfsutil_pw_query_*` functions
/// are called on the given `struct nfsutil_passwd_query`.
///
/// The `optional_stack_memory` and `stack_memory_size` parameters allow
/// the caller to provide stack-allocated memory for the query to use.
/// This should allow the query to avoid using `malloc` in most cases,
/// though this is not a guarantee, because the `passwd` table (file) may
/// have long entries that force a dynamic allocation, or the underlying
/// libc implementation may call arbitrary memory allocation routines such
/// as `malloc` and `realloc`.
///
/// To opt-out of using the `optional_stack_memory` and `stack_memory_size`
/// parameters, pass the arguments `NULL` and `0`, respectively. This will
/// cause subsequent `nfsutil_pw_query_*` functions to lazily allocate memory
/// using `malloc` or `realloc`.
///
/// Usage example:
///
/// static const char *null_alt(const char *str, const char *alt)
/// {
///     if ( str != NULL )
///         return str;
///     else
///         return alt;
/// }
///
/// static void example_print_passwd(const char *login_name)
/// {
///     char    bufptr[PASSWD_STACKMEM_SIZE_HINT];
///     size_t  buflen = PASSWD_STACKMEM_SIZE_HINT;
///     struct  nfsutil_passwd_query  passwd_query;
///     int     err = -1;
///
///     nfsutil_pw_query_init(&passwd_query, bufptr, buflen);
///
///     while ( err != 0 )
///     {
///         err = nfsutil_pw_query_call_getpwnam_r(&passwd_query, login_name);
///         if ( err == EINTR )
///             continue;
///         else
///         if ( err == ENOMEM ) {
///             printf("Out of memory error while attempting to retrieve passwd entry for user %s\n",
///                 login_name);
///             nfsutil_pw_query_cleanup(&passwd_query);
///             return;
///         }
///         else
///         if ( err == EIO ) {
///             printf("I/O error during getpwnam_r: %s\n", strerror(err));
///             nfsutil_pw_query_cleanup(&passwd_query);
///             return;
///         }
///         else
///         //... etc ...
///         if ( err != 0 )
///         {
///             printf("Unhandled error from getpwnam_r: %s\n", strerror(err));
///             nfsutil_pw_query_cleanup(&passwd_query);
///             return;
///         }
///     }
///
///     struct passwd  *pw;
///     pw = nfsutil_pw_query_result(&passwd_query);
///     if ( pw == NULL )
///         printf("passwd entry not found for user '%s'\n", login_name);
///     else
///     {
///         // ... do things with `pw` ...
///         printf("passwd entry for '%s':\n", login_name);
///         printf("  name:  %s\n", null_alt(pw->pw_name, "<NULL>"));
///         printf("  uid:   %d\n", pw->pw_uid);
///         printf("  gid:   %d\n", pw->pw_gid);
///         printf("  dir:   %s\n", null_alt(pw->pw_dir, "<NULL>"));
///         printf("  shell: %s\n", null_alt(pw->pw_shell, "<NULL>"));
///     }
///
///     nfsutil_pw_query_cleanup(&passwd_query);
///     // Everything should be done by this point; `pw` is now invalid.
///
///     return;
/// }
///
void  nfsutil_pw_query_init(
	struct nfsutil_passwd_query  *query,
	void    *optional_stack_memory,
	size_t  stack_memory_size
	);


/// The `nfsutil_grp_query_init` function prepares a `struct nfsutil_group_query`
/// variable for use and ensures that it has predictable contents.
///
/// This function must be called before any other `nfsutil_grp_query_*` functions
/// are called on the given `struct nfsutil_group_query`.
///
/// The `optional_stack_memory` and `stack_memory_size` parameters allow
/// the caller to provide stack-allocated memory for the query to use.
/// This should allow the query to avoid using `malloc` in most cases,
/// though this is not a guarantee, because the `group` table (file) may
/// have long entries that force a dynamic allocation, or the underlying
/// libc implementation may call arbitrary memory allocation routines such
/// as `malloc` and `realloc`.
///
/// To opt-out of using the `optional_stack_memory` and `stack_memory_size`
/// parameters, pass the arguments `NULL` and `0`, respectively. This will
/// cause subsequent `nfsutil_grp_query_*` functions to lazily allocate memory
/// using `malloc` or `realloc`.
///
/// Usage example:
///
/// static const char *null_alt(const char *str, const char *alt)
/// {
///     if ( str != NULL )
///         return str;
///     else
///         return alt;
/// }
///
/// static void example_print_group(const char *group_name)
/// {
///     char    bufptr[GROUP_STACKMEM_SIZE_HINT];
///     size_t  buflen = GROUP_STACKMEM_SIZE_HINT;
///     struct  nfsutil_group_query  group_query;
///     int     err = -1;
///
///     nfsutil_grp_query_init(&group_query, bufptr, buflen);
///
///     while ( err != 0 )
///     {
///         err = nfsutil_grp_query_call_getgrnam_r(&group_query, group_name);
///         if ( err == EINTR )
///             continue;
///         else
///         if ( err == ENOMEM ) {
///             printf("Out of memory error while attempting to retrieve group entry for group %s\n",
///                 group_name);
///             nfsutil_grp_query_cleanup(&group_query);
///             return;
///         }
///         else
///         if ( err == EIO ) {
///             printf("I/O error during getpwnam_r: %s\n", strerror(err));
///             nfsutil_grp_query_cleanup(&group_query);
///             return;
///         }
///         else
///         //... etc ...
///         if ( err != 0 )
///         {
///             printf("Unhandled error from getpwnam_r: %s\n", strerror(err));
///             nfsutil_grp_query_cleanup(&group_query);
///             return;
///         }
///     }
///
///     struct group  *grp;
///     grp = nfsutil_grp_query_result(&group_query);
///     if ( grp == NULL )
///         printf("group entry not found for group '%s'\n", group_name);
///     else
///     {
///         // ... do things with `grp` ...
///         printf("group entry for '%s':\n", group_name);
///         printf("  name:     %s\n", null_alt(grp->gr_name, "<NULL>"));
///         printf("  gid:      %d\n", grp->gr_gid);
///         char **members = grp->gr_mem;
///         for ( ssize_t i = 0; members[i] != NULL; i++ )
///         {
///             const char *member = members[i];
///             printf("  member[%ld]: %s\n", i, null_alt(member, "<NULL>"));
///         }
///     }
///
///     nfsutil_grp_query_cleanup(&group_query);
///     // Everything should be done by this point; `grp` is now invalid.
///
///     return;
/// }
///
void  nfsutil_grp_query_init(
	struct nfsutil_group_query  *query,
	void    *optional_stack_memory,
	size_t  stack_memory_size
	);


/// Searches the system's `passwd` file/database for the entry corresponding
/// to the given `login_name`.
///
/// This function (along with the `nfsutil_passwd_query` object) handles
/// all of the memory allocation needs of `getpwnam_r`, including reallocation
/// if initial buffer sizes are not sufficient.
///
/// Return values are the same as for `getpwnam_r`, with the addition of
/// `ENOMEM`, which is returned if memory (re)allocation (by `realloc`) fails,
/// and the subtraction of `ERANGE` (buffer size insufficient), which this
/// function mitigates by increasing an internal buffer as large as is
/// required.
///
/// See `nfsutil_pw_query_init` for a usage example.
///
/// For more details, see the `getpwnam_r` documentation:
/// https://pubs.opengroup.org/onlinepubs/9699919799/functions/getpwnam.html
///
int nfsutil_pw_query_call_getpwnam_r(
		struct nfsutil_passwd_query  *query,
		const char  *login_name
	);


/// Searches the system's `passwd` file/database for the entry corresponding
/// to the given `uid`.
///
/// This function (along with the `nfsutil_passwd_query` object) handles
/// all of the memory allocation needs of `getpwuid_r`, including reallocation
/// if initial buffer sizes are not sufficient.
///
/// Return values are the same as for `getpwuid_r`, with the addition of
/// `ENOMEM`, which is returned if memory (re)allocation (by `realloc`) fails,
/// and the subtraction of `ERANGE` (buffer size insufficient), which this
/// function mitigates by increasing an internal buffer as large as is
/// required.
///
/// See `nfsutil_pw_query_init` for a usage example.
///
/// For more details, see the `getpwuid_r` documentation:
/// https://pubs.opengroup.org/onlinepubs/9699919799/functions/getpwuid.html
///
int nfsutil_pw_query_call_getpwuid_r(
		struct nfsutil_passwd_query  *query,
		uid_t   uid
	);


/// Searches the system's `group` file/database for the entry corresponding
/// to the given `group_name`.
///
/// This function (along with the `nfsutil_group_query` object) handles
/// all of the memory allocation needs of `getgrnam_r`, including reallocation
/// if initial buffer sizes are not sufficient.
///
/// Return values are the same as for `getgrnam_r`, with the addition of
/// `ENOMEM`, which is returned if memory (re)allocation (by `realloc`) fails,
/// and the subtraction of `ERANGE` (buffer size insufficient), which this
/// function mitigates by increasing an internal buffer as large as is
/// required.
///
/// See `nfsutil_grp_query_init` for a usage example.
///
/// For more details, see the `getgrnam_r` documentation:
/// https://pubs.opengroup.org/onlinepubs/9699919799/functions/getgrnam.html
///
int nfsutil_grp_query_call_getgrnam_r(
		struct nfsutil_group_query  *query,
		const char  *group_name
	);


/// Searches the system's `group` file/database for the entry corresponding
/// to the given `gid`.
///
/// This function (along with the `nfsutil_group_query` object) handles
/// all of the memory allocation needs of `getgrgid_r`, including reallocation
/// if initial buffer sizes are not sufficient.
///
/// Return values are the same as for `getgrgid_r`, with the addition of
/// `ENOMEM`, which is returned if memory (re)allocation (by `realloc`) fails,
/// and the subtraction of `ERANGE` (buffer size insufficient), which this
/// function mitigates by increasing an internal buffer as large as is
/// required.
///
/// See `nfsutil_grp_query_init` for a usage example.
///
/// For more details, see the `getgrgid_r` documentation:
/// https://pubs.opengroup.org/onlinepubs/9699919799/functions/getgrgid.html
///
int nfsutil_grp_query_call_getgrgid_r(
		struct nfsutil_group_query  *query,
		gid_t   gid
	);


/// These functions retrieve the `struct passwd` or `struct group` object
/// returned by earlier calls to `nfsutil_pw_query_call_*` or
/// `nfsutil_grp_query_call_*` functions.
///
/// These objects are only valid as long as the `nfsutil_passwd_query`
/// or `nfsutil_group_query` object is still "live". The memory used
/// for these might be released and/or wiped when `nfsutil_pw_query_cleanup`
/// or `nfsutil_grp_query_cleanup` are called. So if the caller needs to
/// persist these data past any calls to query cleanup functions, the caller
/// should perform a deep copy of these objects into longer-lasting memory
/// regions. For an easy way to perform this deep copy, or to clone the
/// returned `passwd` struct, see the `nfsutil_copy_passwd`,
/// `nfsutil_copy_group`, `nfsutil_clone_passwd`, or `nfsutil_clone_group`
/// functions.
///
/// Returns: NULL if no querying function was previously called, NULL if
///   there was no entry found during the previous query, or a pointer
///   to a `struct passwd` or `struct group` object within the query's
///   memory buffer.
struct passwd *nfsutil_pw_query_result(struct nfsutil_passwd_query *query);

/// ditto
struct group *nfsutil_grp_query_result(struct nfsutil_group_query *query);


/// These functions release (and, if appropriate, sanitize) any resources
/// that were allocated by the query object passed into the `query` parameter.
///
/// These are safe to call even if the query used stack memory exclusively.
/// The query functions will never attempt to free stack memory, or any
/// other forms of caller-allocated memory, and will only free memory that
/// the query owns (e.g. from having called `malloc` or `realloc` internally).
///
/// These are also safe to call if an earlier function failed by returning
/// an ENOMEM error code. The query object (and/or its reference) will
/// contain the information needed for the cleanup function to know if
/// earlier exceptions prevented allocation or not.
///
/// To avoid potential memory leaks, these cleanup functions should always
/// be called after any work involving query objects has concluded.
///
void nfsutil_pw_query_cleanup(struct nfsutil_passwd_query *query);

/// ditto
void nfsutil_grp_query_cleanup(struct nfsutil_group_query *query);


/// Calculates the size, in bytes, of memory required to store all of the
/// string data that the `pw` struct references, including null-terminating
/// characters ('\0').
///
/// If any of `pw`'s string fields point to NULL, those fields will contribute
/// zero (nothing) to the final tally. This represents the notion that if the
/// `pw` struct were to be copied, no additional memory would be required for
/// storing such values.
///
/// Returns 0 if `pw` is NULL.
size_t nfsutil_passwd_string_size(const struct passwd *pw);

/// Calculates the size, in bytes, of all memory directly or indirectly
/// referenced by the given `pw` pointer.
///
/// This is effectively the sum of `sizeof(struct passwd)` and the result
/// of calling `nfsutil_passwd_string_size(pw)`.
///
/// Returns 0 if `pw` is NULL.
size_t nfsutil_passwd_total_size(const struct passwd *pw);


/// Calculates the size, in bytes, of memory required to store all of the
/// string data that the `grp` struct references, including null-terminating
/// characters ('\0').
///
/// This calculation includes the space required to store the members array,
/// as well as that array's terminal NULL element.
///
/// If any of `grp`'s string fields point to NULL, those fields will contribute
/// zero (nothing) to the final tally. This represents the notion that if the
/// `grp` struct were to be copied, no additional memory would be required for
/// storing such values.
///
/// Returns 0 if `grp` is NULL.
size_t nfsutil_group_string_size(const struct group *grp);

/// Calculates the size, in bytes, of all memory directly or indirectly
/// referenced by the given `grp` pointer.
///
/// This is effectively the sum of `sizeof(struct group)` and the result
/// of calling `nfsutil_group_string_size(grp)`.
///
/// Returns 0 if `grp` is NULL.
size_t nfsutil_group_total_size(const struct group *grp);


/// The `nfsutil_copy_passwd` function performs a deep copy of `pw_from` into
/// `pw_to`. Any string data referenced by `pw_from` is copied into the
/// given `string_buffer`, and `pw_to` will have its corresponding string
/// fields populated with pointers to the copied strings in `string_buffer`
///
/// `string_buffer` must be large enough to hold all of the strings copied
/// from the `pw_from` object. This size can be precisely determined by
/// calling the `nfsutil_passwd_string_size` function with the `passwd` struct
/// that will be passed into this function's `pw_from` parameter.
/// If allocating enough space to store the `passwd` struct that `pw_to`
/// points to in addition to the strings, consider using
/// `nfsutil_passwd_total_size`, but ensure that `string_buffer` points to
/// empty buffer space (e.g. after `pw_to`) and not to the `pw_to` object.
///
/// This function assumes that both the `pw_to` and `pw_from` parameters
/// are not NULL.
///
/// Returns the `pw_to` pointer after populating `pw_to` and `string_buffer`
/// with the contents of `pw_from`.
///
struct passwd *nfsutil_copy_passwd(
		struct       passwd *pw_to,
		const struct passwd *pw_from,
		char *string_buffer
	);

/// Clones the `passwd` struct pointed to by `pw_from` by allocating the
/// necessary memory (as returned by `nfsutil_passwd_total_size`) in one
/// contiguous block with a single call to `malloc` and then using
/// `nfsutil_copy_passwd` to copy the contents of `pw_from` into `*pw_to`.
///
/// If `pw_from` is NULL, then no allocation will be done,
/// NULL will be written to `*pw_to`, and 0 will be returned.
///
/// If `nfsutil_clone_passwd` does not return 0, NULL will always be
/// written to `*pw_to`, as this will always indicate some form of
/// allocation failure.
///
/// Returns: 0 upon succes, or ENOMEM if the necessary memory could not be
///   allocated using a single call to `malloc`.
int nfsutil_clone_passwd(
		struct       passwd **pw_to,
		const struct passwd *pw_from
	);

/// The `nfsutil_copy_group` function performs a deep copy of `grp_from` into
/// `grp_to`. Any string data referenced by `grp_from` is copied into the
/// given `string_buffer`, and `grp_to` will have its corresponding string
/// fields populated with pointers to the copied strings in `string_buffer`
///
/// `string_buffer` must be large enough to hold all of the strings copied
/// from the `grp_from` object. This size can be precisely determined by
/// calling the `nfsutil_group_string_size` function with the `group` struct
/// that will be passed into this function's `grp_from` parameter.
/// If allocating enough space to store the `group` struct that `grp_to`
/// points to in addition to the strings, consider using
/// `nfsutil_group_total_size`, but ensure that `string_buffer` points to
/// empty buffer space (e.g. after `grp_to`) and not to the `grp_to` object.
///
/// This function assumes that both the `grp_to` and `grp_from` parameters
/// are not NULL.
///
/// Returns the `grp_to` pointer after populating `grp_to` and `string_buffer`
/// with the contents of `grp_from`.
///
struct group *nfsutil_copy_group(
		struct       group *grp_to,
		const struct group *grp_from,
		char *string_buffer
	);

/// Clones the `group` struct pointed to by `grp_from` by allocating the
/// necessary memory (as returned by `nfsutil_group_total_size`) in one
/// contiguous block with a single call to `malloc` and then using
/// `nfsutil_copy_group` to copy the contents of `grp_from` into `*grp_to`.
///
/// If `grp_from` is NULL, then no allocation will be done,
/// NULL will be written to `*grp_to`, and 0 will be returned.
///
/// If `nfsutil_clone_group` does not return 0, NULL will always be
/// written to `*grp_to`, as this will always indicate some form of
/// allocation failure.
///
/// Returns: 0 upon succes, or ENOMEM if the necessary memory could not be
///   allocated using a single call to `malloc`.
int nfsutil_clone_group(
		struct       group **grp_to,
		const struct group *grp_from
	);


/// Structure used by functions that return only uid+gid information
/// for a passwd query.
struct nfsutil_passwd_ints
{
	uid_t  uid;
	gid_t  gid;
	int    err;
};

/// An initial value for `nfsutil_passwd_ints` variables that sets
/// `uid` to `(uid_t)(-1)` and `gid` to `(gid_t)(-1)` and `err` to `0`.
///
/// If an `nfsutil_passwd_ints` struct isn't populated (e.g. by holding the
/// return value of a function) at the point of its declaration, then it
/// should be initialized with this constant value. This avoids the
/// possibility of an uninitialized `nfsutil_passwd_ints` struct introducing
/// misleading data after being returned/passed several times.
///
extern const struct nfsutil_passwd_ints  nfsutil_passwd_ints_init;

/// Structure used by functions that return only gid information
/// for a group query.
struct nfsutil_group_ints
{
	gid_t  gid;
	int    err;
};

/// An initial value for `nfsutil_group_ints` variables that sets
/// `gid` to `(gid_t)(-1)` and `err` to `0`.
///
/// If an `nfsutil_group_ints` struct isn't populated (e.g. by holding the
/// return value of a function) at the point of its declaration, then it
/// should be initialized with this constant value. This avoids the
/// possibility of an uninitialized `nfsutil_group_ints` struct introducing
/// misleading data after being returned/passed several times.
///
extern const struct nfsutil_group_ints  nfsutil_group_ints_init;

/// Convenience functions that retrieve the uid and gid associated with the
/// given `user_name` or `uid`.
///
/// These are useful if the caller does not require `passwd` entry's
/// string information. Obtaining only the integer information (uid and gid)
/// does not require using an `nfsutil_passwd_query` object or doing
/// any memory management.
///
/// If errors occur, or no entry is found with that `user_name` or `uid`,
/// then the return value's `uid` and `gid` field are set to `(uid_t)(-1)`
/// and `(gid_t)(-1)`, respectively.
///
/// The return value has an `err` field to indicate if errors occurred;
/// this is set to whatever the underlying call to `getpwnam_r` or `getpwuid_r`,
/// returned, or to ENOENT if a matching entry does not exist.
///
/// If the returned value has a non-zero `err` field, then the caller should
/// not use the returned `uid` or `gid` fields.
///
/// These functions do not require the caller to perform any memory management-
/// related tasks. That is all handled internally with an `nfsutil_passwd_query`
/// object and related functions.
///
struct nfsutil_passwd_ints
	nfsutil_getpwnam_ints(const char *user_name);

/// ditto
struct nfsutil_passwd_ints
	nfsutil_getpwuid_ints(uid_t uid);

/// Convenience functions for retrieving the `passwd` struct matching the
/// given `user_name` or `uid`.
///
/// If the resulting struct (`*pw`) was not set to NULL, then the caller is
/// responsible for calling `free` on that struct pointer when they are done
/// using it.
///
/// The `pw` parameter should be passed a pointer to a variable that the caller
/// wishes to populate with a new `passwd` struct pointer, like so:
///
///   struct passwd *pw;
///   int err = nfsutil_getpwnam_struct(&pw, user_name);
///   ... error handling ...
///   if (pw) {
///       ... use `pw` ...
///       free(pw);
///   }
///
/// If an error occurs during the lookup, or there is no entry matching the
/// the given `user_name` or `uid`, then `*pw` will be set to NULL.
///
/// Returns: the return value of the underlying `getpwnam_r` function,
///          or ENOENT if a corresponding entry did not exist.
///
int nfsutil_getpwnam_struct(struct passwd **pw, const char *user_name);
int nfsutil_getpwuid_struct(struct passwd **pw,  uid_t uid); /// ditto

/// Convenience function that retrieves the gid associated with
/// the given `group_name`.
///
/// This is useful if the caller does not require the `group` entry's
/// string information. Obtaining only the integer information (the gid)
/// does not require using an `nfsutil_group_query` object or doing
/// any memory management.
///
/// If errors occur, or no entry is found with that `group_name`, then
/// the return value's `gid` field is set to `(gid_t)(-1)`.
///
/// The return value has an `err` field to indicate if errors occurred;
/// this is set to whatever the underlying call to `getgrnam_r` returned,
/// or to ENOENT if a matching entry does not exist.
///
/// If the returned value has a non-zero `err` field, then the caller should
/// not use the returned `gid` field.
///
/// This function does not require the caller to perform any memory management-
/// related tasks. That is all handled internally with an `nfsutil_group_query`
/// object and related functions.
///
struct nfsutil_group_ints
	nfsutil_getgrnam_ints(const char *group_name);

/// There is probably no reason to ever call this. It is used for retrieving
/// the group's gid, but if you call this, you already have the gid.
/// For now, this function merely exists for symmetry purposes, or in case
/// there ends up being some corner-case where getgruid_r returns a different
/// gid than what it was asked to find, and that behavior is somehow desired
/// (or needs to be tested).
struct nfsutil_group_ints
	nfsutil_getgrgid_ints(gid_t gid);

/// Convenience functions for retrieving the `group` struct matching the
/// given `group_name` or `gid`.
///
/// If the resulting struct (`*grp`) was not set to NULL, then the caller is
/// responsible for calling `free` on that struct pointer when they are done
/// using it.
///
/// The `grp` parameter should be passed a pointer to a variable that the caller
/// wishes to populate with a new `group` struct pointer, like so:
///
///   struct group *grp;
///   int err = nfsutil_getgrnam_struct(&grp, group_name);
///   ... error handling ...
///   if (grp) {
///       ... use `grp` ...
///       free(grp);
///   }
///
/// If an error occurs during the lookup, or there is no entry matching the
/// the given `group_name` or `gid`, then `*grp` will be set to NULL.
///
/// Returns: the return value of the underlying `getgrnam_r` function,
///          or ENOENT if a corresponding entry did not exist.
///
int nfsutil_getgrnam_struct(struct group **grp, const char *group_name);
int nfsutil_getgrgid_struct(struct group **grp,  gid_t gid); /// ditto

/// The `nfsutil_getgrouplist_by_uid` function is similar to the linux/glibc
/// `getgrouplist` function, except that it accepts a user ID instead of a
/// user name, and returns error codes instead of `-1` or a count value.
///
/// This method is useful in cases where a user's `uid` and (optionally) `gid`
/// are available, but it is inconvenient to set up an `nfsutil_passwd_query`
/// object just to get `pw->pw_name` or otherwise allocate memory for
/// a `passwd` struct to get the user's name.
///
/// By default, the `user_gid` parameter of this will behave exactly like the
/// corresponding parameter in `getgrouplist`. That is, the `user_gid` parameter
/// will override any gid retrieved along with the user's name, because this
/// allows `nfsutil_getgrouplist_by_uid` to behave more like the `getgrouplist`
/// function. There is one exception: passing a value of `(gid_t)(-1)` will
/// cause `nfsutil_getgrouplist_by_uid` to use the given user's gid found
/// in the `passwd` database when calling `getgrouplist`. This makes it possible
/// to use this function without having the gid beforehand and without issuing
/// extra `passwd` queries to resolve such a situation.
///
/// Because this calls `nfsutil_pw_query_call_getpwuid_r` internally, this
/// may return all of the error codes that that function can return. As such,
/// this *does not* return the same return values that `getgrouplist` returns.
/// Instead, if the call to `nfsutil_pw_query_call_getpwuid_r` succeeded but
/// `getgrouplist` returned `-1`, then this function will return `ERANGE`
/// to indicate that `*groups` and `*ngroups` were not large enough to store
/// the results. `getgrouplist`'s zero and positive return values were all
/// redundant with `*ngroups`, so just use `*ngroups` to know how many groups
/// were returned. Additionally, `ENOENT` will be returned if `getpwuid_r`
/// could not find an entry corresponding to the given `user_uid`.
///
int nfsutil_getgrouplist_by_uid(
		uid_t user_uid, gid_t user_gid,
		gid_t *groups, int *ngroups
	);

/// `nfsidmap_print_pwgrp_error` prints error messages resulting from
/// `get**nam_r` and `get***id_r` functions using the following format:
/// "${in_function}: Error happened while looking up ${key_name} '${key_value}'"
///     "${rel_entry_before}${rel_entry_value}${rel_entry_after}': <error message>"
///
/// This function uses the IDMAP_LOG macro (at log level 0) to print the
/// error messages, and is thus specific to the nfsidmap portion of nfs_utils.
/// (Ideally, this could be used by any code, but creating a callback for such
/// a macro does not seem to have an obvious|humane solutions. Improvements welcome.)
///
/// The `rel_entry_*` parameters are for describing a value that is related
/// to the key that was used in the lookup. Since these lookups tend to be used
/// for mapping one identifier to another (ex: domain user to local user),
/// it might make sense to fill this with the thing being mapped to the local
/// user/group. Be sure to always include appropriate punctuation or spaces
/// at the beginning of `rel_entry_before` or at the end of `rel_entry_after`.
/// This will always be preceded by a single quote ('\'') and followed by
/// either a colon (':') or space character (' ').
///
/// If any of `rel_entry_before`, `rel_entry_value`, and/or `rel_entry_after`
/// are NULL, then these NULL values will be replaced with "" before formatting.
///
/// It is possible that functions calling this function may print different
/// messages for any of these errors before calling this function. This might
/// seem redundant, but if those error messages predated this function, then
/// keeping them around is a way to avoid unnecessarily changing the error
/// messages produced by nfsidmap (so as to be less likely to break any
/// software that might scan for these messages).
///
/// When handling ENOMEM, this function will use a stack-allocated buffer to
/// format the error string before sending it to IDMAP_LOG. This should work
/// as long as there is remaining stack space and IDMAP_LOG doesn't (directly
/// or indirectly) call malloc/realloc/calloc (or at least doesn't allocate
/// more than what's left). The caller should still try to free as much memory
/// as possible before calling this function (within reason).
///
void nfsidmap_print_pwgrp_error(
		ssize_t     err,
		const char  *in_function,
		const char  *key_name, // Ex: "user name", "local name", "uid", "gid", etc.
		const char  *key_value,
		const char  *rel_entry_before, // Ex: " for Static entry with name '", " in domain '", etc
		const char  *rel_entry_value,  // Ex: "foo@bar", "your_domain_here" 
		const char  *rel_entry_after   // Ex: "'", or put (NULL|"") if you're not using a related entry.
	);


/// Unittests
/// (Sorry, there doesn't seem to be any unittest build for nfs-utils, so you'll
/// have to call them manually from a testing program to see if they pass.)
void test__format_expansion_length(void);
void test__escape_fmtspec_inplace(void); /// ditto

#endif /* PASSWD_QUERY_H */
