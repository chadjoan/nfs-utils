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

#endif /* PASSWD_QUERY_H */
