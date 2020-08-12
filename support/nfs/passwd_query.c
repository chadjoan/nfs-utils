/*
 *  passwd_query.c
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

#include <assert.h>
#include <errno.h>
#include <grp.h>
#include <pwd.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>  // For uid_t/gid_t

#include "passwd_query.h"

// This struct stores results and tracks memory-management related metadata
// for the functions in this module that query system functions such as
// `getpwnam_r` and `getgrgid_r`.
struct buffered_query
{
	// Number of bytes allocated to this nfsutil_passwd_query object.
	size_t   allocation_size;


	// This tracks whether or not the query object owns its own memory.
	// Since `malloc` is the current allocator, this determines whether or not
	// our memory needs to be given to the `free` function during cleanup.
	// 0 means no/false, 1 means yes/true.
	uint8_t  own_allocation;


	// Set to 0 if the query deduced that the given name/uid/whatever
	// does not exist in the system's table being queried (ex: passwd file).
	// Otherwise, it is set to 1 to indicate that the entry was found.
	// In the latter case, the query's buffer 
	// field will be populated with the contents of that row/entry.
	uint8_t  entry_exists;


	// Accessing this member returns a pointer to the memory allocated
	// beyond the `buffered_query` struct. This memory is used to store
	// buffer/return structs and provide query functions (ex: getpwnam_r,
	// getgrnam_r, and so on) with scratch space and a place to put
	// dynamically allocated results (ex: strings pointed to from
	// a struct being returned).
	//
	// The `buf_query_get_buffer_size` function returns the size
	// of this memory region.
	//
	// More specific query types should provide functions for partitioning
	// this memory space, ex: for returning statically-positioned structs
	// or returning the remaining untyped portion.
	char     buffer_start[];
};

#define PWQ_INSTANCE_SIZE   (sizeof(struct buffered_query) + sizeof(struct passwd))
#define PWQ_RESULTS_BUFFER_SIZE_MIN   (512)
#define PWQ_MEMORY_DEMAND   (PWQ_INSTANCE_SIZE + PWQ_RESULTS_BUFFER_SIZE_MIN)
#define GRPQ_INSTANCE_SIZE  (sizeof(struct buffered_query) + sizeof(struct group))
#define GRPQ_RESULTS_BUFFER_SIZE_MIN  (512)
#define GRPQ_MEMORY_DEMAND  (GRPQ_INSTANCE_SIZE + GRPQ_RESULTS_BUFFER_SIZE_MIN)

// ----- generic buffered query memory partitioning -----

// This pointer-length pair is used to simplify the getter functions used to
// return memory regions from the various types of buffered queries.
struct buffer_region
{
	void    *ptr;
	size_t  len;
};

// Returns the number of bytes allocated past the query's `buffer_start` address.
static size_t buf_query_get_buffer_size(struct buffered_query *query)
{
	return query->allocation_size - ((char*)query->buffer_start - (char*)query);
}

// Returns the region of memory associated with the query's `buffer_start`
// member. This is a pointer-length pair with `buffer_start` being the pointer
// and the result of calling `buf_query_get_buffer_size` being the length.
static struct buffer_region
	buf_query_get_buffer(struct buffered_query *query)
{
	struct buffer_region  buf;
	buf.ptr = query->buffer_start;
	buf.len = buf_query_get_buffer_size(query);
	return buf;
}

// ----- passwd query memory partitioning -----

// Returns a pointer to the region of the query's memory that contains the
// `passwd` struct. This struct is modified by the `getpwnam_r` and
// `getpwuid_r` functions, and is effectively part of their return value.
//
// The rest of the data returned by `getpwnam_r` and `getpwuid_r` is stored in
// the rest of the query object's memory buffer, which is accessible through
// the `passwd_query_get_buffer` function.
static struct passwd *passwd_query_get_passwd(struct buffered_query *query)
{
	return (struct passwd*)query->buffer_start;
}

// Returns a the region of the query's memory that is not occupied by the
// `passwd` struct. This region is used by functions like `getpwnam_r`
// and `getpwuid_r` to store dynamic data related to the struct they return,
// such as string data that is referenced by the `passwd` struct.
static struct buffer_region
	passwd_query_get_buffer(struct buffered_query *query)
{
	struct buffer_region  buf = buf_query_get_buffer(query);
	buf.ptr += sizeof(struct passwd);
	buf.len -= sizeof(struct passwd);
	return buf;
}

// ----- group query memory partitioning -----

// Returns a pointer to the region of the query's memory that contains the
// `group` struct. This struct is modified by the `getgrnam_r` and
// `getgrgid_r` functions, and is effectively part of their return value.
//
// The rest of the data returned by `getgrnam_r` and `getgrgid_r` is stored in
// the rest of the query object's memory buffer, which is accessible through
// the `group_query_get_buffer` function.
static struct group *group_query_get_group(struct buffered_query *query)
{
	return (struct group*)query->buffer_start;
}

// Returns a the region of the query's memory that is not occupied by the
// `group` struct. This region is used by functions like `getgrnam_r`
// and `getgrgid_r` to store dynamic data related to the struct they return,
// such as string data that is referenced by the `group` struct.
static struct buffer_region
	group_query_get_buffer(struct buffered_query *query)
{
	struct buffer_region  buf = buf_query_get_buffer(query);
	buf.ptr += sizeof(struct group);
	buf.len -= sizeof(struct group);
	return buf;
}

// ----- query initialization functions -----

static void buf_query_populate(
		struct buffered_query *query,
		size_t   alloc_size,
		uint8_t  own_allocation
	)
{
	// Gently encourage determinism.
	memset(query, 0, alloc_size);

	// Fill data in.
	query->allocation_size = alloc_size;
	query->own_allocation = own_allocation;
}

// Returns 0 upon success, or ENOMEM to indicate an out-of-memory condition.
static int buf_query_mallocate_if_needed(struct buffered_query **query, size_t memory_demand_guess)
{
	// Non-NULL indicates that buf_query_init already found memory for it.
	if ( *query != NULL )
		return 0;

	// *query == NULL
	// Which means that mallocation is needed.
	struct buffered_query *result_query;
	result_query = malloc(memory_demand_guess);
	if ( result_query == NULL )
		return ENOMEM;

	size_t own_allocation = 1;
	buf_query_populate(result_query, memory_demand_guess, own_allocation);

	// By delaying this assignment until the end of the function, we can ensure
	// that *query never points to uninitialized data.
	*query = result_query;
	return 0;
}

static void buf_query_init(
		struct buffered_query  **query,
		void    *optional_stack_memory,
		size_t  stack_memory_size,
		size_t  memory_demand_guess
	)
{
	struct buffered_query *result_query;

	// Use stack memory if available, otherwise malloc.
	if ( optional_stack_memory && (stack_memory_size > memory_demand_guess) )
	{
		result_query = optional_stack_memory;
		size_t own_allocation = 0;
		buf_query_populate(result_query, stack_memory_size, own_allocation);
	}
	else
	{
		// Delay mallocation until it's needed.
		// That way, we don't need to return error codes from this
		// function, which makes the caller's side much cleaner.
		// (In other words, the caller only needs to handle ENOMEM
		// in (probably) one place.)
		// This is done my ensuring that query->internals is a
		// predictable value; NULL in this case.
		result_query = NULL;
	}

	// By delaying this assignment until the end of the function, we can ensure
	// that *query never points to uninitialized data.
	*query = result_query;
}

// public definitions:
void  nfsutil_pw_query_init(
	struct nfsutil_passwd_query  *query,
	void    *optional_stack_memory,
	size_t  stack_memory_size
	)
{
	buf_query_init(
		(struct buffered_query **)&query->internals,
		optional_stack_memory,
		stack_memory_size,
		PWQ_MEMORY_DEMAND);
}

void  nfsutil_grp_query_init(
	struct nfsutil_group_query  *query,
	void    *optional_stack_memory,
	size_t  stack_memory_size
	)
{
	buf_query_init(
		(struct buffered_query **)&query->internals,
		optional_stack_memory,
		stack_memory_size,
		GRPQ_MEMORY_DEMAND);
}


// ----- Various query runner functions. -----
union pwgrp_key
{
	const char *as_name;
	uid_t      as_uid;
	gid_t      as_gid;
};

// This logic was factored out of the query runners to avoid code duplication.
// It uses the outputs of the various system querying functions (ex: getpwnam_r)
// to determine if we need to allocate more memory, and if not, to update the
// state of our query object based on the results of the call.
static void pwgrp_reflect_outcome(

		// Things to analyze
		int    return_code,
		void   *entry_exists,

		// Things to update
		ssize_t *memory_shortage,
		struct buffered_query *query,
		void   *result,
		size_t result_sizeof
	)
{
	if ( return_code == ERANGE )
	{
		*memory_shortage = -1;

		// Clear all buffer memory so the results of this aborted call
		// can't (negatively) affect the results of future attempts.
		struct buffer_region buf = buf_query_get_buffer(query);
		memset(buf.ptr, 0, buf.len);
	}
	else
	{
		*memory_shortage = 0;

		if ( entry_exists )
			query->entry_exists = 1;
		else
		{
			query->entry_exists = 0;

			// Clear the returned struct so that any code that ignores
			// the (entry_exists == 0) status will at least get
			// data that obviously looks blank, instead of getting
			// whatever undefined contents the system function
			// (ex: getpwnam_r, getgrnam_r) left there.
			// Basically, this should make bugs easier to spot and reproduce.
			memset(result, 0, result_sizeof);
		}
	}
}

static int call_getpwnam_r(
		void *caller_context,
		struct buffered_query *query,
		ssize_t *memory_shortage
	)
{
	union pwgrp_key  *key          = caller_context;
	const char       *login_name   = key->as_name;
	struct passwd    *result       = passwd_query_get_passwd(query);
	struct passwd    *entry_exists = NULL;

	struct buffer_region buf = passwd_query_get_buffer(query);

	// Attempt to look up the desired passwd entry by login name.
	int return_code = getpwnam_r(
			login_name, result,
			buf.ptr, buf.len,
			&entry_exists);

	// Update *memory_shortage and query state.
	pwgrp_reflect_outcome(
		return_code, entry_exists,
		memory_shortage, query, result, sizeof(*result));

	return return_code;
}

static int call_getpwuid_r(
		void *caller_context,
		struct buffered_query *query,
		ssize_t *memory_shortage
	)
{
	union pwgrp_key  *key          = caller_context;
	uid_t            uid           = key->as_uid;
	struct passwd    *result       = passwd_query_get_passwd(query);
	struct passwd    *entry_exists = NULL;

	struct buffer_region buf = passwd_query_get_buffer(query);

	// Attempt to look up the desired passwd entry by login name.
	int return_code = getpwuid_r(
			uid, result,
			buf.ptr, buf.len,
			&entry_exists);

	// Update *memory_shortage and query state.
	pwgrp_reflect_outcome(
		return_code, entry_exists,
		memory_shortage, query, result, sizeof(*result));

	return return_code;
}

static int call_getgrnam_r(
		void *caller_context,
		struct buffered_query *query,
		ssize_t *memory_shortage
	)
{
	union pwgrp_key  *key          = caller_context;
	const char       *group_name   = key->as_name;
	struct group     *result       = group_query_get_group(query);
	struct group     *entry_exists = NULL;

	struct buffer_region buf = group_query_get_buffer(query);

	// Attempt to look up the desired group entry by login name.
	int return_code = getgrnam_r(
			group_name, result,
			buf.ptr, buf.len,
			&entry_exists);

	// Update *memory_shortage and query state.
	pwgrp_reflect_outcome(
		return_code, entry_exists,
		memory_shortage, query, result, sizeof(*result));

	return return_code;
}

static int call_getgrgid_r(
		void *caller_context,
		struct buffered_query *query,
		ssize_t *memory_shortage
	)
{
	union pwgrp_key  *key          = caller_context;
	gid_t            gid           = key->as_gid;
	struct group     *result       = group_query_get_group(query);
	struct group     *entry_exists = NULL;

	struct buffer_region buf = group_query_get_buffer(query);

	// Attempt to look up the desired group entry by login name.
	int return_code = getgrgid_r(
			gid, result,
			buf.ptr, buf.len,
			&entry_exists);

	// Update *memory_shortage and query state.
	pwgrp_reflect_outcome(
		return_code, entry_exists,
		memory_shortage, query, result, sizeof(*result));

	return return_code;
}

// ----- realloc loop functions -----
// Any pointers to things like query->internal will need to be updated after
// calling this, as the value of query->internal may change.
//
// Returns 0 if successful, otherwise ENOMEM to indicate an out-of-memory condition.
//
static int buf_query_realloc_upsize(struct buffered_query **query)
{
	size_t oldsize = (*query)->allocation_size;
	size_t newsize = oldsize * 2;
	void *oldptr = *query;
	void *newptr = NULL;

	// This code is intended to avoid assigning anything to *query until
	// any (re)allocation has already succeeded. We would violate the
	// promises made in the `nfsutil_*_query_cleanup` functions if we allowed
	// *query to point to an invalid memory location or set it to NULL when
	// it should point to memory that it owns.
	if ( !(*query)->own_allocation )
	{
		// Memory was not allocated by us. It might be stack memory or something.
		// Passing this memory to `realloc` might incur the wrath of the
		// Undefined Behavior gods, so let's not do that.
		// Instead, we'll `malloc` some new memory and copy our stuff over to that.
		newptr = malloc(newsize);
		if ( newptr == NULL )
			return ENOMEM;

		memcpy(newptr, oldptr, oldsize);
	}
	else
	{
		// Memory was already allocated with `malloc`, so we can pass the
		// pointer to `realloc` without incurring the wrath of the
		// Undefined Behavior gods.
		newptr = realloc(oldptr, newsize);
		if ( newptr == NULL )
			return ENOMEM;
	}

	// Update pointers and metadata to reflect what just happened.
	*query = newptr;
	(*query)->allocation_size = newsize;
	(*query)->own_allocation = 1;
	memset(newptr + oldsize, 0, newsize - oldsize);

	return 0;
}

// The `buf_query_realloc_loop` function implements a reallocation loop
// that can be shared and reused by any code specializing the
// `struct buffered_query` type.
//
// It will call a caller-supplied function, named as the `query_runner`
// parameter. If that function fails to complete because it requires more
// memory, `buf_query_realloc_loop` will repeatedly increase the size of
// the provided query's memory and each time will call `query_runner` with
// these updated and enlarged query objects. This is continued until
// `query_runner` can complete without exhausting the query's memory.
//
// The `struct buffered_query **query` parameter has an extra level of
// indirection to allow `buf_query_realloc_loop` to update the pointer
// to the query object in the event that the query object is moved
// during a reallocation.
//
// The `struct buffered_query **query` must be non-NULL.
// However, `*query` may be NULL. This indicates that the query's internals
// have not been allocated yet. In that situation, `buf_query_realloc_loop`
// will use `malloc` to allocate a new `buffered_query` object and will then
// initialize it before proceeding with any querying actions. The value of
// `query` is then updated so that the pointer it points to will point to
// the newly allocated query object.
//
// The `caller_context` parameter allows the caller to pass data into the
// `query_runner` function, such as any non-buffer arguments to the
// underlying system function (ex: name, uid, gid).
//
// The `query_runner` function shall set the value pointed to by the
// `memory_shortage` argument to -1 if it failed due to an insufficiently
// large buffer, or to 0 if the buffer was large enough to complete the call.
// Positive values of `*memory_shortage` could be used to indicate how much
// memory is needed, but this is currently not implemented.
//
// The integer returned from `query_runner` shall be whatever return code the
// underlying function returned, including unhandled error codes.
// The `buf_query_realloc_loop` function will then return that integer value
// to the caller.
//
// Thus, `buf_query_realloc_loop` returns whatever `query_runner` returns after
// `query_runner` has been provided with enough memory to finish executing
// completely (whether successful or not). `buf_query_realloc_loop` may
// additionally return ENOMEM if an out-of-memory condition was encountered
// while attempting to enlarge the buffer it sent to the `query_runner` function.
//
static int buf_query_realloc_loop(
		void    *caller_context,
		struct  buffered_query **query,
		size_t  memory_demand_guess,
		int (*query_runner)(
			void *caller_context,
			struct buffered_query *query,
			ssize_t *memory_shortage
		)
	)
{
	// query's internals may or may not be allocated at this point.
	// We ensure that it is.
	int oom = buf_query_mallocate_if_needed(query, memory_demand_guess);
	if ( oom )
		return oom;

	ssize_t memory_shortage = 0;
	int return_code = 0;
	while (1)
	{
		// Attempt to run the query with the memory allocated so far.
		return_code = query_runner(
				caller_context, *query, &memory_shortage);

		if ( memory_shortage != 0 ) {
			// Our buffer was not large enough. Upsize.
			oom = buf_query_realloc_upsize(query);
			if ( oom )
				return oom;

			// ... and try again.
			continue;
		}
		else
		{
			// Errors or not, everything else is the caller's responsibility.
			break;
		}
	}

	return return_code;
}

// ----- public querying interface(s) -----

// Notably, we don't use "sysconf(_SC_GETPW_R_SIZE_MAX)" (or similar)
// anywhere in these functions. That's because it is likely to return
// either -1 (which isn't helpful, but is at least honest) or
// some wild guess (which is misleading and requires us to realloc-loop ANYWAYS).
// As of this writing (2020-08-07), musl libc does the former.
// Supposedly, glibc does the latter.
// The real-life implications are what caused this bug report:
// https://bugzilla.linux-nfs.org/show_bug.cgi?id=344
//
// This all means that the optimal strat involves completely ignoring
// sysconf and instead directly proceeding to use a realloc-loop,
// because we would need to do that regardless.

// See the header for more specific documentation on these functions.
int nfsutil_pw_query_call_getpwnam_r(
		struct nfsutil_passwd_query  *query,
		const char  *login_name
	)
{
	union pwgrp_key  key;
	key.as_name = login_name;

	return buf_query_realloc_loop(&key,
		(struct buffered_query **)&query->internals,
		PWQ_MEMORY_DEMAND, &call_getpwnam_r);
}

int nfsutil_pw_query_call_getpwuid_r(
		struct nfsutil_passwd_query  *query,
		uid_t   uid
	)
{
	union pwgrp_key  key;
	key.as_uid = uid;

	return buf_query_realloc_loop(&key,
		(struct buffered_query **)&query->internals,
		PWQ_MEMORY_DEMAND, &call_getpwuid_r);
}

int nfsutil_grp_query_call_getgrnam_r(
		struct nfsutil_group_query  *query,
		const char  *group_name
	)
{
	union pwgrp_key  key;
	key.as_name = group_name;

	return buf_query_realloc_loop(&key,
		(struct buffered_query **)&query->internals,
		GRPQ_MEMORY_DEMAND, &call_getgrnam_r);
}

int nfsutil_grp_query_call_getgrgid_r(
		struct nfsutil_group_query  *query,
		gid_t   gid
	)
{
	union pwgrp_key  key;
	key.as_gid = gid;

	return buf_query_realloc_loop(&key,
		(struct buffered_query **)&query->internals,
		GRPQ_MEMORY_DEMAND, &call_getgrgid_r);
}

// ----- functions for retrieving query results -----
struct passwd *nfsutil_pw_query_result(struct nfsutil_passwd_query *query)
{
	if ( query->internals == NULL )
		return NULL;
	else
	{
		struct buffered_query *query_ = query->internals;
		if ( query_->entry_exists )
			return passwd_query_get_passwd(query_);
		else
			return NULL;
	}
}

struct group *nfsutil_grp_query_result(struct nfsutil_group_query *query)
{
	if ( query->internals == NULL )
		return NULL;
	else
	{
		struct buffered_query *query_ = query->internals;
		if ( query_->entry_exists )
			return group_query_get_group(query_);
		else
			return NULL;
	}
}

// ----- cleanup functions -----
static void buf_query_cleanup(struct buffered_query **query)
{
	if ( *query == NULL )
		return;

	uint8_t  do_free = (*query)->own_allocation;

	// Zero out the memory we used, for at least these reasons:
	// * It makes dangling-pointer bugs easier to find.
	// * It mitigates unforeseen security consequences by
	//     refusing to leave login/group names laying around in memory.
	memset(*query, 0, (*query)->allocation_size);

	// `free` as needed.
	if ( do_free )
		free(*query);

	// Leave the `nfsutil_passwd_query` or `nfsutil_group_query`
	// in a predictable state.
	*query = NULL;
}

void nfsutil_pw_query_cleanup(struct nfsutil_passwd_query *query)
{
	buf_query_cleanup((struct buffered_query **)&query->internals);
}

void nfsutil_grp_query_cleanup(struct nfsutil_group_query *query)
{
	buf_query_cleanup((struct buffered_query **)&query->internals);
}

// ----- other misc helper functions -----
static size_t nullsafe_strlen(const char *s)
{
	if ( s == NULL )
		return 0;
	else
		return strlen(s);
}

size_t nfsutil_passwd_string_size(const struct passwd *pw)
{
	if ( pw == NULL )
		return 0;

	size_t result = 0;
	result += nullsafe_strlen(pw->pw_name) + 1;
	result += nullsafe_strlen(pw->pw_dir) + 1;
	result += nullsafe_strlen(pw->pw_shell) + 1;
	return result;
}

size_t nfsutil_passwd_total_size(const struct passwd *pw)
{
	if ( pw == NULL )
		return 0;

	size_t result = sizeof(struct passwd);
	result += nfsutil_passwd_string_size(pw);
	return result;
}

size_t nfsutil_group_string_size(const struct group *grp)
{
	if ( grp == NULL )
		return 0;

	size_t result = 0;

	// Group name.
	result += nullsafe_strlen(grp->gr_name) + 1;

	if ( grp->gr_mem )
	{
		char **members = grp->gr_mem;
		size_t i;

		// Size of all strings pointed to by the members array.
		for ( i = 0; members[i] != NULL; i++ )
			result += nullsafe_strlen(members[i]);

		// Size of the array itself. The "+ 1" is for the NULL element at the end.
		result += ((char*)((members + i) + 1) - (char*)(members));
	}

	return result;
}

size_t nfsutil_group_total_size(const struct group *grp)
{
	if ( grp == NULL )
		return 0;

	size_t result = sizeof(struct group);
	result += nfsutil_group_string_size(grp);
	return result;
}

// Copies the contents of `src` into `*dst_buffer_cursor`, then updates
// `dst_buffer_cursor` to point to the character after the copied
// string's null-terminating character ('\0').
//
// If `src` is NULL, `dst_buffer_cursor` will not be modified.
//
// Returns a pointer to the start of the copied string, or NULL if `src`
// is NULL.
static char *buffered_copy(char **dst_buffer_cursor, const char *src)
{
	if ( src == NULL )
		return NULL;

	char *result = *dst_buffer_cursor;
	*dst_buffer_cursor = stpcpy(*dst_buffer_cursor, src) + 1;
	return result;
}

struct passwd *nfsutil_copy_passwd(
		struct       passwd *pw_to,
		const struct passwd *pw_from,
		char *string_buffer
	)
{
	char *cursor = string_buffer;

	// Ensure that any gaps or unused portions of the struct are filled
	// with something predictable.
	memset(pw_to, 0, sizeof(*pw_to));

	// Now do the deep copy.
	pw_to->pw_name  = buffered_copy(&cursor, pw_from->pw_name);
	pw_to->pw_uid   = pw_from->pw_uid;
	pw_to->pw_gid   = pw_from->pw_gid;
	pw_to->pw_dir   = buffered_copy(&cursor, pw_from->pw_dir);
	pw_to->pw_shell = buffered_copy(&cursor, pw_from->pw_shell);
	return pw_to;
}

int nfsutil_clone_passwd(
		struct       passwd **pw_to,
		const struct passwd *pw_from
	)
{
	if ( pw_from == NULL )
	{
		*pw_to = NULL;
		return 0;
	}

	size_t alloc_size = nfsutil_passwd_total_size(pw_from);
	char *str_buffer;
	void *buffer = malloc(alloc_size);
	if ( buffer == NULL )
	{
		*pw_to = NULL;
		return ENOMEM;
	}

	*pw_to = buffer;
	str_buffer = buffer;
	str_buffer += sizeof(**pw_to);
	nfsutil_copy_passwd(*pw_to, pw_from, str_buffer);
	return 0;
}

struct group *nfsutil_copy_group(
		struct       group *grp_to,
		const struct group *grp_from,
		char *string_buffer
	)
{
	char *cursor = string_buffer;

	// Ensure that any gaps or unused portions of the struct are filled
	// with something predictable.
	memset(grp_to, 0, sizeof(*grp_to));

	// Now do the deep copy.
	grp_to->gr_name  = buffered_copy(&cursor, grp_from->gr_name);
	grp_to->gr_gid   = grp_from->gr_gid;

	// Members array...
	if ( grp_from->gr_mem == NULL )
		grp_to->gr_mem = NULL;
	else
	{
		char **members_from = grp_from->gr_mem;
		char **members_to   = (char**)cursor;

		// Allocate the array by placing the cursor at the end of the array.
		// The "+ 1" is to allocate room for the NULL element at the end.
		size_t len = 0;
		while ( members_from[len] != NULL )
			len++;

		cursor = (char*)((members_to + len) + 1);

		// Now that the array is allocated, allocate and copy all of the
		// strings while populating the array elements with pointers to
		// those string copies.
		size_t i;
		for ( i = 0; i < len; i++ )
			members_to[i] = buffered_copy(&cursor, members_from[i]);
		members_to[len] = NULL;

		grp_to->gr_mem = members_to;
	}

	return grp_to;
}

int nfsutil_clone_group(
		struct       group **grp_to,
		const struct group *grp_from
	)
{
	if ( grp_from == NULL )
	{
		*grp_to = NULL;
		return 0;
	}

	size_t alloc_size = nfsutil_group_total_size(grp_from);
	char *str_buffer;
	void *buffer = malloc(alloc_size);
	if ( buffer == NULL )
	{
		*grp_to = NULL;
		return ENOMEM;
	}

	*grp_to = buffer;
	str_buffer = buffer;
	str_buffer += sizeof(**grp_to);
	nfsutil_copy_group(*grp_to, grp_from, str_buffer);
	return 0;
}


const struct nfsutil_passwd_ints
	nfsutil_passwd_ints_init = {
		.uid = (uid_t)(-1),
		.gid = (gid_t)(-1),
		.err = 0
	};


const struct nfsutil_group_ints
	nfsutil_group_ints_init = {
		.gid = (gid_t)(-1),
		.err = 0
	};

// Calls the appropriate `getpw***_r` function according to `key` and `key_is_name`.
// The returned struct has the `uid` and `gid` fields set according to whatever
// is found using `getpw***_r`, or are set to (uid_t)(-1) or (gid_t)(-1) if
// the record was not found. The return value's `err` field will be set to
// whatever `getpw***_r` returned, and `found` will be set to 0 if the record
// was not found or 1 if the record was found. The caller should not use the
// `uid` and `gid` fields if the returned struct's `err` field is non-zero or
// its `found` field is 0.
//
// If the caller passes a non-NULL value for `full_results`, this function will
// set `*full_results` to either the `passwd` struct returned by the `getpw***_r`
// function, or to NULL if the record was not found or an error occurred during
// the call.
//
static struct nfsutil_passwd_ints
	nfsutil_getpwxxx_r(struct passwd **full_results, union pwgrp_key key, uint8_t key_is_name)
{
	char    bufptr[PASSWD_STACKMEM_SIZE_HINT];
	size_t  buflen = PASSWD_STACKMEM_SIZE_HINT;
	struct  nfsutil_passwd_query  passwd_query;
	struct  passwd                *pw_tmp = NULL;

	nfsutil_pw_query_init(&passwd_query, bufptr, buflen);

	int err;
	if ( key_is_name )
		err = nfsutil_pw_query_call_getpwnam_r(&passwd_query, key.as_name);
	else
		err = nfsutil_pw_query_call_getpwuid_r(&passwd_query, key.as_uid);

	pw_tmp = nfsutil_pw_query_result(&passwd_query);

	// Populate the full_results if the caller requested them.
	if ( full_results != NULL ) // true if caller requires these results
	{
		// We won't worry about `pw_tmp` being NULL or `err` being non-zero
		// because `nfsutil_clone_passwd` effectively becomes a no-op under such conditions.

		// The caller will be responsible for calling `free` on `*full_results`.
		int oom = nfsutil_clone_passwd(full_results, pw_tmp);
		if ( oom ) // Only ENOMEM should be possible.
			err = oom;
		// Any errors in nfsutil_clone_passwd will set `*full_results` to NULL.
	}

	// Populate the returnable results structure.
	struct  nfsutil_passwd_ints   pw_ints = nfsutil_passwd_ints_init;
	int found = 0;
	if ( pw_tmp ) {
		pw_ints.uid = pw_tmp->pw_uid;
		pw_ints.gid = pw_tmp->pw_gid;
		found = 1;
	}

	if ( err == 0 && !found ) // No errors, it just wasn't found.
		pw_ints.err = ENOENT;
	else
		pw_ints.err = err;

	// It is always safe to call the cleanup function as long as we're done
	// with the query object.
	nfsutil_pw_query_cleanup(&passwd_query);

	return pw_ints;
}

struct nfsutil_passwd_ints
	nfsutil_getpwnam_ints(const char *user_name)
{
	int key_is_name = 1;
	union pwgrp_key  key;
	key.as_name = user_name;
	return nfsutil_getpwxxx_r(NULL, key, key_is_name);
}

struct nfsutil_passwd_ints
	nfsutil_getpwuid_ints(uid_t uid)
{
	int key_is_name = 0;
	union pwgrp_key  key;
	key.as_uid = uid;
	return nfsutil_getpwxxx_r(NULL, key, key_is_name);
}

int nfsutil_getpwnam_struct(struct passwd **pw, const char *user_name)
{
	int key_is_name = 1;
	union pwgrp_key  key;
	key.as_name = user_name;

	struct nfsutil_passwd_ints  pw_ints =
		nfsutil_getpwxxx_r(pw, key, key_is_name);

	return pw_ints.err;
}

int nfsutil_getpwuid_struct(struct passwd **pw,  uid_t uid)
{
	int key_is_name = 0;
	union pwgrp_key  key;
	key.as_uid = uid;

	struct nfsutil_passwd_ints  pw_ints =
		nfsutil_getpwxxx_r(pw, key, key_is_name);

	return pw_ints.err;
}

// Calls the appropriate `getgr***_r` function according to `key` and `key_is_name`.
// The returned struct has its `gid` field set according to whatever is found
// using `getgr***_r`, or is set to (gid_t)(-1) if the record was not found.
// The return value's `err` field will be set to whatever `getgr***_r` returned,
// and `found` will be set to 0 if the record was not found or 1 if the record
// was found. The caller should not use the `gid` field if the returned struct's
// `err` field is non-zero or its `found` field is 0.
//
// If the caller passes a non-NULL value for `full_results`, this function will
// set `*full_results` to either the `group` struct returned by the `getgr***_r`
// function, or to NULL if the record was not found or an error occurred during
// the call.
//
static struct nfsutil_group_ints
	nfsutil_getgrxxx_r(struct group **full_results, union pwgrp_key key, uint8_t key_is_name)
{
	char    bufptr[GROUP_STACKMEM_SIZE_HINT];
	size_t  buflen = GROUP_STACKMEM_SIZE_HINT;
	struct  nfsutil_group_query  group_query;
	struct  group                *grp_tmp = NULL;

	nfsutil_grp_query_init(&group_query, bufptr, buflen);

	int err;
	if ( key_is_name )
		err = nfsutil_grp_query_call_getgrnam_r(&group_query, key.as_name);
	else
		err = nfsutil_grp_query_call_getgrgid_r(&group_query, key.as_gid);

	grp_tmp = nfsutil_grp_query_result(&group_query);

	// Populate the full_results if the caller requested them.
	if ( full_results != NULL ) // true if caller requires these results
	{
		// We won't worry about `grp_tmp` being NULL or `err` being non-zero
		// because `nfsutil_clone_group` effectively becomes a no-op under such conditions.

		// The caller will be responsible for calling `free` on `*full_results`.
		int oom = nfsutil_clone_group(full_results, grp_tmp);
		if ( oom ) // Only ENOMEM should be possible.
			err = oom;
		// Any errors in nfsutil_clone_group will set `*full_results` to NULL.
	}

	// Populate the returnable results structure.
	struct  nfsutil_group_ints   grp_ints = nfsutil_group_ints_init;
	int found = 0;
	if ( grp_tmp ) {
		grp_ints.gid = grp_tmp->gr_gid;
		found = 1;
	}

	if ( err == 0 && !found ) // No errors, it just wasn't found.
		grp_ints.err = ENOENT;
	else
		grp_ints.err = err;

	// It is always safe to call the cleanup function as long as we're done
	// with the query object.
	nfsutil_grp_query_cleanup(&group_query);

	return grp_ints;
}

struct nfsutil_group_ints
	nfsutil_getgrnam_ints(const char *group_name)
{
	int key_is_name = 1;
	union pwgrp_key  key;
	key.as_name = group_name;
	return nfsutil_getgrxxx_r(NULL, key, key_is_name);
}

struct nfsutil_group_ints
	nfsutil_getgrgid_ints(gid_t gid)
{
	int key_is_name = 0;
	union pwgrp_key  key;
	key.as_gid = gid;
	return nfsutil_getgrxxx_r(NULL, key, key_is_name);
}

int nfsutil_getgrnam_struct(struct group **grp, const char *group_name)
{
	int key_is_name = 1;
	union pwgrp_key  key;
	key.as_name = group_name;

	struct nfsutil_group_ints  grp_ints =
		nfsutil_getgrxxx_r(grp, key, key_is_name);

	return grp_ints.err;
}

int nfsutil_getgrgid_struct(struct group **grp,  gid_t gid)
{
	int key_is_name = 0;
	union pwgrp_key  key;
	key.as_gid = gid;

	struct nfsutil_group_ints  grp_ints =
		nfsutil_getgrxxx_r(grp, key, key_is_name);

	return grp_ints.err;
}

// See header for documentation.
int nfsutil_getgrouplist_by_uid(
		uid_t user_uid, gid_t user_gid,
		gid_t *groups, int *ngroups
	)
{
	char    bufptr[PASSWD_STACKMEM_SIZE_HINT];
	size_t  buflen = PASSWD_STACKMEM_SIZE_HINT;
	struct  nfsutil_passwd_query  passwd_query;
	struct  passwd                *pw = NULL;

	nfsutil_pw_query_init(&passwd_query, bufptr, buflen);

	int err = nfsutil_pw_query_call_getpwuid_r(&passwd_query, user_uid);
	pw = nfsutil_pw_query_result(&passwd_query);

	if ( !err && pw == NULL )
		err = ENOENT;
	else
	if ( !err && pw != NULL ) {
		const char *user_name = pw->pw_name;
		if ( user_gid == (gid_t)(-1) )
			user_gid = pw->pw_gid;

		int rc = getgrouplist(user_name, user_gid, groups, ngroups);
		if ( rc < 0 )
			err = ERANGE;

		// The caller is responsible for checking the outgoing results
		// given by the arguments.
	}

	nfsutil_pw_query_cleanup(&passwd_query);

	return err;
}


// This is like strlen, except that it doubles the cost of every '%'
// character it encounters to compensate for situations where such characters
// need to be escaped ("%" -> "%%") to perform double-expansion mitigation.
//
static size_t format_expansion_length(const char *str)
{
	size_t result = 0;
	for ( size_t i = 0;; i++ )
	{
		char ch = str[i];
		if ( ch == '\0' )
			break;
		else
		if ( ch == '%' )
			result += 2;
		else
			result++;
	}
	return result;
}

void test__format_expansion_length(void)
{
	assert(format_expansion_length("") == 0);
	assert(format_expansion_length("a") == 1);
	assert(format_expansion_length(".") == 1);
	assert(format_expansion_length("%") == 2);
	assert(format_expansion_length("aa") == 2);
	assert(format_expansion_length("a%") == 3);
	assert(format_expansion_length("%s") == 3);
	assert(format_expansion_length("%%") == 4);
	assert(format_expansion_length("%a%a") == 6);
	assert(format_expansion_length("a%a%") == 6);
	assert(format_expansion_length("aaaa") == 4);
}

// Returns: The size of the new string, not including the nul-terminating character.
static size_t escape_fmtspec_inplace(char *bufptr, size_t buflen)
{
	ssize_t i; // Index on `bufptr` before substitution.
	ssize_t j; // Index on `bufptr` after substitution.

	size_t newlen = 0;

	if ( bufptr == NULL || buflen == 0 )
		return 0;

	ssize_t bufend = buflen-1; // Last valid char index.

	// Pass 1: count the replacements and find the '\0' byte.
	i = 0; j = 0;
	while(j < bufend)
	{
		char ch = bufptr[i];
		if ( ch == '\0' )
			break;

		if ( ch == '%' ) {
			if ( j == bufend-2 ) {
				// Allocate space for "%%\0" if near end.
				bufptr[++i] = '\0';
				j += 2;
				break;
			}
			else
			if ( j == bufend-1 ) {
				// There's no room for "%%\0", so drop this '%'.
				// Just make sure we can put "\0".
				bufptr[i] = '\0';
				break;
			}
			else {
				// The end is not near.
				i++;
				j += 2;
			}
		} else {
			// Normalcy.
			i++; j++;
		}
	}

	newlen = j;

	// Pass 2: work backwards to shift everything into its final place while
	//   filling the gaps with the substituted characters.
	while ( j > i )
	{
		char ch = bufptr[i--];
		bufptr[j--] = ch;
		if ( ch == '%' )
			bufptr[j--] = '%';
	}
	// assert( i == j );
	// assert( i >= 0 );

	return newlen;
}

static char *escape_fmtspec(const char *str, char *bufptr, size_t buflen)
{
	size_t sz = strlen(str)+1;
	if ( sz > buflen )
		sz = buflen;
	memcpy(bufptr, str, sz);
	if ( sz == buflen )
		bufptr[sz-1] = '\0';
	(void)escape_fmtspec_inplace(bufptr, buflen);
	return bufptr;
}

void test__escape_fmtspec_inplace(void)
{
	char   p[16];
	size_t l = 16;

	assert(escape_fmtspec_inplace(NULL,0) == 0);
	assert(escape_fmtspec_inplace(NULL,1) == 0);
	assert(escape_fmtspec_inplace(p,   0) == 0);
	assert(strcmp(escape_fmtspec("",   p, l), "")     == 0);
	assert(strcmp(escape_fmtspec("a",  p, l), "a")    == 0);
	assert(strcmp(escape_fmtspec(".",  p, l), ".")    == 0);
	assert(strcmp(escape_fmtspec("a",  p, 1), "")     == 0);
	assert(strcmp(escape_fmtspec("%",  p, l), "%%")   == 0);
	assert(strcmp(escape_fmtspec("%",  p, 2), "")     == 0);
	assert(strcmp(escape_fmtspec("%",  p, 3), "%%")   == 0);
	assert(strcmp(escape_fmtspec("aa", p, l), "aa")   == 0);
	assert(strcmp(escape_fmtspec("aa", p, 2), "a")    == 0);
	assert(strcmp(escape_fmtspec("aa", p, 3), "aa")   == 0);
	assert(strcmp(escape_fmtspec("a%", p, l), "a%%")  == 0);
	assert(strcmp(escape_fmtspec("a%", p, 2), "a")    == 0);
	assert(strcmp(escape_fmtspec("a%", p, 3), "a")    == 0);
	assert(strcmp(escape_fmtspec("a%", p, 4), "a%%")  == 0);
	assert(strcmp(escape_fmtspec("%s", p, l), "%%s")  == 0);
	assert(strcmp(escape_fmtspec("%s", p, 2), "")     == 0);
	assert(strcmp(escape_fmtspec("%s", p, 3), "%%")   == 0);
	assert(strcmp(escape_fmtspec("%s", p, 4), "%%s")  == 0);
	assert(strcmp(escape_fmtspec("%%", p, l), "%%%%") == 0);
	assert(strcmp(escape_fmtspec("%%", p, 2), "")     == 0);
	assert(strcmp(escape_fmtspec("%%", p, 3), "%%")   == 0);
	assert(strcmp(escape_fmtspec("%%", p, 4), "%%")   == 0);
	assert(strcmp(escape_fmtspec("%%", p, 5), "%%%%") == 0);
	assert(strcmp(escape_fmtspec("%a%a", p, l), "%%a%%a") == 0);
	assert(strcmp(escape_fmtspec("a%a%", p, l), "a%%a%%") == 0);
	assert(strcmp(escape_fmtspec("aaaa", p, l), "aaaa")   == 0);
}

#ifndef IDMAP_LOG
#define IDMAP_LOG(lvl, args)  do { (printf)args; fputc('\n', stdout); } while (0)
#endif

// `buflen` is the length of the buffer needed to hold the result of formatting
// `fmtstr` with the arguments that follow it in this parameter list.
static void nfsidmap_print_oom_error(
		size_t      buflen,
		const char  *fmtstr,
		const char  *in_function,
		const char  *key_name,
		const char  *key_value,
		const char  *rel_entry_before,
		const char  *rel_entry_value,
		const char  *rel_entry_after
	)
{
	// (Carefully) Exploit VLAs to avoid heap allocation during string formatting.
	char bufptr[buflen];

	// Use snprintf to do formatting. Pray that it doesn't malloc for no reason.
	ssize_t return_code =
		snprintf(bufptr, buflen, fmtstr,
			in_function, key_name, key_value,
			rel_entry_before, rel_entry_value, rel_entry_after);

	// If snprintf returned an error code, we are in no condition to handle it.
	// But we do want to avoid trying to use a potentially b0rked result,
	// so we back off if there's an error code at all.
	if ( return_code <= 0 )
		return;

	// The size of the already-formatted string, including the '\0' byte
	// at the end.
	size_t string_length = return_code+1;

	// If string_length > buflen, it means that the full format expansion
	// would be larger than our buffer, so snprintf had to stop.
	// We could give up due to that error OR... we could just truncate
	// the thing and hope for the best.
	// This is all best-effort anyways, so hell, why not.
	// Basically, it gives us best odds of informing the user about this.
	// (Also this shouldn't happen if the caller correctly calculated the
	// necessary final string length.)
	if ( string_length > buflen ) {
		bufptr[buflen-1] = '\0';
		string_length = buflen;
	}

	// Double up (escape) any formatter characters ('%') that are left
	// in the string, because we've already formatted it and IDMAP_LOG
	// is /also/ formatting. Ideally we wouldn't format twice, but
	// it's hard to know if the formatter behind IDMAP_LOG uses
	// malloc or not. With any luck, it will see a string with no
	// substitutions to make, and will just pass it through to
	// whatever output buffer awaits it.
	(void)escape_fmtspec_inplace(bufptr, buflen);
	char *errmsg = bufptr;

#if defined(_MSC_VER)
#pragma warning( push )
#pragma warning( disable : 4774 )
#elif defined(__GNUC__) || defined(__clang__)
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wformat-security"
#endif
	// If IDMAP_LOG tries to heap-allocate, it might fail, and we'd be
	// bumming regardless. But at least we tried. The worse that could
	// happen is that malloc returns NULL again.
	IDMAP_LOG(0, (errmsg));
#if defined(_MSC_VER)
#pragma warning( pop )
#elif defined(__GNUC__) || defined(__clang__)
#pragma GCC diagnostic pop
#endif
}

// See header for documentation.
//
// `nfsidmap_print_pwgrp_error` prints error messages resulting from
// `get**nam_r` and `get***id_r` functions, (usually) using the following format:
// "${in_function}: Error happened while looking up ${key_name} '${key_value}'"
//     "${rel_entry_before}${rel_entry_value}${rel_entry_after}': <error message>"
void nfsidmap_print_pwgrp_error(
		ssize_t     err,
		const char  *in_function,
		const char  *key_name, // Ex: "user name", "local name", "uid", "gid", etc.
		const char  *key_value,
		const char  *rel_entry_before, // Ex: " for Static entry with name '", " in domain '", etc
		const char  *rel_entry_value,  // Ex: "foo@bar", "your_domain_here" 
		const char  *rel_entry_after   // Ex: "'", or put (NULL|"") if you're not using a related entry.
	)
{
	if ( rel_entry_before == NULL )
		rel_entry_before = "";
	if ( rel_entry_value == NULL )
		rel_entry_value = "";
	if ( rel_entry_after == NULL )
		rel_entry_after = "";

	// Print errors.
	if ( err == ENOENT || err == -ENOENT )
		IDMAP_LOG(0, ("%s: "
			"Error while looking up %s '%s'%s%s%s: not found",
			in_function, key_name, key_value,
			rel_entry_before, rel_entry_value, rel_entry_after));
	else
	if ( err == EIO || err == -EIO )
		IDMAP_LOG(0, ("%s: "
			"Error while looking up %s '%s'%s%s%s: I/O error.",
			in_function, key_name, key_value,
			rel_entry_before, rel_entry_value, rel_entry_after));
	else
	if ( err == EINTR || err == -EINTR )
		IDMAP_LOG(0, ("%s: "
			"Error: a signal was caught while looking up %s '%s'%s%s%s: ",
			in_function, key_name, key_value,
			rel_entry_before, rel_entry_value, rel_entry_after));
	else
	if ( err == EMFILE || err == -EMFILE )
		IDMAP_LOG(0, ("%s: "
			"Error while looking up %s '%s'%s%s%s: "
			"All file descriptors available to the process are currently open.",
			in_function, key_name, key_value,
			rel_entry_before, rel_entry_value, rel_entry_after));
	else
	if ( err == ENFILE || err == -ENFILE )
		IDMAP_LOG(0, ("%s: "
			"Error while looking up %s '%s'%s%s%s: "
			"The maximum allowable number of files is currently open in the system.",
			in_function, key_name, key_value,
			rel_entry_before, rel_entry_value, rel_entry_after));
	else
	if ( err == ENOMEM || err == -ENOMEM )
	{
		const char *errfmtstr = "%s: "
			"Error while looking up %s '%s'%s%s%s: "
			"Out of memory (OOM); memory allocation failed; no memory.";

		size_t fmtmemsize = format_expansion_length(errfmtstr);
		fmtmemsize += format_expansion_length(in_function);
		fmtmemsize += format_expansion_length(key_name);
		fmtmemsize += format_expansion_length(key_value);
		fmtmemsize += format_expansion_length(rel_entry_before);
		fmtmemsize += format_expansion_length(rel_entry_value);
		fmtmemsize += format_expansion_length(rel_entry_after);
		fmtmemsize += 1; // Make sure there's room for '\0'.

		nfsidmap_print_oom_error(fmtmemsize, errfmtstr,
			in_function, key_name, key_value,
			rel_entry_before, rel_entry_value, rel_entry_after);
	}
	else
	if ( err == ERANGE || err == -ERANGE )
		// Notably, this branch should never execute if (passwd|group)_query
		// objects were used to call the `get*****_r` function, as that function
		// will always find an appropriate buffer size that is large enough
		// for the lookup to complete.
		IDMAP_LOG(0, ("%s: "
			"Error while looking up %s '%s'%s%s%s: "
			"Insufficient storage was supplied to contain the data to be "
			"referenced by the resulting passwd or group structure.",
			in_function, key_name, key_value,
			rel_entry_before, rel_entry_value, rel_entry_after));
	else
	if ( err != 0 )
	{
		// Calling strerror is undesirable (thread safety and such), but this
		// branch should not get executed anyways (we have exhausted all error
		// codes returned by getpwnam_r/nfsutil_pw_query_call_getpwnam_r),
		// and if execution does reach this point, we are getting desparate
		// enough to risk it.
		const char *errmsg = strerror(err);
		IDMAP_LOG(0, ("%s: "
			"Unknown error while looking up %s '%s'%s%s%s. "
			"%s%s",
			in_function, key_name, key_value,
			rel_entry_before, rel_entry_value, rel_entry_after,
			errmsg ? " strerror reports this: " : "",
			errmsg ? errmsg : ""));
	}
}
