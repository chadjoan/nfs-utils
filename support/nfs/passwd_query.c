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

#include <errno.h>
#include <grp.h>
#include <pwd.h>
#include <stddef.h>
#include <stdint.h>
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
		char *cursor_before = cursor;
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
