/* -*- Mode: C; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */

/*  Fluent Bit
 *  ==========
 *  Copyright (C) 2015-2024 The Fluent Bit Authors
 *
 *  Licensed under the Apache License, Version 2.0 (the "License");
 *  you may not use this file except in compliance with the License.
 *  You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 *  Unless required by applicable law or agreed to in writing, software
 *  distributed under the License is distributed on an "AS IS" BASIS,
 *  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *  See the License for the specific language governing permissions and
 *  limitations under the License.
 */

/*
 * The following SDS interface is a clone/strip-down version of the original
 * SDS library created by Antirez at https://github.com/antirez/sds.
 */

#ifndef FLB_SDS_H
#define FLB_SDS_H

#include <fluent-bit/flb_info.h>
#include <fluent-bit/flb_macros.h>
#include <stdlib.h>
#include <string.h>
#include <inttypes.h>

#define FLB_SDS_HEADER_SIZE (sizeof(uint64_t) + sizeof(uint64_t))

typedef char *flb_sds_t;

#pragma pack(push, 1)
struct flb_sds {
    uint64_t len;        /* used */
    uint64_t alloc;      /* excluding the header and null terminator */
    char buf[];
};
#pragma pack(pop)

#define FLB_SDS_HEADER(s)  ((struct flb_sds *) (s - FLB_SDS_HEADER_SIZE))

/*
 * Returns the current length of the SDS string.
 * Return value: Current length in bytes, always valid for non-NULL SDS.
 * Memory management: No memory allocation/deallocation.
 */
static inline size_t flb_sds_len(flb_sds_t s)
{
    return (size_t) FLB_SDS_HEADER(s)->len;
}

/*
 * Checks if the SDS string is empty (length is zero).
 * Return value: FLB_TRUE if empty, FLB_FALSE if not empty.
 * Memory management: No memory allocation/deallocation.
 */
static inline int flb_sds_is_empty(flb_sds_t s)
{
    if (flb_sds_len(s) == 0) {
        return FLB_TRUE;
    }

    return FLB_FALSE;
}

/*
 * Sets the length of the SDS string. Does not modify the actual buffer content.
 * Return value: None (void function).
 * Memory management: No memory allocation/deallocation. Caller must ensure 
 * the buffer has valid content up to the specified length.
 */
static inline void flb_sds_len_set(flb_sds_t s, size_t len)
{
    FLB_SDS_HEADER(s)->len = len;
}

/*
 * Returns the allocated capacity of the SDS buffer (excluding header and null terminator).
 * Return value: Allocated capacity in bytes, always valid for non-NULL SDS.
 * Memory management: No memory allocation/deallocation.
 */
static inline size_t flb_sds_alloc(flb_sds_t s)
{
    return (size_t) FLB_SDS_HEADER(s)->alloc;
}

/*
 * Returns the available space in the SDS buffer for additional data.
 * Return value: Available bytes that can be appended without reallocation.
 * Memory management: No memory allocation/deallocation.
 */
static inline size_t flb_sds_avail(flb_sds_t s)
{
    struct flb_sds *h;

    h = FLB_SDS_HEADER(s);
    return (size_t) (h->alloc - h->len);
}

/*
 * Compares SDS string with a C string (case-sensitive).
 * Return value: 0 if equal, -1 if lengths differ, or result of strncmp if lengths match.
 * Memory management: No memory allocation/deallocation.
 */
static inline int flb_sds_cmp(flb_sds_t s, const char *str, int len)
{
    if (flb_sds_len(s) != len) {
        return -1;
    }

    return strncmp(s, str, len);
}

/*
 * Compares SDS string with a C string (case-insensitive).
 * Return value: 0 if equal, -1 if lengths differ, or result of strncasecmp if lengths match.
 * Memory management: No memory allocation/deallocation.
 */
static inline int flb_sds_casecmp(flb_sds_t s, const char *str, int len)
{
    if (flb_sds_len(s) != len) {
        return -1;
    }

    return strncasecmp(s, str, len);
}

/*
 * Creates a new SDS string from a null-terminated C string.
 * Return value: New SDS string, or NULL on memory allocation failure.
 * Memory management: Caller must call flb_sds_destroy() to free returned SDS.
 */
flb_sds_t flb_sds_create(const char *str);

/*
 * Creates a new SDS string from a buffer with specified length.
 * Return value: New SDS string, or NULL on memory allocation failure.
 * Memory management: Caller must call flb_sds_destroy() to free returned SDS.
 */
flb_sds_t flb_sds_create_len(const char *str, int len);

/*
 * Creates a new empty SDS string with specified initial capacity.
 * Return value: New empty SDS string, or NULL on memory allocation failure.
 * Memory management: Caller must call flb_sds_destroy() to free returned SDS.
 */
flb_sds_t flb_sds_create_size(size_t size);

/*
 * Trims whitespace from both ends of SDS string, modifying it in-place.
 * Return value: New length after trimming, or -1 on error.
 * Memory management: No memory allocation/deallocation, modifies existing SDS.
 */
int flb_sds_trim(flb_sds_t s);

/*
 * Concatenates data to the end of an SDS string, reallocating if necessary.
 * Return value: Updated SDS string (may be different pointer), or NULL on failure.
 * Memory management: May reallocate SDS. Always use returned pointer.
 */
flb_sds_t flb_sds_cat(flb_sds_t s, const char *str, int len);

/*
 * Concatenates data to SDS string with character escaping using escape table.
 * Return value: Updated SDS string (may be different pointer), or NULL on failure.
 * Memory management: May reallocate SDS. Always use returned pointer.
 */
flb_sds_t flb_sds_cat_esc(flb_sds_t s, const char *str, int len,
                                       char *esc, size_t esc_size);

/*
 * Concatenates UTF-8 data to SDS string, handling encoding properly.
 * Return value: Updated SDS string (may be different pointer), or NULL on failure.
 * Memory management: May reallocate SDS. Updates sds pointer. Always use returned pointer.
 */
flb_sds_t flb_sds_cat_utf8(flb_sds_t *sds, const char *str, int len);

/*
 * Safe concatenation that updates the SDS pointer automatically.
 * Return value: 0 on success, -1 on failure.
 * Memory management: May reallocate SDS. Updates buf pointer automatically.
 */
int flb_sds_cat_safe(flb_sds_t *buf, const char *str, int len);

/*
 * Increases the allocated capacity of an SDS string by specified bytes.
 * Return value: Updated SDS string (may be different pointer), or NULL on failure.
 * Memory management: Reallocates SDS. Always use returned pointer.
 */
flb_sds_t flb_sds_increase(flb_sds_t s, size_t len);

/*
 * Copies data into an SDS string, replacing current content.
 * Return value: Updated SDS string (may be different pointer), or NULL on failure.
 * Memory management: May reallocate SDS. Always use returned pointer.
 */
flb_sds_t flb_sds_copy(flb_sds_t s, const char *str, int len);

/*
 * Destroys an SDS string and frees all associated memory.
 * Return value: None (void function).
 * Memory management: Frees the SDS and its header. SDS pointer becomes invalid.
 */
void flb_sds_destroy(flb_sds_t s);

/*
 * Appends formatted text to an SDS string using printf-style formatting.
 * Return value: Updated SDS string (may be different pointer), or NULL on failure.
 * Memory management: May reallocate SDS. Updates sds pointer. Always use returned pointer.
 */
flb_sds_t flb_sds_printf(flb_sds_t *sds, const char *fmt, ...) FLB_FORMAT_PRINTF(2, 3);

/*
 * Formatted print into SDS with automatic buffer expansion as needed.
 * Return value: Number of characters written, or -1 on failure.
 * Memory management: May reallocate SDS. Updates str pointer automatically.
 */
int flb_sds_snprintf(flb_sds_t *str, size_t size, const char *fmt, ...) FLB_FORMAT_PRINTF(3, 4);

#endif
