/* Copyright (C) 2016 Open Information Security Foundation
 *
 * You can copy, redistribute or modify this Program under the terms of
 * the GNU General Public License version 2 as published by the Free
 * Software Foundation.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * version 2 along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA
 * 02110-1301, USA.
 */

/**
 * \file
 *
 * \author Vadym Malakhatko <v.malakhatko@sirinsoftware.com>
 */

#ifndef __UTIL_LOG_STENOGRAPHER_H__
#define __UTIL_LOG_STENOGRAPHER_H__

#ifdef HAVE_LIBCURL
#include <curl/curl.h>
#include "alert-stenographer.h"

int SCConfLogOpenStenographer(ConfNode *, void *);
void LogStenographerFileWrite(void *lf_ctx, const char *file_path, const char* start_time, const char* end_time);

#endif /* HAVE_LIBHIREDIS */
#endif /* __UTIL_LOG_REDIS_H__ */
