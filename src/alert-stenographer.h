/* Copyright (C) 2007-2014 Open Information Security Foundation
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

#ifndef __ALERT_STENOGRAPHER_H__
#define __ALERT_STENOGRAPHER_H__


#include "util-logopenfile.h"
#include "output.h"

/**
 * This holds global structures and variables. 
 */
typedef struct AlertStenographerCtx_ {
    LogFileCtx *logfile_ctx;
    char *pcap_dir;
    uint32_t before_time;
    uint32_t after_time;
    int compression;
    int no_overlapping;
    int cleanup;
    char *cleanup_script;
    unsigned long cleanup_expiry_time;
    unsigned long min_disk_space_left;
} AlertStenographerCtx;

void AlertStenographerRegister(void);
OutputInitResult AlertStenographerInitCtx(ConfNode *);

#endif /* __ALERT_STENOGRAPHER_H__ */

