/* Copyright (C) 2007-2020 Open Information Security Foundation
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
 *
 * Logs alerts in a line based text format compatible to Snort's
 * alert_fast format.
 */

#include "suricata-common.h"
#include "debug.h"
#include "detect.h"
#include "flow.h"
#include "conf.h"

#include "threads.h"
#include "tm-threads.h"
#include "threadvars.h"
#include "util-debug.h"

#include "util-unittest.h"
#include "util-unittest-helper.h"

#include "detect-parse.h"
#include "detect-engine.h"
#include "detect-engine-mpm.h"
#include "detect-reference.h"
#include "util-classification-config.h"

#include "output.h"
#include "alert-stenographer.h"

#include "util-privs.h"
#include "util-print.h"
#include "util-proto-name.h"
#include "util-optimize.h"
#include "util-logopenfile.h"
#include "util-time.h"
#include "util-misc.h"
#include "util-log-stenographer.h"

#define DEFAULT_LOG_FILENAME "stenographer.log"

#define MODULE_NAME "AlertStenographer"

/* The largest that size allowed for one alert string. */
#define MAX_STENOGRAPHER_ALERT_SIZE 2048
/* The largest alert buffer that will be written at one time, possibly
 * holding multiple alerts. */
#define MAX_STENOGRAPHER_BUFFER_SIZE (2 * MAX_STENOGRAPHER_ALERT_SIZE)


TmEcode AlertStenographerThreadInit(ThreadVars *, const void *, void **);
TmEcode AlertStenographerThreadDeinit(ThreadVars *, void *);
void AlertStenographerRegisterTests(void);
static void AlertStenographerDeInitCtx(OutputCtx *);

int AlertStenographerCondition(ThreadVars *tv, const Packet *p);
int AlertStenographer(ThreadVars *tv, void *data, const Packet *p);

void AlertStenographerRegister(void)
{
    OutputRegisterPacketModule(LOGGER_ALERT_STENOGRAPHER, MODULE_NAME, "alert-stenographer",
        AlertStenographerInitCtx, AlertStenographer, AlertStenographerCondition,
        AlertStenographerThreadInit, AlertStenographerThreadDeinit, NULL);
    AlertStenographerRegisterTests();
}

typedef struct AlertStenographerThread_ {
    /** LogFileCtx has the pointer to the file and a mutex to allow multithreading */
    AlertStenographerCtx* ctx;
} AlertStenographerThread;

int AlertStenographerCondition(ThreadVars *tv, const Packet *p)
{
    return (p->alerts.cnt ? TRUE : FALSE);
}

static inline void AlertStenographerOutputAlert(AlertStenographerThread *aft, char *buffer,
                                           int alert_size)
{
    /* Output the alert string and count alerts. Only need to lock here. */
    aft->ctx->logfile_ctx->Write(buffer, alert_size, aft->ctx->logfile_ctx);
}

#include <dirent.h>
#include <sys/stat.h>

int CleanupOldest (const char *dirname, time_t expiry, const char * script_before_cleanup) {

    int script_run = 0;
    DIR * directory; 
    struct stat buf;
    struct dirent *entry;
    int retcode, num_ents;
    char *filename;
    time_t now;

    num_ents = 0; /* Number of entries left in current directory */

    /* Open target directory */
    directory = opendir(dirname);
    if (directory == NULL) {
        fprintf(stderr, "%s: ", dirname);
        perror ("Unable to read directory");
        return -1;
    }
    if ((chdir(dirname) == -1)) {
        fprintf(stderr, "%s: ", dirname);
        perror("chdir failed");
        return -1;
    }
  
    /* Process directory contents, deleting all regular files with
     * mtimes more than expiry seconds in the past */

    now = time(NULL);  
    while ((entry = readdir(directory))) {
        filename = entry->d_name;

        /* Ignore '.' and '..' */
        if (! strcmp(filename,".")  ) { continue; }
        if (! strcmp(filename,"..") ) { continue; }
    
        //num_ents ++; /* New entry, count it */
    
        retcode = lstat(filename, &buf);
        if (retcode == -1) {
            fprintf(stderr, "%s: ", filename);
            perror("stat failed");
            continue;
        }

        if (S_ISREG(buf.st_mode) || S_ISLNK(buf.st_mode)) {
            /* File or symlink- check last modification time */
            if ((now - expiry) > buf.st_mtime) {
                unlink (filename);
                if(script_run == 0) {
                    if(script_before_cleanup != NULL) {
                        system(script_before_cleanup);
                    }
                    script_run = 1;
                }

                num_ents ++;
            }
        }
    }
    closedir(directory);
    chdir("..");
    return num_ents;
}

#include <sys/statvfs.h>

unsigned long GetAvailableDiskSpace(const char* path) {
    struct statvfs stat;

  if (statvfs(path, &stat) != 0) {
    // error happens, just quits here
    return -1;
  }

  // the available size is f_bsize * f_bavail
  return stat.f_bsize * stat.f_bavail;
}

static long last_alert_sec;

int SignalStenographer(void *data) {
  
    AlertStenographerThread *aft = (AlertStenographerThread *)data;
    char timebuf[64];

    int size = 0;
    char stenographerPcapAlertFile[64];
    struct timeval signal_time;
    gettimeofday(&signal_time, NULL);
    CreateIsoTimeString(&signal_time, stenographerPcapAlertFile, sizeof(stenographerPcapAlertFile));
    
    CreateTimeString(&signal_time, timebuf, sizeof(timebuf));
    char alert_buffer[MAX_STENOGRAPHER_BUFFER_SIZE];
    PrintBufferData(alert_buffer, &size, MAX_STENOGRAPHER_ALERT_SIZE,
                            "Pcap file was saved after receiving SIGUSR2 %s", stenographerPcapAlertFile);
    AlertStenographerOutputAlert(aft, alert_buffer, size);
        
    struct timeval end_time;
    end_time.tv_sec = signal_time.tv_sec + aft->ctx->after_time;
    end_time.tv_usec = signal_time.tv_usec;
    char end_timebuf[64];
    CreateIsoTimeStringNoMS(&end_time, end_timebuf, sizeof(end_timebuf));
        
    struct timeval start_time;
    start_time.tv_sec = signal_time.tv_sec - aft->ctx->before_time;
    start_time.tv_usec = signal_time.tv_usec;
    if(aft->ctx->no_overlapping) {
        if (start_time.tv_sec < last_alert_sec) {
            start_time.tv_sec = last_alert_sec;
            last_alert_sec = end_time.tv_sec;
        }
    }
    char start_timebuf[64];
    CreateIsoTimeStringNoMS(&start_time, start_timebuf, sizeof(start_timebuf));

    pid_t pid = fork();
    if (pid == 0) {
        if(aft->ctx->cleanup) {
            if(aft->ctx->cleanup_expiry_time) {
                int files_deleted = CleanupOldest(aft->ctx->pcap_dir, aft->ctx->cleanup_expiry_time, aft->ctx->cleanup_script);
                if(files_deleted) {
                    char cleanup_message[MAX_STENOGRAPHER_BUFFER_SIZE];
                    int cleanup_size = 0;
                    PrintBufferData(cleanup_message, &cleanup_size, MAX_STENOGRAPHER_ALERT_SIZE,
                        "%s Cleanup of the folder '%s' is finished, %d file(s) older than %lu seconds were deleted \n", timebuf, aft->ctx->pcap_dir, files_deleted, aft->ctx->cleanup_expiry_time);
                    AlertStenographerOutputAlert(aft, cleanup_message, cleanup_size);
                }
            }

            if(aft->ctx->min_disk_space_left) {
                
            if(aft->ctx->min_disk_space_left > GetAvailableDiskSpace(aft->ctx->pcap_dir)) {
                int files_deleted = CleanupOldest(aft->ctx->pcap_dir, 0, aft->ctx->cleanup_script);
                if(files_deleted) {
                    char cleanup_message[MAX_STENOGRAPHER_BUFFER_SIZE];
                    int cleanup_size = 0;
                    PrintBufferData(cleanup_message, &cleanup_size, MAX_STENOGRAPHER_ALERT_SIZE,
                            "%s Cleanup of the folder '%s' is finished, %d file(s) were deleted, %lu bytes of empty space left \n", timebuf, aft->ctx->pcap_dir, files_deleted, GetAvailableDiskSpace(aft->ctx->pcap_dir));
                    AlertStenographerOutputAlert(aft, cleanup_message, cleanup_size);
                    }
                }
            }
        }

        struct timeval current_time;
        gettimeofday(&current_time, NULL);
        while (current_time.tv_sec < (end_time.tv_sec + 60)) {
            gettimeofday(&current_time, NULL);
            sleep(1);
        }
            
        LogStenographerFileWrite((void *)aft->ctx, stenographerPcapAlertFile, start_timebuf, end_timebuf);
        exit(0);
    }
}


int AlertStenographer(ThreadVars *tv, void *data, const Packet *p)
{
    AlertStenographerThread *aft = (AlertStenographerThread *)data;
    int i;
    char timebuf[64];
    int decoder_event = 0;

    CreateTimeString(&p->ts, timebuf, sizeof(timebuf));

    char stenographerPcapAlertFile[64];
    CreateIsoTimeString(&p->ts, stenographerPcapAlertFile, sizeof(stenographerPcapAlertFile));

    char srcip[46], dstip[46];
    if (PKT_IS_IPV4(p)) {
        PrintInet(AF_INET, (const void *)GET_IPV4_SRC_ADDR_PTR(p), srcip, sizeof(srcip));
        PrintInet(AF_INET, (const void *)GET_IPV4_DST_ADDR_PTR(p), dstip, sizeof(dstip));
    } else if (PKT_IS_IPV6(p)) {
        PrintInet(AF_INET6, (const void *)GET_IPV6_SRC_ADDR(p), srcip, sizeof(srcip));
        PrintInet(AF_INET6, (const void *)GET_IPV6_DST_ADDR(p), dstip, sizeof(dstip));
    } else {
        decoder_event = 1;
    }

    /* Buffer to store the generated alert strings. The buffer is
     * filled with alert strings until it doesn't have room to store
     * another full alert, only then is the buffer written.  This is
     * more efficient for multiple alerts and only slightly slower for
     * single alerts.
     */
    char alert_buffer[MAX_STENOGRAPHER_BUFFER_SIZE];

    char proto[16] = "";
    if (SCProtoNameValid(IP_GET_IPPROTO(p)) == TRUE) {
        strlcpy(proto, known_proto[IP_GET_IPPROTO(p)], sizeof(proto));
    } else {
        snprintf(proto, sizeof(proto), "PROTO:%03" PRIu32, IP_GET_IPPROTO(p));
    }
    uint16_t src_port_or_icmp = p->sp;
    uint16_t dst_port_or_icmp = p->dp;
    if (IP_GET_IPPROTO(p) == IPPROTO_ICMP || IP_GET_IPPROTO(p) == IPPROTO_ICMPV6) {
        src_port_or_icmp = p->icmp_s.type;
        dst_port_or_icmp = p->icmp_s.code;
    }
    for (i = 0; i < p->alerts.cnt; i++) {
        const PacketAlert *pa = &p->alerts.alerts[i];
        if (unlikely(pa->s == NULL)) {
            continue;
        }

        const char *action = "";
        if ((pa->action & ACTION_DROP) && EngineModeIsIPS()) {
            action = "[Drop] ";
        } else if (pa->action & ACTION_DROP) {
            action = "[wDrop] ";
        }

        /* Create the alert string without locking. */
        int size = 0;
        if (likely(decoder_event == 0)) {
            if(aft->ctx->compression) {
                PrintBufferData(alert_buffer, &size, MAX_STENOGRAPHER_ALERT_SIZE,
                            "%s  %s[**] [%" PRIu32 ":%" PRIu32 ":%"
                            PRIu32 "] %s [**] [Classification: %s] [Priority: %"PRIu32"]"
                            " {%s} %s:%" PRIu32 " -> %s:%" PRIu32 " pcapfile: %s.lz4\n", timebuf, action,
                            pa->s->gid, pa->s->id, pa->s->rev, pa->s->msg, pa->s->class_msg, pa->s->prio,
                            proto, srcip, src_port_or_icmp, dstip, dst_port_or_icmp, stenographerPcapAlertFile);
            }
            else{
                PrintBufferData(alert_buffer, &size, MAX_STENOGRAPHER_ALERT_SIZE,
                            "%s  %s[**] [%" PRIu32 ":%" PRIu32 ":%"
                            PRIu32 "] %s [**] [Classification: %s] [Priority: %"PRIu32"]"
                            " {%s} %s:%" PRIu32 " -> %s:%" PRIu32 " pcapfile: %s.pcap\n", timebuf, action,
                            pa->s->gid, pa->s->id, pa->s->rev, pa->s->msg, pa->s->class_msg, pa->s->prio,
                            proto, srcip, src_port_or_icmp, dstip, dst_port_or_icmp, stenographerPcapAlertFile);
            }
        } else {
            if(aft->ctx->compression) {
            PrintBufferData(alert_buffer, &size, MAX_STENOGRAPHER_ALERT_SIZE, 
                            "%s  %s[**] [%" PRIu32 ":%" PRIu32
                            ":%" PRIu32 "] %s [**] [Classification: %s] [Priority: "
                            "%" PRIu32 "] pcapfile: %s.lz4 [**] [Raw pkt: ", timebuf, action, pa->s->gid,
                            pa->s->id, pa->s->rev, pa->s->msg, pa->s->class_msg, pa->s->prio, stenographerPcapAlertFile);
            }else {
                PrintBufferData(alert_buffer, &size, MAX_STENOGRAPHER_ALERT_SIZE, 
                            "%s  %s[**] [%" PRIu32 ":%" PRIu32
                            ":%" PRIu32 "] %s [**] [Classification: %s] [Priority: "
                            "%" PRIu32 "] pcapfile: %s.pcap [**] [Raw pkt: ", timebuf, action, pa->s->gid,
                            pa->s->id, pa->s->rev, pa->s->msg, pa->s->class_msg, pa->s->prio, stenographerPcapAlertFile);
            }
            PrintBufferRawLineHex(alert_buffer, &size, MAX_STENOGRAPHER_ALERT_SIZE,
                                  GET_PKT_DATA(p), GET_PKT_LEN(p) < 32 ? GET_PKT_LEN(p) : 32);
            if (p->pcap_cnt != 0) {
                PrintBufferData(alert_buffer, &size, MAX_STENOGRAPHER_ALERT_SIZE, 
                                "] [pcap file packet: %"PRIu64"]\n", p->pcap_cnt);
            } else {
                PrintBufferData(alert_buffer, &size, MAX_STENOGRAPHER_ALERT_SIZE, "]\n");
            }
        }

        /* Write the alert to output file */
        AlertStenographerOutputAlert(aft, alert_buffer, size);
        
        
        struct timeval end_time;
        end_time.tv_sec = p->ts.tv_sec + aft->ctx->after_time;
        end_time.tv_usec = p->ts.tv_usec;
        char end_timebuf[64];
        CreateIsoTimeStringNoMS(&end_time, end_timebuf, sizeof(end_timebuf));
        
        struct timeval start_time;
        start_time.tv_sec = p->ts.tv_sec - aft->ctx->before_time;
        start_time.tv_usec = p->ts.tv_usec;
        if(aft->ctx->no_overlapping) {
            if (start_time.tv_sec < last_alert_sec) {
                start_time.tv_sec = last_alert_sec;
                last_alert_sec = end_time.tv_sec;
            }
        }
        char start_timebuf[64];
        CreateIsoTimeStringNoMS(&start_time, start_timebuf, sizeof(start_timebuf));

        pid_t pid = fork();
        if (pid == 0) {
            if(aft->ctx->cleanup) {
            if(aft->ctx->cleanup_expiry_time) {
                int files_deleted = CleanupOldest(aft->ctx->pcap_dir, aft->ctx->cleanup_expiry_time, aft->ctx->cleanup_script);
                if(files_deleted) {
                    char cleanup_message[MAX_STENOGRAPHER_BUFFER_SIZE];
                    int cleanup_size = 0;
                    PrintBufferData(cleanup_message, &cleanup_size, MAX_STENOGRAPHER_ALERT_SIZE,
                        "%s Cleanup of the folder '%s' is finished, %d file(s) older than %lu seconds were deleted \n", timebuf, aft->ctx->pcap_dir, files_deleted, aft->ctx->cleanup_expiry_time);
                    AlertStenographerOutputAlert(aft, cleanup_message, cleanup_size);
                }
            }

            if(aft->ctx->min_disk_space_left) {
                
                if(aft->ctx->min_disk_space_left > GetAvailableDiskSpace(aft->ctx->pcap_dir)) {
                    int files_deleted = CleanupOldest(aft->ctx->pcap_dir, 0, aft->ctx->cleanup_script);
                    if(files_deleted) {
                        char cleanup_message[MAX_STENOGRAPHER_BUFFER_SIZE];
                        int cleanup_size = 0;
                        PrintBufferData(cleanup_message, &cleanup_size, MAX_STENOGRAPHER_ALERT_SIZE,
                            "%s Cleanup of the folder '%s' is finished, %d file(s) were deleted, %lu bytes of empty space left \n", timebuf, aft->ctx->pcap_dir, files_deleted, GetAvailableDiskSpace(aft->ctx->pcap_dir));
                        AlertStenographerOutputAlert(aft, cleanup_message, cleanup_size);
                    }
                }
            }
            }

            struct timeval current_time;
            gettimeofday(&current_time, NULL);
            while (current_time.tv_sec < (end_time.tv_sec + 60)) {
                gettimeofday(&current_time, NULL);
                sleep(1);
            }
            
            LogStenographerFileWrite((void *)aft->ctx, stenographerPcapAlertFile, start_timebuf, end_timebuf);
            exit(0);
        }
    }

    return TM_ECODE_OK;
}

TmEcode AlertStenographerThreadInit(ThreadVars *t, const void *initdata, void **data)
{
    AlertStenographerThread *aft = SCMalloc(sizeof(AlertStenographerThread));
    if (unlikely(aft == NULL))
        return TM_ECODE_FAILED;
    memset(aft, 0, sizeof(AlertStenographerThread));
    if(initdata == NULL)
    {
        SCLogDebug("Error getting context for AlertStenographer.  \"initdata\" argument NULL");
        SCFree(aft);
        return TM_ECODE_FAILED;
    }
    /** Use the Ouptut Context (file pointer and mutex) */
    aft->ctx = ((OutputCtx *)initdata)->data;
    //SCLogStenographerInit("https://127.0.0.1/query", 1234L, "/etc/stenographer/certs/client_cert.pem", 
     //                           "/etc/stenographer/certs/client_key.pem", "/etc/stenographer/certs/ca_cert.pem");

    *data = (void *)aft;
    return TM_ECODE_OK;
}

TmEcode AlertStenographerThreadDeinit(ThreadVars *t, void *data)
{
    AlertStenographerThread *aft = (AlertStenographerThread *)data;
    if (aft == NULL) {
        return TM_ECODE_OK;
    }

    /* clear memory */
    memset(aft, 0, sizeof(AlertStenographerThread));

    SCFree(aft);
    return TM_ECODE_OK;
}

/**
 * \brief Create a new LogFileCtx for "fast" output style.
 * \param conf The configuration node for this output.
 * \return A LogFileCtx pointer on success, NULL on failure.
 */
OutputInitResult AlertStenographerInitCtx(ConfNode *conf)
{
    OutputInitResult result = { NULL, false };
    LogFileCtx *logfile_ctx = LogFileNewCtx();
    AlertStenographerCtx *ctx;
    if (logfile_ctx == NULL) {
        SCLogDebug("AlertStenographerInitCtx2: Could not create new LogFileCtx");
        return result;
    }

    if (SCConfLogOpenGeneric(conf, logfile_ctx, DEFAULT_LOG_FILENAME, 1) < 0) {
        LogFileFreeCtx(logfile_ctx);
        return result;
    }
    const char * pcap_dir = ConfNodeLookupChildValue(conf, "pcap-dir");
    if (pcap_dir == NULL) {
        SCLogError(SC_ERR_INVALID_ARGUMENT,
                    "Failed to initialize pcap directory, invalid path: %s",
                    pcap_dir);
        exit(EXIT_FAILURE);
    }
    const char * s_before_time = ConfNodeLookupChildValue(conf, "before-time");

    uint32_t before_time = 0;
    if (s_before_time != NULL) {
            if (ParseSizeStringU32(s_before_time, &before_time) < 0) {
                SCLogError(SC_ERR_INVALID_ARGUMENT,
                    "Failed to initialize pcap output, invalid limit: %s",
                    s_before_time);
                exit(EXIT_FAILURE);
            }
            // TODO add limits
        }
    const char * s_after_time = ConfNodeLookupChildValue(conf, "after-time");
    uint32_t after_time = 0;
    if (s_after_time != NULL) {
            if (ParseSizeStringU32(s_after_time, &after_time) < 0) {
                SCLogError(SC_ERR_INVALID_ARGUMENT,
                    "Failed to initialize pcap output, invalid limit: %s",
                    s_after_time);
                exit(EXIT_FAILURE);
            }
            // TODO add limitd
        }

    int compression = False;
    const char * s_compression = ConfNodeLookupChildValue(conf, "compression");
    if (s_compression != NULL) {
        if(ConfValIsTrue(s_compression)) {
            compression = True;
        }
    }

    int no_overlapping = False;

    
    const char * s_no_overlapping = ConfNodeLookupChildValue(conf, "no-overlapping");
    if(s_no_overlapping!= NULL) {
        if(ConfValIsTrue(s_no_overlapping)) {
            no_overlapping = True;
        }
    }

    int cleanup = False;
    const char * cleanup_script = NULL;

    ConfNode *cleanup_node = NULL;
    
    cleanup_node = ConfNodeLookupChild(conf, "cleanup");
    uint64_t expiry_time = 0;
    uint64_t min_disk_space_left = 0;
    if (cleanup_node != NULL && ConfNodeChildValueIsTrue(cleanup_node, "enabled")) {
        cleanup = True;
        const char *script = ConfNodeLookupChildValue(cleanup_node, "script");

        if (script != NULL) {
            cleanup_script = script;
        }
        const char * s_expiry_time = ConfNodeLookupChildValue(cleanup_node, "expiry-time");
    
        if (s_expiry_time != NULL) {
            if (ParseSizeStringU64(s_expiry_time, &expiry_time) < 0) {
                SCLogError(SC_ERR_INVALID_ARGUMENT,
                    "Failed to initialize expity time, invalid limit: %s",
                    s_expiry_time);
                exit(EXIT_FAILURE);
            }
        }
        
        const char * s_min_disk_space_left = ConfNodeLookupChildValue(cleanup_node, "min-disk-space-left");
    
        if (s_min_disk_space_left != NULL) {
            if (ParseSizeStringU64(s_min_disk_space_left, &min_disk_space_left) < 0) {
                SCLogError(SC_ERR_INVALID_ARGUMENT,
                    "Failed to initialize minimum disk space left, invalid limit: %s",
                    s_min_disk_space_left);
                exit(EXIT_FAILURE);
            }
        }
    }

    OutputCtx *output_ctx = SCCalloc(1, sizeof(OutputCtx));
    if (unlikely(output_ctx == NULL)) {
        LogFileFreeCtx(logfile_ctx);
        return result;
    }
    ctx = SCMalloc(sizeof(AlertStenographerCtx));
    ctx->pcap_dir = pcap_dir;
    ctx->before_time = before_time;
    ctx->after_time = after_time;
    ctx->compression = compression;
    ctx->no_overlapping = no_overlapping;
    ctx->cleanup = cleanup;
    ctx->cleanup_script = cleanup_script;
    ctx->cleanup_expiry_time = expiry_time;
    ctx->min_disk_space_left = min_disk_space_left;
    ctx->logfile_ctx = logfile_ctx;
    if (unlikely(ctx == NULL)) {
        //prelude_perror(ret, "Unable to allocate memory");
        //prelude_client_destroy(client, PRELUDE_CLIENT_EXIT_STATUS_SUCCESS);
        //SCReturnCT(result, "OutputInitResult");
    }
    output_ctx->data = ctx;
    output_ctx->DeInit = AlertStenographerDeInitCtx;

    result.ctx = output_ctx;
    result.ok = true;
    return result;
}

static void AlertStenographerDeInitCtx(OutputCtx *output_ctx)
{
    AlertStenographerCtx * stenographer_ctx = output_ctx->data;
    LogFileCtx *logfile_ctx = (LogFileCtx *)stenographer_ctx->logfile_ctx;
    LogFileFreeCtx(logfile_ctx);
    // TODO free chars *
    SCFree(stenographer_ctx);
    SCFree(output_ctx);
}

/*------------------------------Unittests-------------------------------------*/

#ifdef UNITTESTS

static int AlertStenographerTest01(void)
{
    int result = 0;
    uint8_t *buf = (uint8_t *) "GET /one/ HTTP/1.1\r\n"
        "Host: one.example.org\r\n";

    uint16_t buflen = strlen((char *)buf);
    Packet *p = NULL;
    ThreadVars th_v;
    DetectEngineThreadCtx *det_ctx;

    memset(&th_v, 0, sizeof(th_v));
    p = UTHBuildPacket(buf, buflen, IPPROTO_TCP);

    DetectEngineCtx *de_ctx = DetectEngineCtxInit();
    if (de_ctx == NULL) {
        return result;
    }

    de_ctx->flags |= DE_QUIET;

    FILE *fd = SCClassConfGenerateValidDummyClassConfigFD01();
    SCClassConfLoadClassficationConfigFile(de_ctx, fd);

    de_ctx->sig_list = SigInit(de_ctx, "alert tcp any any -> any any "
            "(msg:\"Stenographer test\"; content:\"GET\"; "
            "Classtype:unknown; sid:1;)");

    SigGroupBuild(de_ctx);
    DetectEngineThreadCtxInit(&th_v, (void *)de_ctx, (void *)&det_ctx);

    SigMatchSignatures(&th_v, de_ctx, det_ctx, p);
    if (p->alerts.cnt == 1) {
        result = (strcmp(p->alerts.alerts[0].s->class_msg, "Unknown are we") == 0);
    }

    SigGroupCleanup(de_ctx);
    SigCleanSignatures(de_ctx);
    DetectEngineThreadCtxDeinit(&th_v, (void *)det_ctx);
    DetectEngineCtxFree(de_ctx);

    UTHFreePackets(&p, 1);
    return result;
}

static int AlertStenographerTest02(void)
{
    int result = 0;
    uint8_t *buf = (uint8_t *) "GET /one/ HTTP/1.1\r\n"
        "Host: one.example.org\r\n";
    uint16_t buflen = strlen((char *)buf);
    Packet *p = NULL;
    ThreadVars th_v;
    DetectEngineThreadCtx *det_ctx;

    memset(&th_v, 0, sizeof(th_v));

    p = UTHBuildPacket(buf, buflen, IPPROTO_TCP);

    DetectEngineCtx *de_ctx = DetectEngineCtxInit();
    if (de_ctx == NULL) {
        return result;
    }

    de_ctx->flags |= DE_QUIET;

    FILE *fd = SCClassConfGenerateValidDummyClassConfigFD01();
    SCClassConfLoadClassficationConfigFile(de_ctx, fd);

    de_ctx->sig_list = SigInit(de_ctx, "alert tcp any any -> any any "
            "(msg:\"Stenographer test\"; content:\"GET\"; "
            "Classtype:unknown; sid:1;)");

    SigGroupBuild(de_ctx);
    DetectEngineThreadCtxInit(&th_v, (void *)de_ctx, (void *)&det_ctx);

    SigMatchSignatures(&th_v, de_ctx, det_ctx, p);
    if (p->alerts.cnt == 1) {
        result = (strcmp(p->alerts.alerts[0].s->class_msg,
                    "Unknown are we") == 0);
        if (result == 0)
            printf("p->alerts.alerts[0].class_msg %s: ", p->alerts.alerts[0].s->class_msg);
    }

    SigGroupCleanup(de_ctx);
    SigCleanSignatures(de_ctx);
    DetectEngineThreadCtxDeinit(&th_v, (void *)det_ctx);
    DetectEngineCtxFree(de_ctx);

    UTHFreePackets(&p, 1);
    return result;
}

#endif /* UNITTESTS */

/**
 * \brief This function registers unit tests for AlertStenographer API.
 */
void AlertStenographerRegisterTests(void)
{

#ifdef UNITTESTS

    UtRegisterTest("AlertStenographerTest01", AlertStenographerTest01);
    UtRegisterTest("AlertStenographerTest02", AlertStenographerTest02);

#endif /* UNITTESTS */

}
