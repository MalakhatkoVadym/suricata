/* Copyright (c) 2009 Open Information Security Foundation */

/**
 * \file
 * \author Brian Rectanus <brectanu@gmail.com>
 */

#include "suricata-common.h"
#include "threads.h"
#include "debug.h"
#include "decode.h"
#include "detect.h"

#include "detect-parse.h"
#include "detect-engine.h"
#include "detect-engine-mpm.h"
#include "detect-content.h"

#include "flow.h"
#include "flow-var.h"

#include "util-debug.h"
#include "util-unittest.h"
#include "util-spm.h"

#include "app-layer.h"

#include <htp/htp.h>
#include "app-layer-htp.h"
#include "detect-http-method.h"
#include "stream-tcp.h"


int DetectHttpMethodMatch(ThreadVars *, DetectEngineThreadCtx *,
                          Flow *, uint8_t, void *, Signature *, SigMatch *);
static int DetectHttpMethodSetup(DetectEngineCtx *, Signature *, char *);
void DetectHttpMethodRegisterTests(void);
void DetectHttpMethodFree(void *);

/**
 * \brief Registration function for keyword: http_method
 */
void DetectHttpMethodRegister(void) {
    sigmatch_table[DETECT_AL_HTTP_METHOD].name = "http_method";
    sigmatch_table[DETECT_AL_HTTP_METHOD].Match = NULL;
    sigmatch_table[DETECT_AL_HTTP_METHOD].AppLayerMatch = DetectHttpMethodMatch;
    sigmatch_table[DETECT_AL_HTTP_METHOD].alproto = ALPROTO_HTTP;
    sigmatch_table[DETECT_AL_HTTP_METHOD].Setup = DetectHttpMethodSetup;
    sigmatch_table[DETECT_AL_HTTP_METHOD].Free  = DetectHttpMethodFree;
    sigmatch_table[DETECT_AL_HTTP_METHOD].RegisterTests = DetectHttpMethodRegisterTests;
    sigmatch_table[DETECT_AL_HTTP_METHOD].flags |= SIGMATCH_PAYLOAD;

    SCLogDebug("registering http_method rule option");
}

int DetectHttpMethodDoMatch(DetectEngineThreadCtx *det_ctx, Signature *s, SigMatch *sm, Flow *f, uint8_t flags, void *state) {
    SCEnter();
    uint8_t i;
    DetectHttpMethodData *data = (DetectHttpMethodData *)sm->ctx;
    HtpState *hs = (HtpState *)state;
    htp_tx_t *tx = NULL;
    int ret = 0;

    if (hs == NULL) {
        SCLogDebug("No HTP state.");
        SCReturnInt(0);
    }

    SCMutexLock(&f->m);
    for (i = hs->new_in_tx_index; i < list_size(hs->connp->conn->transactions); i++)
    {
        tx = list_get(hs->connp->conn->transactions, i);
        if (tx == NULL)
            continue;


        /* Compare the numeric methods if they are known, otherwise compare
         * the raw values.
         */
        if (data->method != M_UNKNOWN) {
            if (data->method == tx->request_method_number) {
               SCLogDebug("Matched numeric HTTP method values.");
                ret = 1;
            }
        } else if (tx->request_method != NULL) {
            const uint8_t *meth_str = (const uint8_t *)
                                               bstr_ptr(tx->request_method);

            if ((meth_str != NULL) &&
                    SpmSearch((uint8_t*) meth_str, bstr_size(tx->request_method),
                    data->content, data->content_len) != NULL)
            {
                SCLogDebug("Matched raw HTTP method values.");

                ret = 1;
            }
        }
    }

    SCMutexUnlock(&f->m);
    SCReturnInt(ret);
}

/**
 * \brief match the specified version on a tls session
 *
 * \param t       pointer to thread vars
 * \param det_ctx pointer to the pattern matcher thread
 * \param f       pointer to the current flow
 * \param flags   flags to indicate the direction of the received packet
 * \param state   pointer the app layer state, which will cast into HtpState
 * \param m       pointer to the sigmatch cast into DetectHttpMethodData
 *
 * \retval 0 no match
 * \retval 1 match
 */
int DetectHttpMethodMatch(ThreadVars *t, DetectEngineThreadCtx *det_ctx,
                          Flow *f, uint8_t flags, void *state,
                          Signature *s, SigMatch *sm)
{
    int r = DetectHttpMethodDoMatch(det_ctx, s, sm, f, flags, state);
    SCReturnInt(r);
}

/**
 * \brief this function is used to add the parsed "http_method" option
 * \brief into the current signature
 *
 * \param de_ctx pointer to the Detection Engine Context
 * \param s      pointer to the Current Signature
 * \param str    pointer to the user provided option string
 *
 * \retval 0 on Success
 * \retval -1 on Failure
 */
static int DetectHttpMethodSetup(DetectEngineCtx *de_ctx, Signature *s, char *str)
{
    SCEnter();
    DetectHttpMethodData *data = NULL;
    SigMatch *sm = NULL;
    bstr *method;
    /** new sig match to replace previous content */
    SigMatch *nm = NULL;

    if ((str != NULL) && (strcmp(str, "") != 0)) {
        SCLogError(SC_ERR_INVALID_ARGUMENT,
                   "http_method does not take an argument");
        SCReturnInt(-1);
    }

    if (s->pmatch_tail == NULL) {
        SCLogError(SC_ERR_INVALID_SIGNATURE,
                   "http_method modifier used before any signature match");
        SCReturnInt(-1);
    }

    SigMatch *pm = DetectContentFindPrevApplicableSM(s->pmatch_tail);
    if (pm == NULL) {
        SCLogError(SC_ERR_INVALID_SIGNATURE,
                "http_method modifies \"content\", but none was found");
        SCReturnInt(-1);
    }

    /** \todo snort docs only mention rawbytes, not fast_pattern */
    if (((DetectContentData *)pm->ctx)->flags & DETECT_CONTENT_FAST_PATTERN)
    {
        SCLogError(SC_ERR_INVALID_SIGNATURE,
                   "http_method cannot be used with \"fast_pattern\"");

        SCReturnInt(-1);
    } else if (((DetectContentData *)pm->ctx)->flags & DETECT_CONTENT_RAWBYTES)
    {
        SCLogError(SC_ERR_INVALID_SIGNATURE,
                   "http_method cannot be used with \"rawbytes\"");

        SCReturnInt(-1);
    }

    /* Setup the new sigmatch */
    nm = SigMatchAlloc();
    if (nm == NULL) {
        SCLogError(SC_ERR_MEM_ALLOC, "SigMatchAlloc failed");
        goto error;
    }

    data = SCMalloc(sizeof(DetectHttpMethodData));
    if (data == NULL) {
        SCLogError(SC_ERR_MEM_ALLOC, "SCMalloc failed");
        goto error;
    }

    data->content_len = ((DetectContentData *)pm->ctx)->content_len;
    data->content = SCMalloc(data->content_len);
    if (data->content == NULL) {
        SCLogError(SC_ERR_MEM_ALLOC, "SCMalloc failed");
        goto error;
    }
    memcpy(data->content,
           ((DetectContentData *)pm->ctx)->content, data->content_len);

    method = bstr_memdup((char *)data->content, data->content_len);
    /** \todo error check */
    data->method = htp_convert_method_to_number(method);
    bstr_free(method);

    nm->type = DETECT_AL_HTTP_METHOD;
    nm->ctx = (void *)data;

    /* pull the previous content from the pmatch list, append
     * the new match to the match list */
    SigMatchReplaceContent(s, pm, nm);

    /* free the old content sigmatch */
    DetectContentFree(pm->ctx);
    SCFree(pm);

    /* Flagged the signature as to scan the app layer data */
    s->flags |= SIG_FLAG_APPLAYER;

    SCReturnInt(0);

error:
    if (data != NULL) DetectHttpMethodFree(data);
    if (sm != NULL) SCFree(sm);
    SCReturnInt(-1);
}

/**
 * \brief this function will free memory associated with DetectHttpMethodData
 *
 * \param id_d pointer to DetectHttpMethodData
 */
void DetectHttpMethodFree(void *ptr) {
    DetectHttpMethodData *data = (DetectHttpMethodData *)ptr;

    if (data->content != NULL) SCFree(data->content);
    SCFree(data);
}

#ifdef UNITTESTS /* UNITTESTS */

#include "stream-tcp-reassemble.h"

/** \test Check a signature with content */
int DetectHttpMethodTest01(void)
{
    DetectEngineCtx *de_ctx = NULL;
    int result = 0;

    if ( (de_ctx = DetectEngineCtxInit()) == NULL)
        goto end;

    de_ctx->flags |= DE_QUIET;
    de_ctx->sig_list = SigInit(de_ctx,
                               "alert tcp any any -> any any "
                               "(msg:\"Testing http_method\"; "
                               "content:\"GET\"; "
                               "http_method; sid:1;)");

    if (de_ctx->sig_list != NULL) {
        result = 1;
    } else {
        printf("sig parse failed: ");
    }

 end:
    if (de_ctx != NULL) SigCleanSignatures(de_ctx);
    if (de_ctx != NULL) DetectEngineCtxFree(de_ctx);
    return result;
}

/** \test Check a signature without content (fail) */
int DetectHttpMethodTest02(void)
{
    DetectEngineCtx *de_ctx = NULL;
    int result = 0;

    if ( (de_ctx = DetectEngineCtxInit()) == NULL)
        goto end;

    de_ctx->flags |= DE_QUIET;
    de_ctx->sig_list = SigInit(de_ctx,
                               "alert tcp any any -> any any "
                               "(msg:\"Testing http_method\"; "
                               "http_method; sid:1;)");

    if (de_ctx->sig_list == NULL) {
        result = 1;
    }

 end:
    if (de_ctx != NULL) SigCleanSignatures(de_ctx);
    if (de_ctx != NULL) DetectEngineCtxFree(de_ctx);
    return result;
}

/** \test Check a signature with parameter (fail) */
int DetectHttpMethodTest03(void)
{
    DetectEngineCtx *de_ctx = NULL;
    int result = 0;

    if ( (de_ctx = DetectEngineCtxInit()) == NULL)
        goto end;

    de_ctx->flags |= DE_QUIET;
    de_ctx->sig_list = SigInit(de_ctx,
                               "alert tcp any any -> any any "
                               "(msg:\"Testing http_method\"; "
                               "content:\"foobar\"; "
                               "http_method:\"GET\"; sid:1;)");

    if (de_ctx->sig_list == NULL) {
        result = 1;
    }

 end:
    if (de_ctx != NULL) SigCleanSignatures(de_ctx);
    if (de_ctx != NULL) DetectEngineCtxFree(de_ctx);
    return result;
}

/** \test Check a signature with fast_pattern (fail) */
int DetectHttpMethodTest04(void)
{
    DetectEngineCtx *de_ctx = NULL;
    int result = 0;

    if ( (de_ctx = DetectEngineCtxInit()) == NULL)
        goto end;

    de_ctx->flags |= DE_QUIET;
    de_ctx->sig_list = SigInit(de_ctx,
                               "alert tcp any any -> any any "
                               "(msg:\"Testing http_method\"; "
                               "content:\"GET\"; "
                               "fast_pattern; "
                               "http_method; sid:1;)");

    if (de_ctx->sig_list == NULL) {
        result = 1;
    }

 end:
    if (de_ctx != NULL) SigCleanSignatures(de_ctx);
    if (de_ctx != NULL) DetectEngineCtxFree(de_ctx);
    return result;
}

/** \test Check a signature with rawbytes (fail) */
int DetectHttpMethodTest05(void)
{
    DetectEngineCtx *de_ctx = NULL;
    int result = 0;

    if ( (de_ctx = DetectEngineCtxInit()) == NULL)
        goto end;

    de_ctx->flags |= DE_QUIET;
    de_ctx->sig_list = SigInit(de_ctx,
                               "alert tcp any any -> any any "
                               "(msg:\"Testing http_method\"; "
                               "content:\"GET\"; "
                               "rawbytes; "
                               "http_method; sid:1;)");

    if (de_ctx->sig_list == NULL) {
        result = 1;
    }

 end:
    if (de_ctx != NULL) SigCleanSignatures(de_ctx);
    if (de_ctx != NULL) DetectEngineCtxFree(de_ctx);
    return result;
}

/** \test Check a signature with an known request method */
static int DetectHttpMethodSigTest01(void)
{
    int result = 0;
    Flow f;
    uint8_t httpbuf1[] = "GET / HTTP/1.0\r\n"
                         "Host: foo.bar.tld\r\n"
                         "\r\n";
    uint32_t httplen1 = sizeof(httpbuf1) - 1; /* minus the \0 */
    TcpSession ssn;
    Packet p;
    Signature *s = NULL;
    ThreadVars th_v;
    DetectEngineThreadCtx *det_ctx;
    HtpState *http_state = NULL;

    memset(&th_v, 0, sizeof(th_v));
    memset(&p, 0, sizeof(p));
    memset(&f, 0, sizeof(f));
    memset(&ssn, 0, sizeof(ssn));

    p.src.family = AF_INET;
    p.dst.family = AF_INET;
    p.payload = NULL;
    p.payload_len = 0;
    p.proto = IPPROTO_TCP;

    f.protoctx = (void *)&ssn;
    p.flow = &f;
    p.flowflags |= FLOW_PKT_TOSERVER;
    ssn.alproto = ALPROTO_HTTP;

    StreamTcpInitConfig(TRUE);
    StreamL7DataPtrInit(&ssn);

    DetectEngineCtx *de_ctx = DetectEngineCtxInit();
    if (de_ctx == NULL) {
        goto end;
    }

    de_ctx->flags |= DE_QUIET;

    s = de_ctx->sig_list = SigInit(de_ctx,
                                   "alert tcp any any -> any any "
                                   "(msg:\"Testing http_method\"; "
                                   "content:\"GET\"; "
                                   "http_method; sid:1;)");
    if (s == NULL) {
        goto end;
    }

    s = s->next = SigInit(de_ctx,
                          "alert tcp any any -> any any "
                          "(msg:\"Testing http_method\"; "
                          "content:\"POST\"; "
                          "http_method; sid:2;)");
    if (s == NULL) {
        goto end;
    }

    SigGroupBuild(de_ctx);
    DetectEngineThreadCtxInit(&th_v, (void *)de_ctx, (void *)&det_ctx);

    int r = AppLayerParse(&f, ALPROTO_HTTP, STREAM_TOSERVER, httpbuf1, httplen1);
    if (r != 0) {
        SCLogDebug("toserver chunk 1 returned %" PRId32 ", expected 0: ", r);
        goto end;
    }

    http_state = ssn.aldata[AlpGetStateIdx(ALPROTO_HTTP)];
    if (http_state == NULL) {
        SCLogDebug("no http state: ");
        goto end;
    }

    SigMatchSignatures(&th_v, de_ctx, det_ctx, &p);

    if (!(PacketAlertCheck(&p, 1))) {
        goto end;
    }
    if (PacketAlertCheck(&p, 2)) {
        goto end;
    }

    result = 1;

end:
    if (http_state != NULL) HTPStateFree(http_state);
    if (de_ctx != NULL) SigGroupCleanup(de_ctx);
    if (de_ctx != NULL) SigCleanSignatures(de_ctx);
    if (de_ctx != NULL) DetectEngineCtxFree(de_ctx);

    StreamL7DataPtrFree(&ssn);
    StreamTcpFreeConfig(TRUE);
    return result;
}

/** \test Check a signature with an unknown request method */
static int DetectHttpMethodSigTest02(void)
{
    int result = 0;
    Flow f;
    uint8_t httpbuf1[] = "FOO / HTTP/1.0\r\n"
                         "Host: foo.bar.tld\r\n"
                         "\r\n";
    uint32_t httplen1 = sizeof(httpbuf1) - 1; /* minus the \0 */
    TcpSession ssn;
    Packet p;
    Signature *s = NULL;
    ThreadVars th_v;
    DetectEngineThreadCtx *det_ctx = NULL;
    HtpState *http_state = NULL;

    memset(&th_v, 0, sizeof(th_v));
    memset(&p, 0, sizeof(p));
    memset(&f, 0, sizeof(f));
    memset(&ssn, 0, sizeof(ssn));

    p.src.family = AF_INET;
    p.dst.family = AF_INET;
    p.payload = NULL;
    p.payload_len = 0;
    p.proto = IPPROTO_TCP;

    f.protoctx = (void *)&ssn;
    p.flow = &f;
    p.flowflags |= FLOW_PKT_TOSERVER;
    ssn.alproto = ALPROTO_HTTP;

    StreamTcpInitConfig(TRUE);
    StreamL7DataPtrInit(&ssn);

    DetectEngineCtx *de_ctx = DetectEngineCtxInit();
    if (de_ctx == NULL) {
        goto end;
    }

    de_ctx->flags |= DE_QUIET;

    s = de_ctx->sig_list = SigInit(de_ctx,
                                   "alert tcp any any -> any any "
                                   "(msg:\"Testing http_method\"; "
                                   "content:\"FOO\"; "
                                   "http_method; sid:1;)");
    if (s == NULL) {
        goto end;
    }

    s = s->next = SigInit(de_ctx,
                          "alert tcp any any -> any any "
                          "(msg:\"Testing http_method\"; "
                          "content:\"BAR\"; "
                          "http_method; sid:2;)");
    if (s == NULL) {
        goto end;
    }

    SigGroupBuild(de_ctx);
    DetectEngineThreadCtxInit(&th_v, (void *)de_ctx, (void *)&det_ctx);

    int r = AppLayerParse(&f, ALPROTO_HTTP, STREAM_TOSERVER, httpbuf1, httplen1);
    if (r != 0) {
        SCLogDebug("toserver chunk 1 returned %" PRId32 ", expected 0: ", r);
        goto end;
    }

    http_state = ssn.aldata[AlpGetStateIdx(ALPROTO_HTTP)];
    if (http_state == NULL) {
        SCLogDebug("no http state: ");
        goto end;
    }

    SigMatchSignatures(&th_v, de_ctx, det_ctx, &p);

    if (!(PacketAlertCheck(&p, 1))) {
        goto end;
    }
    if (PacketAlertCheck(&p, 2)) {
        goto end;
    }

    result = 1;

end:
    if (http_state != NULL) HTPStateFree(http_state);
    if (de_ctx != NULL) SigGroupCleanup(de_ctx);
    if (de_ctx != NULL) SigCleanSignatures(de_ctx);
    if (det_ctx != NULL) DetectEngineThreadCtxDeinit(&th_v, (void *) det_ctx);
    if (de_ctx != NULL) DetectEngineCtxFree(de_ctx);

    StreamL7DataPtrFree(&ssn);
    StreamTcpFreeConfig(TRUE);
    return result;
}

/** \test Check a signature against an unparsable request */
static int DetectHttpMethodSigTest03(void)
{
    int result = 0;
    Flow f;
    uint8_t httpbuf1[] = " ";
    uint32_t httplen1 = sizeof(httpbuf1) - 1; /* minus the \0 */
    TcpSession ssn;
    Packet p;
    Signature *s = NULL;
    ThreadVars th_v;
    DetectEngineThreadCtx *det_ctx;
    HtpState *http_state = NULL;

    memset(&th_v, 0, sizeof(th_v));
    memset(&p, 0, sizeof(p));
    memset(&f, 0, sizeof(f));
    memset(&ssn, 0, sizeof(ssn));

    p.src.family = AF_INET;
    p.dst.family = AF_INET;
    p.payload = NULL;
    p.payload_len = 0;
    p.proto = IPPROTO_TCP;

    f.protoctx = (void *)&ssn;
    p.flow = &f;
    p.flowflags |= FLOW_PKT_TOSERVER;
    ssn.alproto = ALPROTO_HTTP;

    StreamTcpInitConfig(TRUE);
    StreamL7DataPtrInit(&ssn);

    DetectEngineCtx *de_ctx = DetectEngineCtxInit();
    if (de_ctx == NULL) {
        goto end;
    }

    de_ctx->flags |= DE_QUIET;

    s = de_ctx->sig_list = SigInit(de_ctx,
                                   "alert tcp any any -> any any "
                                   "(msg:\"Testing http_method\"; "
                                   "content:\" \"; "
                                   "http_method; sid:1;)");
    if (s == NULL) {
        SCLogDebug("Bad signature");
        goto end;
    }

    SigGroupBuild(de_ctx);
    DetectEngineThreadCtxInit(&th_v, (void *)de_ctx, (void *)&det_ctx);

    int r = AppLayerParse(&f, ALPROTO_HTTP, STREAM_TOSERVER, httpbuf1, httplen1);
    if (r != 0) {
        SCLogDebug("toserver chunk 1 returned %" PRId32 ", expected 0: ", r);
        goto end;
    }

    http_state = ssn.aldata[AlpGetStateIdx(ALPROTO_HTTP)];
    if (http_state == NULL) {
        SCLogDebug("no http state: ");
        goto end;
    }

    SigMatchSignatures(&th_v, de_ctx, det_ctx, &p);

    if (PacketAlertCheck(&p, 1)) {
        goto end;
    }

    result = 1;

end:
    if (http_state != NULL) HTPStateFree(http_state);
    if (de_ctx != NULL) SigGroupCleanup(de_ctx);
    if (de_ctx != NULL) SigCleanSignatures(de_ctx);
    if (de_ctx != NULL) DetectEngineCtxFree(de_ctx);

    StreamL7DataPtrFree(&ssn);
    StreamTcpFreeConfig(TRUE);
    return result;
}

#endif /* UNITTESTS */

/**
 * \brief this function registers unit tests for DetectHttpMethod
 */
void DetectHttpMethodRegisterTests(void) {
#ifdef UNITTESTS /* UNITTESTS */
    SCLogDebug("Registering tests for DetectHttpMethod...");
    UtRegisterTest("DetectHttpMethodTest01", DetectHttpMethodTest01, 1);
    UtRegisterTest("DetectHttpMethodTest02", DetectHttpMethodTest02, 1);
    UtRegisterTest("DetectHttpMethodTest03", DetectHttpMethodTest03, 1);
    UtRegisterTest("DetectHttpMethodTest04", DetectHttpMethodTest04, 1);
    UtRegisterTest("DetectHttpMethodTest05", DetectHttpMethodTest05, 1);
    UtRegisterTest("DetectHttpMethodSigTest01", DetectHttpMethodSigTest01, 1);
    UtRegisterTest("DetectHttpMethodSigTest02", DetectHttpMethodSigTest02, 1);
    UtRegisterTest("DetectHttpMethodSigTest03", DetectHttpMethodSigTest03, 1);
#endif /* UNITTESTS */
}

