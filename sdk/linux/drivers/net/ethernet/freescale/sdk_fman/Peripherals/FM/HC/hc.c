/*
 * Copyright 2008-2012 Freescale Semiconductor Inc.
 * Copyright 2021 NXP
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 *     * Redistributions of source code must retain the above copyright
 *       notice, this list of conditions and the following disclaimer.
 *     * Redistributions in binary form must reproduce the above copyright
 *       notice, this list of conditions and the following disclaimer in the
 *       documentation and/or other materials provided with the distribution.
 *     * Neither the name of Freescale Semiconductor nor the
 *       names of its contributors may be used to endorse or promote products
 *       derived from this software without specific prior written permission.
 *
 *
 * ALTERNATIVELY, this software may be distributed under the terms of the
 * GNU General Public License ("GPL") as published by the Free Software
 * Foundation, either version 2 of that License or (at your option) any
 * later version.
 *
 * THIS SOFTWARE IS PROVIDED BY Freescale Semiconductor ``AS IS'' AND ANY
 * EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
 * WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
 * DISCLAIMED. IN NO EVENT SHALL Freescale Semiconductor BE LIABLE FOR ANY
 * DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
 * (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
 * LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND
 * ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
 * SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */
#define __ERR_MODULE__  MODULE_FM

#include <linux/jiffies.h>
#include <linux/printk.h>

#include "std_ext.h"
#include "error_ext.h"
#include "sprint_ext.h"
#include "string_ext.h"

#include "fm_common.h"
#include "fm_hc.h"


/**************************************************************************//**
 @Description       defaults
*//***************************************************************************/
#define DEFAULT_dataMemId                                       0

#define HC_HCOR_OPCODE_PLCR_PRFL                                0x0
#define HC_HCOR_OPCODE_KG_SCM                                   0x1
#define HC_HCOR_OPCODE_SYNC                                     0x2
#define HC_HCOR_OPCODE_CC                                       0x3
#define HC_HCOR_OPCODE_CC_IP_FRAG_INITIALIZATION                0x11
#define HC_HCOR_ACTION_REG_IP_FRAG_SCRATCH_POOL_CMD_SHIFT       24
#define HC_HCOR_ACTION_REG_IP_FRAG_SCRATCH_POOL_BPID            16

#define HC_HCOR_GBL                         0x20000000

#define HC_HCOR_KG_SCHEME_COUNTER           0x00000400

#define HC_HCOR_KG_SCHEME_REGS_MASK         0xFFFFFE00

#define SIZE_OF_HC_FRAME_PORT_REGS          (sizeof(t_HcFrame)-sizeof(struct fman_kg_scheme_regs)+sizeof(t_FmPcdKgPortRegs))
#define SIZE_OF_HC_FRAME_SCHEME_REGS        sizeof(t_HcFrame)
#define SIZE_OF_HC_FRAME_PROFILES_REGS      (sizeof(t_HcFrame)-sizeof(struct fman_kg_scheme_regs)+sizeof(t_FmPcdPlcrProfileRegs))
#define SIZE_OF_HC_FRAME_PROFILE_CNT        (sizeof(t_HcFrame)-sizeof(t_FmPcdPlcrProfileRegs)+sizeof(uint32_t))
#define SIZE_OF_HC_FRAME_READ_OR_CC_DYNAMIC 16



#define HC_CMD_POOL_SIZE                    (INTG_MAX_NUM_OF_CORES)
/* Preserve the Linux wrapper's former one-second confirmation allowance. */
#define HC_CONFIRM_POLLS                    10000
#define HC_CONFIRM_POLL_US                  100

#define BUILD_FD(len)                     \
do {                                      \
    memset(&fmFd, 0, sizeof(t_DpaaFD));   \
    DPAA_FD_SET_ADDR(&fmFd, p_HcFrame);   \
    DPAA_FD_SET_OFFSET(&fmFd, 0);         \
    DPAA_FD_SET_LENGTH(&fmFd, len);       \
} while (0)



typedef struct t_FmPcdKgPortRegs {
    volatile uint32_t                       spReg;
    volatile uint32_t                       cppReg;
} t_FmPcdKgPortRegs;

typedef struct t_HcFrame {
    volatile uint32_t                           opcode;
    volatile uint32_t                           actionReg;
    volatile uint32_t                           extraReg;
    volatile uint32_t                           commandSequence;
    union {
        struct fman_kg_scheme_regs              schemeRegs;
        struct fman_kg_scheme_regs              schemeRegsWithoutCounter;
        t_FmPcdPlcrProfileRegs                  profileRegs;
        volatile uint32_t                       singleRegForWrite;    /* for writing SP, CPP, profile counter */
        t_FmPcdKgPortRegs                       portRegsForRead;
        volatile uint32_t                       clsPlanEntries[CLS_PLAN_NUM_PER_GRP];
    } hcSpecificData;
} t_HcFrame;



typedef enum e_HcBufState {
    e_HC_BUF_FREE,
    e_HC_BUF_READY,       /* Borrowed by a command builder or confirmed caller. */
    e_HC_BUF_IN_FLIGHT,   /* Hardware may access the frame; caller still owns it. */
    e_HC_BUF_ORPHANED     /* Caller returned after timeout; confirmation owns it. */
} e_HcBufState;

typedef struct t_FmHc {
    t_Handle                    h_FmPcd;
    t_Handle                    h_HcPortDev;
    bool						usageAllowed;    /**< HC usage is allowed or denied by user via API */
    t_FmPcdQmEnqueueCallback    *f_QmEnqueue;     /**< A callback for enqueuing frames to the QM */
    t_Handle                    h_QmArg;          /**< A handle to the QM module */
    void                        (*f_QmDescribe)(t_Handle h_QmArg, char *p_Buf, uint32_t size);
    uint8_t                     dataMemId;        /**< Memory partition ID for data buffers */

    uint32_t                    seqNum[HC_CMD_POOL_SIZE];   /* FIFO of seqNum to use when
                                                               taking buffer */
    uint32_t                    nextSeqNumLocation;         /* seqNum location in seqNum[] for next buffer */
    t_Handle                    h_Spinlock;
    e_HcBufState                bufState[HC_CMD_POOL_SIZE];
    bool                        quiescing;    /* No new borrowers during teardown. */
    uint32_t                    failures;     /* Failed since a command last completed. */
    t_HcFrame                   *p_Frm[HC_CMD_POOL_SIZE];
    /* What each command in flight is and when it went out, taken before the
     * enqueue swaps the frame to hardware order: a timeout names its command,
     * and that command's confirmation, should it still come, says how late. */
    uint32_t                    sentOpcode[HC_CMD_POOL_SIZE];
    unsigned long               sentAt[HC_CMD_POOL_SIZE];
    /* Each command that timed out, until its confirmation says how late it
     * was: commands in flight together can each time out. While any is
     * unanswered the port is sent nothing more (HcUnanswered()). */
    bool                        timedOut[HC_CMD_POOL_SIZE];
} t_FmHc;

static const char *HcOpcodeName(uint32_t opcode)
{
    switch (opcode & ~HC_HCOR_GBL)
    {
        case HC_HCOR_OPCODE_PLCR_PRFL:                 return "policer profile";
        case HC_HCOR_OPCODE_KG_SCM:                    return "KeyGen scheme";
        case HC_HCOR_OPCODE_SYNC:                      return "sync";
        case HC_HCOR_OPCODE_CC:                        return "coarse classification";
        case HC_HCOR_OPCODE_CC_IP_FRAG_INITIALIZATION: return "IP fragmentation init";
        default:                                       return "unknown";
    }
}

/* Caller holds the HC lock. */
static uint32_t HcOutstanding(t_FmHc *p_FmHc)
{
    uint32_t i, n = 0;

    for (i = 0; i < HC_CMD_POOL_SIZE; i++)
        if (p_FmHc->bufState[i] == e_HC_BUF_IN_FLIGHT ||
            p_FmHc->bufState[i] == e_HC_BUF_ORPHANED)
            n++;
    return n;
}

static uint32_t HcLock(t_FmHc *p_FmHc)
{
    return XX_LockIntrSpinlock(p_FmHc->h_Spinlock);
}

static void HcUnlock(t_FmHc *p_FmHc, uint32_t flags)
{
    XX_UnlockIntrSpinlock(p_FmHc->h_Spinlock, flags);
}

/* Caller holds the HC lock. Both the borrower and hardware are finished. */
static void ReturnBuf(t_FmHc *p_FmHc, uint32_t seqNum)
{
    ASSERT_COND(p_FmHc->nextSeqNumLocation);
    p_FmHc->bufState[seqNum] = e_HC_BUF_FREE;
    p_FmHc->seqNum[--p_FmHc->nextSeqNumLocation] = seqNum;
}

/* Caller holds the HC lock. Whether a command that timed out is still to be
 * answered. Until each is, the port that has not answered is sent nothing
 * more: what it was given may still be running, and a command sent after it
 * would wait out its own deadline behind it. Its answer opens the channel
 * again (FmHcTxConf()). */
static bool HcUnanswered(t_FmHc *p_FmHc)
{
    uint32_t i;

    for (i = 0; i < HC_CMD_POOL_SIZE; i++)
        if (p_FmHc->timedOut[i])
            return TRUE;
    return FALSE;
}

/* While a timed-out command is unanswered, or while commands cannot be
 * queued, every later command fails the same way -- and CDX retries a sync
 * once a second while anything waits on a barrier. So a run of failures
 * reports its first only, and the command that ends it says how many there
 * were: a new run always reports again. A timeout is reported
 * unconditionally and starts a run of its own. */
static bool HcFirstFailure(t_FmHc *p_FmHc)
{
    uint32_t    intFlags = HcLock(p_FmHc);
    bool        first = !p_FmHc->failures++;

    HcUnlock(p_FmHc, intFlags);
    return first;
}

#define HC_RETURN_FIRST_ERROR(_p_FmHc, _level, _err, _vmsg) \
    do { \
        if (HcFirstFailure(_p_FmHc)) { \
            REPORT_ERROR(_level, (_err), _vmsg); \
        } \
        return ERROR_CODE(_err); \
    } while (0)


static t_Error FillBufPool(t_FmHc *p_FmHc)
{
    uint32_t i;

    ASSERT_COND(p_FmHc);

    for (i = 0; i < HC_CMD_POOL_SIZE; i++)
    {
        p_FmHc->p_Frm[i] = (t_HcFrame *)XX_MallocSmart(sizeof(t_HcFrame),
                                                       p_FmHc->dataMemId,
                                                       16);
        if (!p_FmHc->p_Frm[i])
            RETURN_ERROR(MAJOR, E_NO_MEMORY, ("FM HC frames!"));
    }

    /* Initialize FIFO of seqNum to use during GetBuf */
    for (i = 0; i < HC_CMD_POOL_SIZE; i++)
    {
        p_FmHc->seqNum[i] = i;
        p_FmHc->bufState[i] = e_HC_BUF_FREE;
    }
    p_FmHc->nextSeqNumLocation = 0;

    return E_OK;
}

static __inline__ t_HcFrame * GetBuf(t_FmHc *p_FmHc, uint32_t *p_SeqNum)
{
    uint32_t    intFlags;

    ASSERT_COND(p_FmHc);

    intFlags = HcLock(p_FmHc);

    if (p_FmHc->quiescing || p_FmHc->nextSeqNumLocation == HC_CMD_POOL_SIZE)
    {
        /* No more buffers */
        HcUnlock(p_FmHc, intFlags);
        return NULL;
    }

    *p_SeqNum = p_FmHc->seqNum[p_FmHc->nextSeqNumLocation];
    ASSERT_COND(p_FmHc->bufState[*p_SeqNum] == e_HC_BUF_FREE);
    p_FmHc->bufState[*p_SeqNum] = e_HC_BUF_READY;
    p_FmHc->nextSeqNumLocation++;

    HcUnlock(p_FmHc, intFlags);
    return p_FmHc->p_Frm[*p_SeqNum];
}

static __inline__ void PutBuf(t_FmHc *p_FmHc, t_HcFrame *p_Buf, uint32_t seqNum)
{
    uint32_t    intFlags;

    intFlags = HcLock(p_FmHc);
    ASSERT_COND(seqNum < HC_CMD_POOL_SIZE && p_Buf == p_FmHc->p_Frm[seqNum]);
    ASSERT_COND(p_FmHc->bufState[seqNum] == e_HC_BUF_READY ||
                p_FmHc->bufState[seqNum] == e_HC_BUF_IN_FLIGHT);
    if (p_FmHc->bufState[seqNum] == e_HC_BUF_IN_FLIGHT)
        p_FmHc->bufState[seqNum] = e_HC_BUF_ORPHANED;
    else
        ReturnBuf(p_FmHc, seqNum);
    HcUnlock(p_FmHc, intFlags);
}

static __inline__ t_Error EnQFrm(t_FmHc *p_FmHc, t_DpaaFD *p_FmFd, uint32_t seqNum)
{
    t_Error     err = E_OK;
    uint32_t    intFlags;
    uint32_t    timeout = HC_CONFIRM_POLLS;

    intFlags = HcLock(p_FmHc);
    if (p_FmHc->quiescing || HcUnanswered(p_FmHc))
    {
        HcUnlock(p_FmHc, intFlags);
        HC_RETURN_FIRST_ERROR(p_FmHc, MINOR, E_INVALID_STATE,
                              ("HC unavailable until a timed-out command is answered"));
    }
    ASSERT_COND(p_FmHc->bufState[seqNum] == e_HC_BUF_READY);
    p_FmHc->bufState[seqNum] = e_HC_BUF_IN_FLIGHT;
    p_FmHc->sentOpcode[seqNum] = p_FmHc->p_Frm[seqNum]->opcode;
    p_FmHc->sentAt[seqNum] = jiffies;
    HcUnlock(p_FmHc, intFlags);
    DBG(TRACE, ("Send Hc, SeqNum %d, buff@0x%p, fd offset 0x%x",
                seqNum,
                DPAA_FD_GET_ADDR(p_FmFd),
                DPAA_FD_GET_OFFSET(p_FmFd)));
    err = p_FmHc->f_QmEnqueue(p_FmHc->h_QmArg, (void *)p_FmFd);
    if (err)
    {
        /* Enqueue errors mean rejection, never an accepted-command timeout. */
        intFlags = HcLock(p_FmHc);
        p_FmHc->bufState[seqNum] = e_HC_BUF_READY;
        HcUnlock(p_FmHc, intFlags);
        HC_RETURN_FIRST_ERROR(p_FmHc, MINOR, err, ("HC enqueue failed"));
    }

    for (;;)
    {
        intFlags = HcLock(p_FmHc);
        if (p_FmHc->bufState[seqNum] == e_HC_BUF_READY)
        {
            uint32_t failures = p_FmHc->failures;

            p_FmHc->failures = 0;
            HcUnlock(p_FmHc, intFlags);
            if (failures)
                pr_info("FM HC: a command completed after %u failed\n", failures);
            return E_OK;
        }
        if (!timeout--)
        {
            /* Unanswered, the command may still run, or be running: its
             * frame stays the hardware's (PutBuf()), and nothing more goes
             * to the port until it is answered, nor may register programming
             * switch to direct (FmIsHcUsageAllowed()). Its caller learns
             * only that the outcome is unknown -- for a change to the FMan's
             * state, that it may have been made -- and puts its own record
             * right once the answer has opened the channel again. */
            uint32_t opcode = p_FmHc->sentOpcode[seqNum];
            uint32_t waited = jiffies_to_msecs(jiffies - p_FmHc->sentAt[seqNum]);
            uint32_t others = HcOutstanding(p_FmHc) - 1;
            char queues[256] = "not known";

            p_FmHc->timedOut[seqNum] = TRUE;
            p_FmHc->failures++;
            HcUnlock(p_FmHc, intFlags);
            /* Where the frame is: in the sending CPU's enqueue ring, QMan
             * never took it; on the port's queue, the port never took it; on
             * the answer queue, the CPU's portal has not dequeued it, and its
             * channel's work queues say what it served first; in the portal's
             * ring, that CPU has not processed it; on none of them, the FMan
             * is still running it. The description asks QMan only within a
             * bound, and says so when QMan does not answer. */
            if (p_FmHc->f_QmDescribe)
                p_FmHc->f_QmDescribe(p_FmHc->h_QmArg, queues, sizeof(queues));
            /* The builder below is the HC entry point; who asked for the
             * command -- an ehash insert or delete barrier, a quarantine
             * drain -- is further up. Once per episode: until the answer,
             * every later command is refused before it is sent. */
            dump_stack();
            RETURN_ERROR(MINOR, E_TIMEOUT,
                         ("HC confirmation timed out; commands wait for its answer: seq %u, %s (opcode 0x%08x) built by %pS, unconfirmed after %u ms, %u other commands outstanding; %s",
                          seqNum, HcOpcodeName(opcode), opcode,
                          __builtin_return_address(0), waited, others, queues));
        }
        HcUnlock(p_FmHc, intFlags);
        XX_UDelay(HC_CONFIRM_POLL_US);
    }
}


t_Handle FmHcConfigAndInit(t_FmHcParams *p_FmHcParams)
{
    t_FmHc          *p_FmHc;
    t_FmPortParams  fmPortParam;
    t_Error         err;

    p_FmHc = (t_FmHc *)XX_Malloc(sizeof(t_FmHc));
    if (!p_FmHc)
    {
        REPORT_ERROR(MINOR, E_NO_MEMORY, ("HC obj"));
        return NULL;
    }
    memset(p_FmHc,0,sizeof(t_FmHc));

    p_FmHc->h_FmPcd             = p_FmHcParams->h_FmPcd;
    p_FmHc->f_QmEnqueue         = p_FmHcParams->params.f_QmEnqueue;
    p_FmHc->h_QmArg             = p_FmHcParams->params.h_QmArg;
    p_FmHc->f_QmDescribe        = p_FmHcParams->params.f_QmDescribe;
    p_FmHc->dataMemId           = DEFAULT_dataMemId;
    p_FmHc->usageAllowed		= TRUE;
    p_FmHc->h_Spinlock = XX_InitSpinlock();
    if (!p_FmHc->h_Spinlock)
    {
        XX_Free(p_FmHc);
        return NULL;
    }

    err = FillBufPool(p_FmHc);
    if (err != E_OK)
    {
        REPORT_ERROR(MAJOR, err, NO_MSG);
        FmHcFree(p_FmHc);
        return NULL;
    }

    if (!FmIsMaster(p_FmHcParams->h_Fm))
        return (t_Handle)p_FmHc;

    memset(&fmPortParam, 0, sizeof(fmPortParam));
    fmPortParam.baseAddr    = p_FmHcParams->params.portBaseAddr;
    fmPortParam.portType    = e_FM_PORT_TYPE_OH_HOST_COMMAND;
    fmPortParam.portId      = p_FmHcParams->params.portId;
    fmPortParam.liodnBase   = p_FmHcParams->params.liodnBase;
    fmPortParam.h_Fm        = p_FmHcParams->h_Fm;

    fmPortParam.specificParams.nonRxParams.errFqid      = p_FmHcParams->params.errFqid;
    fmPortParam.specificParams.nonRxParams.dfltFqid     = p_FmHcParams->params.confFqid;
    fmPortParam.specificParams.nonRxParams.qmChannel    = p_FmHcParams->params.qmChannel;
    fmPortParam.specificParams.nonRxParams.liodnOffset  = p_FmHcParams->params.liodnOffset;

    p_FmHc->h_HcPortDev = FM_PORT_Config(&fmPortParam);
    if (!p_FmHc->h_HcPortDev)
    {
        REPORT_ERROR(MAJOR, E_INVALID_HANDLE, ("FM HC port!"));
        FmHcFree(p_FmHc);
        return NULL;
    }

    err = FM_PORT_ConfigMaxFrameLength(p_FmHc->h_HcPortDev,
                                       (uint16_t)sizeof(t_HcFrame));

    if (err != E_OK)
    {
        REPORT_ERROR(MAJOR, err, ("FM HC port init!"));
        FmHcFree(p_FmHc);
        return NULL;
    }

    /* final init */
    err = FM_PORT_Init(p_FmHc->h_HcPortDev);
    if (err != E_OK)
    {
        REPORT_ERROR(MAJOR, err, ("FM HC port init!"));
        FmHcFree(p_FmHc);
        return NULL;
    }

    err = FM_PORT_Enable(p_FmHc->h_HcPortDev);
    if (err != E_OK)
    {
        REPORT_ERROR(MAJOR, err, ("FM HC port enable!"));
        FmHcFree(p_FmHc);
        return NULL;
    }

    return (t_Handle)p_FmHc;
}

t_Error FmHcQuiesce(t_Handle h_FmHc)
{
    t_FmHc *p_FmHc = (t_FmHc *)h_FmHc;
    uint32_t flags;
    t_Error err = E_OK;

    if (!p_FmHc)
        return E_OK;
    flags = HcLock(p_FmHc);
    /* An unanswered command's frame is still the hardware's, and borrowed
     * until its answer returns it. */
    if (p_FmHc->nextSeqNumLocation || HcUnanswered(p_FmHc))
        err = ERROR_CODE(E_BUSY);
    else
        p_FmHc->quiescing = TRUE;
    HcUnlock(p_FmHc, flags);
    return err;
}

t_Error FmHcFree(t_Handle h_FmHc)
{
    t_FmHc  *p_FmHc = (t_FmHc*)h_FmHc;
    t_Error err;
    int     i;

    if (!p_FmHc)
        return E_OK;

    err = FmHcQuiesce(p_FmHc);
    if (err)
        return err;
    if (p_FmHc->h_HcPortDev)
    {
        err = FM_PORT_Free(p_FmHc->h_HcPortDev);
        if (err)
            return err;
    }

    for (i=0; i<HC_CMD_POOL_SIZE; i++)
        if (p_FmHc->p_Frm[i])
            XX_FreeSmart(p_FmHc->p_Frm[i]);
        else
            break;

    XX_FreeSpinlock(p_FmHc->h_Spinlock);
    XX_Free(p_FmHc);
    return E_OK;
}

void FmHcTxConf(t_Handle h_FmHc, t_DpaaFD *p_Fd)
{
    t_FmHc      *p_FmHc = (t_FmHc*)h_FmHc;
    t_HcFrame   *p_HcFrame;
    uint32_t    intFlags;
    uint32_t    seqNum;
    bool        late = FALSE, reopened = FALSE;
    uint32_t    opcode = 0, waited = 0;

    ASSERT_COND(p_FmHc);

    intFlags = HcLock(p_FmHc);
    p_HcFrame  = (t_HcFrame *)PTR_MOVE(DPAA_FD_GET_ADDR(p_Fd), DPAA_FD_GET_OFFSET(p_Fd));

    /* Match an owned buffer before reading an untrusted sequence index. */
    for (seqNum = 0; seqNum < HC_CMD_POOL_SIZE; seqNum++)
        if (p_HcFrame == p_FmHc->p_Frm[seqNum])
            break;
    if (!p_HcFrame || seqNum == HC_CMD_POOL_SIZE ||
        p_HcFrame->commandSequence != seqNum ||
        (p_FmHc->bufState[seqNum] != e_HC_BUF_IN_FLIGHT &&
         p_FmHc->bufState[seqNum] != e_HC_BUF_ORPHANED))
        REPORT_ERROR(MINOR, E_INVALID_FRAME, ("Not an Host-Command frame received!"));
    else
    {
        /* A command that timed out answering after all says it was late
         * rather than lost: the one thing a timeout cannot tell. The last
         * such answer opens the channel again, with nothing left inside the
         * port. */
        if (p_FmHc->timedOut[seqNum])
        {
            p_FmHc->timedOut[seqNum] = FALSE;
            late = TRUE;
            reopened = !HcUnanswered(p_FmHc);
            opcode = p_FmHc->sentOpcode[seqNum];
            waited = jiffies_to_msecs(jiffies - p_FmHc->sentAt[seqNum]);
        }
        if (p_FmHc->bufState[seqNum] == e_HC_BUF_ORPHANED)
            ReturnBuf(p_FmHc, seqNum);
        else
            p_FmHc->bufState[seqNum] = e_HC_BUF_READY;
    }
    HcUnlock(p_FmHc, intFlags);
    if (late)
        pr_warn("FM HC: seq %u, %s (opcode 0x%08x), confirmed %u ms after it was sent, after its timeout%s\n",
                seqNum, HcOpcodeName(opcode), opcode, waited,
                reopened ? "; commands resume" : "");
}

t_Error FmHcPcdKgSetScheme(t_Handle                    h_FmHc,
                           t_Handle                    h_Scheme,
                           struct fman_kg_scheme_regs  *p_SchemeRegs,
                           bool                        updateCounter)
{
    t_FmHc                              *p_FmHc = (t_FmHc*)h_FmHc;
    t_Error                             err = E_OK;
    t_HcFrame                           *p_HcFrame;
    t_DpaaFD                            fmFd;
    uint8_t                             physicalSchemeId;
    uint32_t                            seqNum;

    p_HcFrame = GetBuf(p_FmHc, &seqNum);
    if (!p_HcFrame)
        RETURN_ERROR(MINOR, E_NO_MEMORY, ("HC Frame object"));

    physicalSchemeId = FmPcdKgGetSchemeId(h_Scheme);

    memset(p_HcFrame, 0, sizeof(t_HcFrame));
    p_HcFrame->opcode = (uint32_t)(HC_HCOR_GBL | HC_HCOR_OPCODE_KG_SCM);
    p_HcFrame->actionReg  = FmPcdKgBuildWriteSchemeActionReg(physicalSchemeId, updateCounter);
    p_HcFrame->extraReg = HC_HCOR_KG_SCHEME_REGS_MASK;
    memcpy(&p_HcFrame->hcSpecificData.schemeRegs, p_SchemeRegs, sizeof(struct fman_kg_scheme_regs));
    if (!updateCounter)
    {
        p_HcFrame->hcSpecificData.schemeRegs.kgse_dv0   = p_SchemeRegs->kgse_dv0;
        p_HcFrame->hcSpecificData.schemeRegs.kgse_dv1   = p_SchemeRegs->kgse_dv1;
        p_HcFrame->hcSpecificData.schemeRegs.kgse_ccbs  = p_SchemeRegs->kgse_ccbs;
        p_HcFrame->hcSpecificData.schemeRegs.kgse_mv    = p_SchemeRegs->kgse_mv;
    }
    p_HcFrame->commandSequence = seqNum;

    BUILD_FD(sizeof(t_HcFrame));

    err = EnQFrm(p_FmHc, &fmFd, seqNum);

    PutBuf(p_FmHc, p_HcFrame, seqNum);

    if (err != E_OK)
        RETURN_ERROR(MINOR, err, NO_MSG);

    return E_OK;
}

t_Error FmHcPcdKgDeleteScheme(t_Handle h_FmHc, t_Handle h_Scheme)
{
    t_FmHc      *p_FmHc = (t_FmHc*)h_FmHc;
    t_Error     err = E_OK;
    t_HcFrame   *p_HcFrame;
    t_DpaaFD    fmFd;
    uint8_t     physicalSchemeId = FmPcdKgGetSchemeId(h_Scheme);
    uint32_t    seqNum;

    p_HcFrame = GetBuf(p_FmHc, &seqNum);
    if (!p_HcFrame)
        RETURN_ERROR(MINOR, E_NO_MEMORY, ("HC Frame object"));

    memset(p_HcFrame, 0, sizeof(t_HcFrame));
    p_HcFrame->opcode = (uint32_t)(HC_HCOR_GBL | HC_HCOR_OPCODE_KG_SCM);
    p_HcFrame->actionReg  = FmPcdKgBuildWriteSchemeActionReg(physicalSchemeId, TRUE);
    p_HcFrame->extraReg = HC_HCOR_KG_SCHEME_REGS_MASK;
    memset(&p_HcFrame->hcSpecificData.schemeRegs, 0, sizeof(struct fman_kg_scheme_regs));
    p_HcFrame->commandSequence = seqNum;

    BUILD_FD(sizeof(t_HcFrame));

    err = EnQFrm(p_FmHc, &fmFd, seqNum);

    PutBuf(p_FmHc, p_HcFrame, seqNum);

    if (err != E_OK)
        RETURN_ERROR(MINOR, err, NO_MSG);

    return E_OK;
}

t_Error FmHcPcdKgCcGetSetParams(t_Handle h_FmHc, t_Handle  h_Scheme, uint32_t requiredAction, uint32_t value)
{
    t_FmHc      *p_FmHc = (t_FmHc*)h_FmHc;
    t_Error     err = E_OK;
    t_HcFrame   *p_HcFrame;
    t_DpaaFD    fmFd;
    uint8_t     relativeSchemeId;
    uint8_t     physicalSchemeId = FmPcdKgGetSchemeId(h_Scheme);
    uint32_t    tmpReg32 = 0;
    uint32_t    seqNum;

    /* Scheme is locked by calling routine */
    /* WARNING - this lock will not be efficient if other HC routine will attempt to change
     * "kgse_mode" or "kgse_om" without locking scheme !
     */

    relativeSchemeId = FmPcdKgGetRelativeSchemeId(p_FmHc->h_FmPcd, physicalSchemeId);
    if ( relativeSchemeId == FM_PCD_KG_NUM_OF_SCHEMES)
        RETURN_ERROR(MAJOR, E_NOT_IN_RANGE, NO_MSG);

    if (!FmPcdKgGetRequiredActionFlag(p_FmHc->h_FmPcd, relativeSchemeId) ||
       !(FmPcdKgGetRequiredAction(p_FmHc->h_FmPcd, relativeSchemeId) & requiredAction))
    {
        if ((requiredAction & UPDATE_NIA_ENQ_WITHOUT_DMA) &&
            (FmPcdKgGetNextEngine(p_FmHc->h_FmPcd, relativeSchemeId) == e_FM_PCD_PLCR))
            {
                if ((FmPcdKgIsDirectPlcr(p_FmHc->h_FmPcd, relativeSchemeId) == FALSE) ||
                    (FmPcdKgIsDistrOnPlcrProfile(p_FmHc->h_FmPcd, relativeSchemeId) == TRUE))
                    RETURN_ERROR(MAJOR, E_NOT_SUPPORTED, ("In this situation PP can not be with distribution and has to be shared"));
                err = FmPcdPlcrCcGetSetParams(p_FmHc->h_FmPcd, FmPcdKgGetRelativeProfileId(p_FmHc->h_FmPcd, relativeSchemeId), requiredAction);
                if (err)
                    RETURN_ERROR(MAJOR, err, NO_MSG);
            }
        else /* From here we deal with KG-Schemes only */
        {
            /* Pre change general code */
            p_HcFrame = GetBuf(p_FmHc, &seqNum);
            if (!p_HcFrame)
                RETURN_ERROR(MINOR, E_NO_MEMORY, ("HC Frame object"));
            memset(p_HcFrame, 0, sizeof(t_HcFrame));
            p_HcFrame->opcode = (uint32_t)(HC_HCOR_GBL | HC_HCOR_OPCODE_KG_SCM);
            p_HcFrame->actionReg  = FmPcdKgBuildReadSchemeActionReg(physicalSchemeId);
            p_HcFrame->extraReg = HC_HCOR_KG_SCHEME_REGS_MASK;
            p_HcFrame->commandSequence = seqNum;
            BUILD_FD(SIZE_OF_HC_FRAME_READ_OR_CC_DYNAMIC);
            if ((err = EnQFrm(p_FmHc, &fmFd, seqNum)) != E_OK)
            {
                PutBuf(p_FmHc, p_HcFrame, seqNum);
                RETURN_ERROR(MINOR, err, NO_MSG);
            }

            /* specific change */
            if ((requiredAction & UPDATE_NIA_ENQ_WITHOUT_DMA) &&
                ((FmPcdKgGetNextEngine(p_FmHc->h_FmPcd, relativeSchemeId) == e_FM_PCD_DONE) &&
                 (FmPcdKgGetDoneAction(p_FmHc->h_FmPcd, relativeSchemeId) ==  e_FM_PCD_ENQ_FRAME)))
            {
                tmpReg32 = p_HcFrame->hcSpecificData.schemeRegs.kgse_mode;
                ASSERT_COND(tmpReg32 & (NIA_ENG_BMI | NIA_BMI_AC_ENQ_FRAME));
                p_HcFrame->hcSpecificData.schemeRegs.kgse_mode =  tmpReg32 | NIA_BMI_AC_ENQ_FRAME_WITHOUT_DMA;
            }

            if ((requiredAction & UPDATE_KG_NIA_CC_WA) &&
                (FmPcdKgGetNextEngine(p_FmHc->h_FmPcd, relativeSchemeId) == e_FM_PCD_CC))
            {
                tmpReg32 = p_HcFrame->hcSpecificData.schemeRegs.kgse_mode;
                ASSERT_COND(tmpReg32 & (NIA_ENG_FM_CTL | NIA_FM_CTL_AC_CC));
                tmpReg32 &= ~NIA_FM_CTL_AC_CC;
                p_HcFrame->hcSpecificData.schemeRegs.kgse_mode =  tmpReg32 | NIA_FM_CTL_AC_PRE_CC;
            }

            if (requiredAction & UPDATE_KG_OPT_MODE)
                p_HcFrame->hcSpecificData.schemeRegs.kgse_om = value;

            if (requiredAction & UPDATE_KG_NIA)
            {
                tmpReg32 = p_HcFrame->hcSpecificData.schemeRegs.kgse_mode;
                tmpReg32 &= ~(NIA_ENG_MASK | NIA_AC_MASK);
                tmpReg32 |= value;
                p_HcFrame->hcSpecificData.schemeRegs.kgse_mode = tmpReg32;
            }

            /* Post change general code */
            p_HcFrame->opcode = (uint32_t)(HC_HCOR_GBL | HC_HCOR_OPCODE_KG_SCM);
            p_HcFrame->actionReg  = FmPcdKgBuildWriteSchemeActionReg(physicalSchemeId, FALSE);
            p_HcFrame->extraReg = HC_HCOR_KG_SCHEME_REGS_MASK;

            BUILD_FD(sizeof(t_HcFrame));
            err = EnQFrm(p_FmHc, &fmFd, seqNum);

            PutBuf(p_FmHc, p_HcFrame, seqNum);

            if (err != E_OK)
                RETURN_ERROR(MINOR, err, NO_MSG);
        }
    }

    return E_OK;
}

uint32_t  FmHcPcdKgGetSchemeCounter(t_Handle h_FmHc, t_Handle h_Scheme)
{
    t_FmHc      *p_FmHc = (t_FmHc*)h_FmHc;
    t_Error     err;
    t_HcFrame   *p_HcFrame;
    t_DpaaFD    fmFd;
    uint32_t    retVal;
    uint8_t     relativeSchemeId;
    uint8_t     physicalSchemeId = FmPcdKgGetSchemeId(h_Scheme);
    uint32_t    seqNum;

    relativeSchemeId = FmPcdKgGetRelativeSchemeId(p_FmHc->h_FmPcd, physicalSchemeId);
    if ( relativeSchemeId == FM_PCD_KG_NUM_OF_SCHEMES)
    {
        REPORT_ERROR(MAJOR, E_NOT_IN_RANGE, NO_MSG);
        return 0;
    }

    /* first read scheme and check that it is valid */
    p_HcFrame = GetBuf(p_FmHc, &seqNum);
    if (!p_HcFrame)
    {
        REPORT_ERROR(MINOR, E_NO_MEMORY, ("HC Frame object"));
        return 0;
    }
    memset(p_HcFrame, 0, sizeof(t_HcFrame));
    p_HcFrame->opcode = (uint32_t)(HC_HCOR_GBL | HC_HCOR_OPCODE_KG_SCM);
    p_HcFrame->actionReg  = FmPcdKgBuildReadSchemeActionReg(physicalSchemeId);
    p_HcFrame->extraReg = HC_HCOR_KG_SCHEME_REGS_MASK;
    p_HcFrame->commandSequence = seqNum;

    BUILD_FD(SIZE_OF_HC_FRAME_READ_OR_CC_DYNAMIC);

    err = EnQFrm(p_FmHc, &fmFd, seqNum);
    if (err != E_OK)
    {
        PutBuf(p_FmHc, p_HcFrame, seqNum);
        REPORT_ERROR(MINOR, err, NO_MSG);
        return 0;
    }

    if (!FmPcdKgHwSchemeIsValid(p_HcFrame->hcSpecificData.schemeRegs.kgse_mode))
    {
        PutBuf(p_FmHc, p_HcFrame, seqNum);
        REPORT_ERROR(MAJOR, E_ALREADY_EXISTS, ("Scheme is invalid"));
        return 0;
    }

    retVal = p_HcFrame->hcSpecificData.schemeRegs.kgse_spc;
    PutBuf(p_FmHc, p_HcFrame, seqNum);

    return retVal;
}

t_Error  FmHcPcdKgSetSchemeCounter(t_Handle h_FmHc, t_Handle h_Scheme, uint32_t value)
{
    t_FmHc      *p_FmHc = (t_FmHc*)h_FmHc;
    t_Error     err = E_OK;
    t_HcFrame   *p_HcFrame;
    t_DpaaFD    fmFd;
    uint8_t     relativeSchemeId, physicalSchemeId;
    uint32_t    seqNum;

    physicalSchemeId = FmPcdKgGetSchemeId(h_Scheme);
    relativeSchemeId = FmPcdKgGetRelativeSchemeId(p_FmHc->h_FmPcd, physicalSchemeId);
    if ( relativeSchemeId == FM_PCD_KG_NUM_OF_SCHEMES)
        RETURN_ERROR(MAJOR, E_NOT_IN_RANGE, NO_MSG);

    /* first read scheme and check that it is valid */
    p_HcFrame = GetBuf(p_FmHc, &seqNum);
    if (!p_HcFrame)
        RETURN_ERROR(MINOR, E_NO_MEMORY, ("HC Frame object"));
    memset(p_HcFrame, 0, sizeof(t_HcFrame));
    p_HcFrame->opcode = (uint32_t)(HC_HCOR_GBL | HC_HCOR_OPCODE_KG_SCM);
    p_HcFrame->actionReg  = FmPcdKgBuildWriteSchemeActionReg(physicalSchemeId, TRUE);
    p_HcFrame->extraReg = HC_HCOR_KG_SCHEME_COUNTER;
    /* write counter */
    p_HcFrame->hcSpecificData.singleRegForWrite = value;
    p_HcFrame->commandSequence = seqNum;

    BUILD_FD(sizeof(t_HcFrame));

    err = EnQFrm(p_FmHc, &fmFd, seqNum);

    PutBuf(p_FmHc, p_HcFrame, seqNum);
    return err;
}

t_Error FmHcPcdKgSetClsPlan(t_Handle h_FmHc, t_FmPcdKgInterModuleClsPlanSet *p_Set)
{
    t_FmHc                  *p_FmHc = (t_FmHc*)h_FmHc;
    t_HcFrame               *p_HcFrame;
    t_DpaaFD                fmFd;
    uint8_t                 i, idx;
    uint32_t                seqNum;
    const void *src;
    void *dest;
    t_Error                 err = E_OK;

    ASSERT_COND(p_FmHc);

    p_HcFrame = GetBuf(p_FmHc, &seqNum);
    if (!p_HcFrame)
        RETURN_ERROR(MINOR, E_NO_MEMORY, ("HC Frame object"));

    for (i = p_Set->baseEntry; i < (p_Set->baseEntry+p_Set->numOfClsPlanEntries); i+=8)
    {
        memset(p_HcFrame, 0, sizeof(t_HcFrame));
        p_HcFrame->opcode = (uint32_t)(HC_HCOR_GBL | HC_HCOR_OPCODE_KG_SCM);
        p_HcFrame->actionReg  = FmPcdKgBuildWriteClsPlanBlockActionReg((uint8_t)(i / CLS_PLAN_NUM_PER_GRP));
        p_HcFrame->extraReg = HC_HCOR_KG_SCHEME_REGS_MASK;

        idx = (uint8_t)(i - p_Set->baseEntry);
	dest = (void *)&p_HcFrame->hcSpecificData.clsPlanEntries;
	src = &p_Set->vectors[idx];
        memcpy(dest, src, CLS_PLAN_NUM_PER_GRP*sizeof(uint32_t));
        p_HcFrame->commandSequence = seqNum;

        BUILD_FD(sizeof(t_HcFrame));

        if ((err = EnQFrm(p_FmHc, &fmFd, seqNum)) != E_OK)
        {
            PutBuf(p_FmHc, p_HcFrame, seqNum);
            RETURN_ERROR(MINOR, err, NO_MSG);
        }
    }

    PutBuf(p_FmHc, p_HcFrame, seqNum);
    return err;
}

t_Error FmHcPcdKgDeleteClsPlan(t_Handle h_FmHc, uint8_t  grpId)
{
    t_FmHc                              *p_FmHc = (t_FmHc*)h_FmHc;
    t_FmPcdKgInterModuleClsPlanSet      *p_ClsPlanSet;

    p_ClsPlanSet = (t_FmPcdKgInterModuleClsPlanSet *)XX_Malloc(sizeof(t_FmPcdKgInterModuleClsPlanSet));
    if (!p_ClsPlanSet)
        RETURN_ERROR(MAJOR, E_NO_MEMORY, ("Classification plan set"));

    memset(p_ClsPlanSet, 0, sizeof(t_FmPcdKgInterModuleClsPlanSet));

    p_ClsPlanSet->baseEntry = FmPcdKgGetClsPlanGrpBase(p_FmHc->h_FmPcd, grpId);
    p_ClsPlanSet->numOfClsPlanEntries = FmPcdKgGetClsPlanGrpSize(p_FmHc->h_FmPcd, grpId);
    ASSERT_COND(p_ClsPlanSet->numOfClsPlanEntries <= FM_PCD_MAX_NUM_OF_CLS_PLANS);

    if (FmHcPcdKgSetClsPlan(p_FmHc, p_ClsPlanSet) != E_OK)
    {
        XX_Free(p_ClsPlanSet);
        RETURN_ERROR(MAJOR, E_INVALID_STATE, NO_MSG);
    }

    XX_Free(p_ClsPlanSet);
    FmPcdKgDestroyClsPlanGrp(p_FmHc->h_FmPcd, grpId);

    return E_OK;
}

t_Error FmHcPcdPlcrCcGetSetParams(t_Handle h_FmHc,uint16_t absoluteProfileId, uint32_t requiredAction)
{
    t_FmHc              *p_FmHc = (t_FmHc*)h_FmHc;
    t_HcFrame           *p_HcFrame;
    t_DpaaFD            fmFd;
    t_Error             err;
    uint32_t            tmpReg32 = 0;
    uint32_t            requiredActionTmp, requiredActionFlag;
    uint32_t            seqNum;

    SANITY_CHECK_RETURN_VALUE(h_FmHc, E_INVALID_HANDLE,0);

    /* Profile is locked by calling routine */
    /* WARNING - this lock will not be efficient if other HC routine will attempt to change
     * "fmpl_pegnia" "fmpl_peynia" or "fmpl_pernia" without locking Profile !
     */

    requiredActionTmp = FmPcdPlcrGetRequiredAction(p_FmHc->h_FmPcd, absoluteProfileId);
    requiredActionFlag = FmPcdPlcrGetRequiredActionFlag(p_FmHc->h_FmPcd, absoluteProfileId);

    if (!requiredActionFlag || !(requiredActionTmp & requiredAction))
    {
        if (requiredAction & UPDATE_NIA_ENQ_WITHOUT_DMA)
        {
            p_HcFrame = GetBuf(p_FmHc, &seqNum);
            if (!p_HcFrame)
                RETURN_ERROR(MINOR, E_NO_MEMORY, ("HC Frame object"));
            /* first read scheme and check that it is valid */
            memset(p_HcFrame, 0, sizeof(t_HcFrame));
            p_HcFrame->opcode = (uint32_t)(HC_HCOR_GBL | HC_HCOR_OPCODE_PLCR_PRFL);
            p_HcFrame->actionReg  = FmPcdPlcrBuildReadPlcrActionReg(absoluteProfileId);
            p_HcFrame->extraReg = 0x00008000;
            p_HcFrame->commandSequence = seqNum;

            BUILD_FD(SIZE_OF_HC_FRAME_READ_OR_CC_DYNAMIC);

            if ((err = EnQFrm(p_FmHc, &fmFd, seqNum)) != E_OK)
            {
                PutBuf(p_FmHc, p_HcFrame, seqNum);
                RETURN_ERROR(MINOR, err, NO_MSG);
            }

            tmpReg32 = p_HcFrame->hcSpecificData.profileRegs.fmpl_pegnia;
            if (!(tmpReg32 & (NIA_ENG_BMI | NIA_BMI_AC_ENQ_FRAME)))
            {
                PutBuf(p_FmHc, p_HcFrame, seqNum);
                RETURN_ERROR(MAJOR, E_INVALID_STATE,
                             ("Next engine of this policer profile has to be assigned to FM_PCD_DONE"));
            }

            tmpReg32 |= NIA_BMI_AC_ENQ_FRAME_WITHOUT_DMA;

            p_HcFrame->opcode = (uint32_t)(HC_HCOR_GBL | HC_HCOR_OPCODE_PLCR_PRFL);
            p_HcFrame->actionReg  = FmPcdPlcrBuildWritePlcrActionReg(absoluteProfileId);
            p_HcFrame->actionReg |= FmPcdPlcrBuildNiaProfileReg(TRUE, FALSE, FALSE);
            p_HcFrame->extraReg = 0x00008000;
            p_HcFrame->hcSpecificData.singleRegForWrite = tmpReg32;

            BUILD_FD(SIZE_OF_HC_FRAME_PROFILE_CNT);

            if ((err = EnQFrm(p_FmHc, &fmFd, seqNum)) != E_OK)
            {
                PutBuf(p_FmHc, p_HcFrame, seqNum);
                RETURN_ERROR(MINOR, err, NO_MSG);
            }

            tmpReg32 = p_HcFrame->hcSpecificData.profileRegs.fmpl_peynia;
            if (!(tmpReg32 & (NIA_ENG_BMI | NIA_BMI_AC_ENQ_FRAME)))
            {
                PutBuf(p_FmHc, p_HcFrame, seqNum);
                RETURN_ERROR(MAJOR, E_INVALID_STATE, ("Next engine of this policer profile has to be assigned to FM_PCD_DONE"));
            }

            tmpReg32 |= NIA_BMI_AC_ENQ_FRAME_WITHOUT_DMA;

            p_HcFrame->opcode = (uint32_t)(HC_HCOR_GBL | HC_HCOR_OPCODE_PLCR_PRFL);
            p_HcFrame->actionReg  = FmPcdPlcrBuildWritePlcrActionReg(absoluteProfileId);
            p_HcFrame->actionReg |= FmPcdPlcrBuildNiaProfileReg(FALSE, TRUE, FALSE);
            p_HcFrame->extraReg = 0x00008000;
            p_HcFrame->hcSpecificData.singleRegForWrite = tmpReg32;

            BUILD_FD(SIZE_OF_HC_FRAME_PROFILE_CNT);

            if ((err = EnQFrm(p_FmHc, &fmFd, seqNum)) != E_OK)
            {
                PutBuf(p_FmHc, p_HcFrame, seqNum);
                RETURN_ERROR(MINOR, err, NO_MSG);
            }

            tmpReg32 = p_HcFrame->hcSpecificData.profileRegs.fmpl_pernia;
            if (!(tmpReg32 & (NIA_ENG_BMI | NIA_BMI_AC_ENQ_FRAME)))
            {
                PutBuf(p_FmHc, p_HcFrame, seqNum);
                RETURN_ERROR(MAJOR, E_INVALID_STATE, ("Next engine of this policer profile has to be assigned to FM_PCD_DONE"));
            }

            tmpReg32 |= NIA_BMI_AC_ENQ_FRAME_WITHOUT_DMA;

            p_HcFrame->opcode = (uint32_t)(HC_HCOR_GBL | HC_HCOR_OPCODE_PLCR_PRFL);
            p_HcFrame->actionReg  = FmPcdPlcrBuildWritePlcrActionReg(absoluteProfileId);
            p_HcFrame->actionReg |= FmPcdPlcrBuildNiaProfileReg(FALSE, FALSE, TRUE);
            p_HcFrame->extraReg = 0x00008000;
            p_HcFrame->hcSpecificData.singleRegForWrite = tmpReg32;

            BUILD_FD(SIZE_OF_HC_FRAME_PROFILE_CNT);

            if ((err = EnQFrm(p_FmHc, &fmFd, seqNum)) != E_OK)
            {
                PutBuf(p_FmHc, p_HcFrame, seqNum);
                RETURN_ERROR(MINOR, err, NO_MSG);
            }

            PutBuf(p_FmHc, p_HcFrame, seqNum);
        }
    }

    return E_OK;
}

t_Error FmHcPcdPlcrSetProfile(t_Handle h_FmHc, t_Handle h_Profile, t_FmPcdPlcrProfileRegs *p_PlcrRegs)
{
    t_FmHc                              *p_FmHc = (t_FmHc*)h_FmHc;
    t_Error                             err = E_OK;
    uint16_t                            profileIndx;
    t_HcFrame                           *p_HcFrame;
    t_DpaaFD                            fmFd;
    uint32_t                            seqNum;

    p_HcFrame = GetBuf(p_FmHc, &seqNum);
    if (!p_HcFrame)
        HC_RETURN_FIRST_ERROR(p_FmHc, MINOR, E_NO_MEMORY, ("HC Frame object"));

    profileIndx = FmPcdPlcrProfileGetAbsoluteId(h_Profile);

    memset(p_HcFrame, 0, sizeof(t_HcFrame));
    p_HcFrame->opcode = (uint32_t)(HC_HCOR_GBL | HC_HCOR_OPCODE_PLCR_PRFL);
    p_HcFrame->actionReg  = FmPcdPlcrBuildWritePlcrActionRegs(profileIndx);
    p_HcFrame->extraReg = 0x00008000;
    memcpy(&p_HcFrame->hcSpecificData.profileRegs, p_PlcrRegs, sizeof(t_FmPcdPlcrProfileRegs));
    p_HcFrame->commandSequence = seqNum;

    BUILD_FD(sizeof(t_HcFrame));

    err = EnQFrm(p_FmHc, &fmFd, seqNum);

    PutBuf(p_FmHc, p_HcFrame, seqNum);

    /* A policer's owner writes it again until it lands, once a second while
     * the channel is shut: EnQFrm() reported it, if it was the first of its
     * run. */
    if (err != E_OK)
        return ERROR_CODE(err);

    return E_OK;
}

t_Error FmHcPcdPlcrDeleteProfile(t_Handle h_FmHc, t_Handle h_Profile)
{
    t_FmHc      *p_FmHc = (t_FmHc*)h_FmHc;
    uint16_t    absoluteProfileId = FmPcdPlcrProfileGetAbsoluteId(h_Profile);
    t_Error     err = E_OK;
    t_HcFrame   *p_HcFrame;
    t_DpaaFD    fmFd;
    uint32_t    seqNum;

    p_HcFrame = GetBuf(p_FmHc, &seqNum);
    if (!p_HcFrame)
        RETURN_ERROR(MINOR, E_NO_MEMORY, ("HC Frame object"));
    memset(p_HcFrame, 0, sizeof(t_HcFrame));
    p_HcFrame->opcode = (uint32_t)(HC_HCOR_GBL | HC_HCOR_OPCODE_PLCR_PRFL);
    p_HcFrame->actionReg  = FmPcdPlcrBuildWritePlcrActionReg(absoluteProfileId);
    p_HcFrame->actionReg  |= 0x00008000;
    p_HcFrame->extraReg = 0x00008000;
    memset(&p_HcFrame->hcSpecificData.profileRegs, 0, sizeof(t_FmPcdPlcrProfileRegs));
    p_HcFrame->commandSequence = seqNum;

    BUILD_FD(sizeof(t_HcFrame));

    err = EnQFrm(p_FmHc, &fmFd, seqNum);

    PutBuf(p_FmHc, p_HcFrame, seqNum);

    if (err != E_OK)
        RETURN_ERROR(MINOR, err, NO_MSG);

    return E_OK;
}

t_Error  FmHcPcdPlcrSetProfileCounter(t_Handle h_FmHc, t_Handle h_Profile, e_FmPcdPlcrProfileCounters counter, uint32_t value)
{

    t_FmHc      *p_FmHc = (t_FmHc*)h_FmHc;
    uint16_t    absoluteProfileId = FmPcdPlcrProfileGetAbsoluteId(h_Profile);
    t_Error     err = E_OK;
    t_HcFrame   *p_HcFrame;
    t_DpaaFD    fmFd;
    uint32_t    seqNum;

    /* first read scheme and check that it is valid */
    p_HcFrame = GetBuf(p_FmHc, &seqNum);
    if (!p_HcFrame)
        RETURN_ERROR(MINOR, E_NO_MEMORY, ("HC Frame object"));
    memset(p_HcFrame, 0, sizeof(t_HcFrame));
    p_HcFrame->opcode = (uint32_t)(HC_HCOR_GBL | HC_HCOR_OPCODE_PLCR_PRFL);
    p_HcFrame->actionReg  = FmPcdPlcrBuildWritePlcrActionReg(absoluteProfileId);
    p_HcFrame->actionReg |= FmPcdPlcrBuildCounterProfileReg(counter);
    p_HcFrame->extraReg = 0x00008000;
    p_HcFrame->hcSpecificData.singleRegForWrite = value;
    p_HcFrame->commandSequence = seqNum;

    BUILD_FD(SIZE_OF_HC_FRAME_PROFILE_CNT);

    err = EnQFrm(p_FmHc, &fmFd, seqNum);

    PutBuf(p_FmHc, p_HcFrame, seqNum);

    if (err != E_OK)
        RETURN_ERROR(MINOR, err, NO_MSG);

    return E_OK;
}

t_Error FmHcPcdPlcrReadProfileCounters(t_Handle h_FmHc, t_Handle h_Profile, t_FmPcdPlcrProfileCounterValues *p_Values)
{
    t_FmHc      *p_FmHc = (t_FmHc*)h_FmHc;
    uint16_t    absoluteProfileId = FmPcdPlcrProfileGetAbsoluteId(h_Profile);
    t_Error     err;
    t_HcFrame   *p_HcFrame;
    t_DpaaFD    fmFd;
    uint32_t    seqNum;

    SANITY_CHECK_RETURN_ERROR(h_FmHc, E_INVALID_HANDLE);

    p_HcFrame = GetBuf(p_FmHc, &seqNum);
    if (!p_HcFrame)
        HC_RETURN_FIRST_ERROR(p_FmHc, MINOR, E_NO_MEMORY, ("HC Frame object"));
    memset(p_HcFrame, 0, sizeof(t_HcFrame));
    p_HcFrame->opcode = (uint32_t)(HC_HCOR_GBL | HC_HCOR_OPCODE_PLCR_PRFL);
    p_HcFrame->actionReg  = FmPcdPlcrBuildReadPlcrActionReg(absoluteProfileId);
    p_HcFrame->extraReg = 0x00008000;
    p_HcFrame->commandSequence = seqNum;

    BUILD_FD(SIZE_OF_HC_FRAME_READ_OR_CC_DYNAMIC);

    err = EnQFrm(p_FmHc, &fmFd, seqNum);
    if (err == E_OK)
    {
        p_Values->green = p_HcFrame->hcSpecificData.profileRegs.fmpl_pegpc;
        p_Values->yellow = p_HcFrame->hcSpecificData.profileRegs.fmpl_peypc;
        p_Values->red = p_HcFrame->hcSpecificData.profileRegs.fmpl_perpc;
        p_Values->recolouredYellow = p_HcFrame->hcSpecificData.profileRegs.fmpl_perypc;
        p_Values->recolouredRed = p_HcFrame->hcSpecificData.profileRegs.fmpl_perrpc;
    }
    PutBuf(p_FmHc, p_HcFrame, seqNum);
    /* Read again on every stats dump: EnQFrm() reported it, if it was the
     * first of its run. */
    if (err != E_OK)
        return ERROR_CODE(err);
    return E_OK;
}

uint32_t FmHcPcdPlcrGetProfileCounter(t_Handle h_FmHc, t_Handle h_Profile, e_FmPcdPlcrProfileCounters counter)
{
    t_FmPcdPlcrProfileCounterValues values;

    if (FmHcPcdPlcrReadProfileCounters(h_FmHc, h_Profile, &values) != E_OK)
        return 0;
    switch (counter)
    {
        case e_FM_PCD_PLCR_PROFILE_GREEN_PACKET_TOTAL_COUNTER:
            return values.green;
        case e_FM_PCD_PLCR_PROFILE_YELLOW_PACKET_TOTAL_COUNTER:
            return values.yellow;
        case e_FM_PCD_PLCR_PROFILE_RED_PACKET_TOTAL_COUNTER:
            return values.red;
        case e_FM_PCD_PLCR_PROFILE_RECOLOURED_YELLOW_PACKET_TOTAL_COUNTER:
            return values.recolouredYellow;
        case e_FM_PCD_PLCR_PROFILE_RECOLOURED_RED_PACKET_TOTAL_COUNTER:
            return values.recolouredRed;
        default:
            REPORT_ERROR(MAJOR, E_INVALID_SELECTION, NO_MSG);
            return 0;
    }
}

t_Error FmHcKgWriteSp(t_Handle h_FmHc, uint8_t hardwarePortId, uint32_t spReg, bool add)
{
    t_FmHc                  *p_FmHc = (t_FmHc*)h_FmHc;
    t_HcFrame               *p_HcFrame;
    t_DpaaFD                fmFd;
    t_Error                 err = E_OK;
    uint32_t                seqNum;

    ASSERT_COND(p_FmHc);

    p_HcFrame = GetBuf(p_FmHc, &seqNum);
    if (!p_HcFrame)
        RETURN_ERROR(MINOR, E_NO_MEMORY, ("HC Frame object"));
    memset(p_HcFrame, 0, sizeof(t_HcFrame));
    /* first read SP register */
    p_HcFrame->opcode = (uint32_t)(HC_HCOR_GBL | HC_HCOR_OPCODE_KG_SCM);
    p_HcFrame->actionReg  = FmPcdKgBuildReadPortSchemeBindActionReg(hardwarePortId);
    p_HcFrame->extraReg = HC_HCOR_KG_SCHEME_REGS_MASK;
    p_HcFrame->commandSequence = seqNum;

    BUILD_FD(SIZE_OF_HC_FRAME_PORT_REGS);

    if ((err = EnQFrm(p_FmHc, &fmFd, seqNum)) != E_OK)
    {
        PutBuf(p_FmHc, p_HcFrame, seqNum);
        RETURN_ERROR(MINOR, err, NO_MSG);
    }

    /* spReg is the first reg, so we can use it both for read and for write */
    if (add)
        p_HcFrame->hcSpecificData.portRegsForRead.spReg |= spReg;
    else
        p_HcFrame->hcSpecificData.portRegsForRead.spReg &= ~spReg;

    p_HcFrame->actionReg  = FmPcdKgBuildWritePortSchemeBindActionReg(hardwarePortId);

    BUILD_FD(sizeof(t_HcFrame));

    err = EnQFrm(p_FmHc, &fmFd, seqNum);

    PutBuf(p_FmHc, p_HcFrame, seqNum);

    if (err != E_OK)
        RETURN_ERROR(MINOR, err, NO_MSG);

    return E_OK;
}

t_Error FmHcKgWriteCpp(t_Handle h_FmHc, uint8_t hardwarePortId, uint32_t cppReg)
{
    t_FmHc                  *p_FmHc = (t_FmHc*)h_FmHc;
    t_HcFrame               *p_HcFrame;
    t_DpaaFD                fmFd;
    t_Error                 err = E_OK;
    uint32_t                seqNum;

    ASSERT_COND(p_FmHc);

    p_HcFrame = GetBuf(p_FmHc, &seqNum);
    if (!p_HcFrame)
        RETURN_ERROR(MINOR, E_NO_MEMORY, ("HC Frame object"));
    memset(p_HcFrame, 0, sizeof(t_HcFrame));
    /* first read SP register */
    p_HcFrame->opcode = (uint32_t)(HC_HCOR_GBL | HC_HCOR_OPCODE_KG_SCM);
    p_HcFrame->actionReg  = FmPcdKgBuildWritePortClsPlanBindActionReg(hardwarePortId);
    p_HcFrame->extraReg = HC_HCOR_KG_SCHEME_REGS_MASK;
    p_HcFrame->hcSpecificData.singleRegForWrite = cppReg;
    p_HcFrame->commandSequence = seqNum;

    BUILD_FD(sizeof(t_HcFrame));

    err = EnQFrm(p_FmHc, &fmFd, seqNum);

    PutBuf(p_FmHc, p_HcFrame, seqNum);

    if (err != E_OK)
        RETURN_ERROR(MINOR, err, NO_MSG);

    return E_OK;
}

t_Error FmHcPcdCcDoDynamicChange(t_Handle h_FmHc, uint32_t oldAdAddrOffset, uint32_t newAdAddrOffset)
{
    t_FmHc                  *p_FmHc = (t_FmHc*)h_FmHc;
    t_HcFrame               *p_HcFrame;
    t_DpaaFD                fmFd;
    t_Error                 err = E_OK;
    uint32_t                seqNum;

    SANITY_CHECK_RETURN_ERROR(p_FmHc, E_INVALID_HANDLE);

    p_HcFrame = GetBuf(p_FmHc, &seqNum);
    if (!p_HcFrame)
        RETURN_ERROR(MINOR, E_NO_MEMORY, ("HC Frame object"));
    memset(p_HcFrame, 0, sizeof(t_HcFrame));

    p_HcFrame->opcode     = (uint32_t)(HC_HCOR_GBL | HC_HCOR_OPCODE_CC);
    p_HcFrame->actionReg  = newAdAddrOffset;
    p_HcFrame->actionReg |= 0xc0000000;
    p_HcFrame->extraReg   = oldAdAddrOffset;
    p_HcFrame->commandSequence = seqNum;

    BUILD_FD(SIZE_OF_HC_FRAME_READ_OR_CC_DYNAMIC);

    err = EnQFrm(p_FmHc, &fmFd, seqNum);

    PutBuf(p_FmHc, p_HcFrame, seqNum);

    if (err != E_OK)
        RETURN_ERROR(MAJOR, err, NO_MSG);

    return E_OK;
}

t_Error FmHcPcdSync(t_Handle h_FmHc)
{
    t_FmHc                  *p_FmHc = (t_FmHc*)h_FmHc;
    t_HcFrame               *p_HcFrame;
    t_DpaaFD                fmFd;
    t_Error                 err = E_OK;
    uint32_t                seqNum;

    ASSERT_COND(p_FmHc);

    /* The one command a waiter retries on a timer: both failures below
     * repeat on every retry once the channel is gone. */
    p_HcFrame = GetBuf(p_FmHc, &seqNum);
    if (!p_HcFrame)
        HC_RETURN_FIRST_ERROR(p_FmHc, MINOR, E_NO_MEMORY, ("HC Frame object"));
    memset(p_HcFrame, 0, sizeof(t_HcFrame));
    /* first read SP register */
    p_HcFrame->opcode = (uint32_t)(HC_HCOR_GBL | HC_HCOR_OPCODE_SYNC);
    p_HcFrame->actionReg = 0;
    p_HcFrame->extraReg = 0;
    p_HcFrame->commandSequence = seqNum;

    BUILD_FD(sizeof(t_HcFrame));

    err = EnQFrm(p_FmHc, &fmFd, seqNum);

    PutBuf(p_FmHc, p_HcFrame, seqNum);

    /* EnQFrm() reported it, if it was the first of its run. */
    if (err != E_OK)
        return ERROR_CODE(err);

    return E_OK;
}

t_Error FmAllowHcUsage(t_Handle h_FmHc, bool allow)
{
    t_FmHc *p_FmHc = (t_FmHc*)h_FmHc;
    uint32_t flags;
    t_Error err = E_OK;

    if (!p_FmHc)
        return E_OK;
    flags = HcLock(p_FmHc);
    if (p_FmHc->quiescing)
        err = ERROR_CODE(E_INVALID_STATE);
    else if (p_FmHc->nextSeqNumLocation || HcUnanswered(p_FmHc))
        err = ERROR_CODE(E_BUSY);
    else
        p_FmHc->usageAllowed = allow;
    HcUnlock(p_FmHc, flags);
    return err;
}

bool FmIsHcUsageAllowed(t_Handle h_FmHc)
{
	t_FmHc *p_FmHc = (t_FmHc*)h_FmHc;
	uint32_t flags;
	bool allowed;

	if (p_FmHc == NULL)
		return FALSE;

	/* Never direct while an unanswered command may still be inside the
	 * port: a register write would race it. */
	flags = HcLock(p_FmHc);
	allowed = p_FmHc->usageAllowed || HcUnanswered(p_FmHc);
	HcUnlock(p_FmHc, flags);
	return allowed;
}
