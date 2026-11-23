/* Copyright (c) 2008-2012 Freescale Semiconductor, Inc.
 * All rights reserved.
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


/**************************************************************************//**
 @File          fm_port_ext.h

 @Description   FM-Port Application Programming Interface.
*//***************************************************************************/
#ifndef __FM_PORT_EXT
#define __FM_PORT_EXT

#include "error_ext.h"
#include "std_ext.h"
#include "fm_pcd_ext.h"
#include "fm_ext.h"
#include "net_ext.h"


/**************************************************************************//**

 @Group         FM_grp Frame Manager API

 @Description   FM API functions, definitions and enums

 @{
*//***************************************************************************/

/**************************************************************************//**
 @Group         FM_PORT_grp FM Port

 @Description   FM Port API

                The FM uses a general module called "port" to represent a Tx port
                (MAC), an Rx port (MAC) or Offline Parsing port.
                The number of ports in an FM varies between SOCs.
                The SW driver manages these ports as sub-modules of the FM, i.e.
                after an FM is initialized, its ports may be initialized and
                operated upon.

                The port is initialized aware of its type, but other functions on
                a port may be indifferent to its type. When necessary, the driver
                verifies coherence and returns error if applicable.

                On initialization, user specifies the port type and it's index
                (relative to the port's type) - always starting at 0.

 @{
*//***************************************************************************/

/**************************************************************************//**
 @Description   An enum for defining port PCD modes.
                This enum defines the superset of PCD engines support - i.e. not
                all engines have to be used, but all have to be enabled. The real
                flow of a specific frame depends on the PCD configuration and the
                frame headers and payload.
                Note: the first engine and the first engine after the parser (if
                exists) should be in order, the order is important as it will
                define the flow of the port. However, as for the rest engines
                (the ones that follows), the order is not important anymore as
                it is defined by the PCD graph itself.
*//***************************************************************************/
typedef enum e_FmPortPcdSupport {
      e_FM_PORT_PCD_SUPPORT_NONE = 0                /**< BMI to BMI, PCD is not used */
    , e_FM_PORT_PCD_SUPPORT_PRS_ONLY                /**< Use only Parser */
    , e_FM_PORT_PCD_SUPPORT_PLCR_ONLY               /**< Use only Policer */
    , e_FM_PORT_PCD_SUPPORT_PRS_AND_PLCR            /**< Use Parser and Policer */
    , e_FM_PORT_PCD_SUPPORT_PRS_AND_KG              /**< Use Parser and Keygen */
    , e_FM_PORT_PCD_SUPPORT_PRS_AND_KG_AND_CC       /**< Use Parser, Keygen and Coarse Classification */
    , e_FM_PORT_PCD_SUPPORT_PRS_AND_KG_AND_CC_AND_PLCR
                                                    /**< Use all PCD engines */
    , e_FM_PORT_PCD_SUPPORT_PRS_AND_KG_AND_PLCR     /**< Use Parser, Keygen and Policer */
    , e_FM_PORT_PCD_SUPPORT_PRS_AND_CC              /**< Use Parser and Coarse Classification */
    , e_FM_PORT_PCD_SUPPORT_PRS_AND_CC_AND_PLCR     /**< Use Parser and Coarse Classification and Policer */
    , e_FM_PORT_PCD_SUPPORT_CC_ONLY                 /**< Use only Coarse Classification */
} e_FmPortPcdSupport;

/**************************************************************************//**
 @Description   Port interrupts
*//***************************************************************************/
typedef enum e_FmPortExceptions {
    e_FM_PORT_EXCEPTION_IM_BUSY                 /**< Independent-Mode Rx-BUSY */
} e_FmPortExceptions;


/**************************************************************************//**
 @Collection    General FM Port defines
*//***************************************************************************/
#define FM_PORT_PRS_RESULT_NUM_OF_WORDS     8   /**< Number of 4 bytes words in parser result */
/* @} */

/**************************************************************************//**
 @Collection   FM Frame error
*//***************************************************************************/
typedef uint32_t    fmPortFrameErrSelect_t;                         /**< typedef for defining Frame Descriptor errors */

#define FM_PORT_FRM_ERR_UNSUPPORTED_FORMAT      FM_FD_ERR_UNSUPPORTED_FORMAT    /**< Not for Rx-Port! Unsupported Format */
#define FM_PORT_FRM_ERR_LENGTH                  FM_FD_ERR_LENGTH                /**< Not for Rx-Port! Length Error */
#define FM_PORT_FRM_ERR_DMA                     FM_FD_ERR_DMA                   /**< DMA Data error */
#define FM_PORT_FRM_ERR_NON_FM                  FM_FD_RX_STATUS_ERR_NON_FM      /**< non Frame-Manager error; probably come from SEC that
                                                                                     was chained to FM */

#define FM_PORT_FRM_ERR_IPRE                    (FM_FD_ERR_IPR & ~FM_FD_IPR)        /**< IPR error */
#define FM_PORT_FRM_ERR_IPR_NCSP                (FM_FD_ERR_IPR_NCSP & ~FM_FD_IPR)   /**< IPR non-consistent-sp */

#define FM_PORT_FRM_ERR_IPFE                    0                                   /**< Obsolete; will be removed in the future */

#define FM_PORT_FRM_ERR_PHYSICAL                FM_FD_ERR_PHYSICAL              /**< Rx FIFO overflow, FCS error, code error, running disparity
                                                                                     error (SGMII and TBI modes), FIFO parity error. PHY
                                                                                     Sequence error, PHY error control character detected. */
#define FM_PORT_FRM_ERR_SIZE                    FM_FD_ERR_SIZE                  /**< Frame too long OR Frame size exceeds max_length_frame  */
#define FM_PORT_FRM_ERR_CLS_DISCARD             FM_FD_ERR_CLS_DISCARD           /**< indicates a classifier "drop" operation */
#define FM_PORT_FRM_ERR_EXTRACTION              FM_FD_ERR_EXTRACTION            /**< Extract Out of Frame */
#define FM_PORT_FRM_ERR_NO_SCHEME               FM_FD_ERR_NO_SCHEME             /**< No Scheme Selected */
#define FM_PORT_FRM_ERR_KEYSIZE_OVERFLOW        FM_FD_ERR_KEYSIZE_OVERFLOW      /**< Keysize Overflow */
#define FM_PORT_FRM_ERR_COLOR_RED               FM_FD_ERR_COLOR_RED             /**< Frame color is red */
#define FM_PORT_FRM_ERR_COLOR_YELLOW            FM_FD_ERR_COLOR_YELLOW          /**< Frame color is yellow */
#define FM_PORT_FRM_ERR_ILL_PLCR                FM_FD_ERR_ILL_PLCR              /**< Illegal Policer Profile selected */
#define FM_PORT_FRM_ERR_PLCR_FRAME_LEN          FM_FD_ERR_PLCR_FRAME_LEN        /**< Policer frame length error */
#define FM_PORT_FRM_ERR_PRS_TIMEOUT             FM_FD_ERR_PRS_TIMEOUT           /**< Parser Time out Exceed */
#define FM_PORT_FRM_ERR_PRS_ILL_INSTRUCT        FM_FD_ERR_PRS_ILL_INSTRUCT      /**< Invalid Soft Parser instruction */
#define FM_PORT_FRM_ERR_PRS_HDR_ERR             FM_FD_ERR_PRS_HDR_ERR           /**< Header error was identified during parsing */
#define FM_PORT_FRM_ERR_BLOCK_LIMIT_EXCEEDED    FM_FD_ERR_BLOCK_LIMIT_EXCEEDED  /**< Frame parsed beyind 256 first bytes */
#define FM_PORT_FRM_ERR_PROCESS_TIMEOUT         0x00000001                      /**< FPM Frame Processing Timeout Exceeded */
/* @} */



/**************************************************************************//**
 @Group         FM_PORT_init_grp FM Port Initialization Unit

 @Description   FM Port Initialization Unit

 @{
*//***************************************************************************/

/**************************************************************************//**
 @Description   Exceptions user callback routine, will be called upon an
                exception passing the exception identification.

 @Param[in]     h_App      - User's application descriptor.
 @Param[in]     exception  - The exception.
  *//***************************************************************************/
typedef void (t_FmPortExceptionCallback) (t_Handle h_App, e_FmPortExceptions exception);

/**************************************************************************//**
 @Description   User callback function called by driver with received data.

                User provides this function. Driver invokes it.

 @Param[in]     h_App           Application's handle originally specified to
                                the API Config function
 @Param[in]     p_Data          A pointer to data received
 @Param[in]     length          length of received data
 @Param[in]     status          receive status and errors
 @Param[in]     position        position of buffer in frame
 @Param[in]     h_BufContext    A handle of the user acossiated with this buffer

 @Retval        e_RX_STORE_RESPONSE_CONTINUE - order the driver to continue Rx
                                               operation for all ready data.
 @Retval        e_RX_STORE_RESPONSE_PAUSE    - order the driver to stop Rx operation.
*//***************************************************************************/
typedef e_RxStoreResponse (t_FmPortImRxStoreCallback) (t_Handle h_App,
                                                       uint8_t  *p_Data,
                                                       uint16_t length,
                                                       uint16_t status,
                                                       uint8_t  position,
                                                       t_Handle h_BufContext);

/**************************************************************************//**
 @Description   User callback function called by driver when transmit completed.

                User provides this function. Driver invokes it.

 @Param[in]     h_App           Application's handle originally specified to
                                the API Config function
 @Param[in]     p_Data          A pointer to data received
 @Param[in]     status          transmit status and errors
 @Param[in]     lastBuffer      is last buffer in frame
 @Param[in]     h_BufContext    A handle of the user acossiated with this buffer
 *//***************************************************************************/
typedef void (t_FmPortImTxConfCallback) (t_Handle   h_App,
                                         uint8_t    *p_Data,
                                         uint16_t   status,
                                         t_Handle   h_BufContext);

/**************************************************************************//**
 @Description   A structure for additional Rx port parameters
*//***************************************************************************/
typedef struct t_FmPortRxParams {
    uint32_t                errFqid;            /**< Error Queue Id. */
    uint32_t                dfltFqid;           /**< Default Queue Id.  */
    uint16_t                liodnOffset;        /**< Port's LIODN offset. */
    t_FmExtPools            extBufPools;        /**< Which external buffer pools are used
                                                     (up to FM_PORT_MAX_NUM_OF_EXT_POOLS), and their sizes. */
} t_FmPortRxParams;

/**************************************************************************//**
 @Description   A structure for additional non-Rx port parameters
*//***************************************************************************/
typedef struct t_FmPortNonRxParams {
    uint32_t                errFqid;            /**< Error Queue Id. */
    uint32_t                dfltFqid;           /**< For Tx - Default Confirmation queue,
                                                     0 means no Tx confirmation for processed
                                                     frames. For OP port - default Rx queue. */
    uint32_t                qmChannel;          /**< QM-channel dedicated to this port; will be used
                                                     by the FM for dequeue. */
    uint16_t                liodnOffset;        /**< Port's LIODN offset. */
} t_FmPortNonRxParams;

/**************************************************************************//**
 @Description   A structure for additional Rx port parameters
*//***************************************************************************/
typedef struct t_FmPortImRxTxParams {
    t_Handle                    h_FmMuram;          /**< A handle of the FM-MURAM partition */
    uint16_t                    liodnOffset;        /**< For Rx ports only. Port's LIODN Offset. */
    uint8_t                     dataMemId;          /**< Memory partition ID for data buffers */
    uint32_t                    dataMemAttributes;  /**< Memory attributes for data buffers */
    t_BufferPoolInfo            rxPoolParams;       /**< For Rx ports only. */
    t_FmPortImRxStoreCallback   *f_RxStore;         /**< For Rx ports only. */
    t_FmPortImTxConfCallback    *f_TxConf;          /**< For Tx ports only. */
} t_FmPortImRxTxParams;

/**************************************************************************//**
 @Description   A union for additional parameters depending on port type
*//***************************************************************************/
typedef union u_FmPortSpecificParams {
    t_FmPortImRxTxParams        imRxTxParams;       /**< Rx/Tx Independent-Mode port parameter structure */
    t_FmPortRxParams            rxParams;           /**< Rx port parameters structure */
    t_FmPortNonRxParams         nonRxParams;        /**< Non-Rx port parameters structure */
} u_FmPortSpecificParams;

/**************************************************************************//**
 @Description   A structure representing FM initialization parameters
*//***************************************************************************/
typedef struct t_FmPortParams {
    uintptr_t                   baseAddr;           /**< Virtual Address of memory mapped FM Port registers.*/
    t_Handle                    h_Fm;               /**< A handle to the FM object this port related to */
    e_FmPortType                portType;           /**< Port type */
    uint8_t                     portId;             /**< Port Id - relative to type;
                                                         NOTE: When configuring Offline Parsing port for
                                                         FMANv3 devices (DPAA_VERSION 11 and higher),
                                                         it is highly recommended NOT to use portId=0 due to lack
                                                         of HW resources on portId=0. */
    bool                        independentModeEnable;
                                                    /**< This port is Independent-Mode - Used for Rx/Tx ports only! */
    uint16_t                    liodnBase;          /**< Irrelevant for P4080 rev 1. LIODN base for this port, to be
                                                         used together with LIODN offset. */
    u_FmPortSpecificParams      specificParams;     /**< Additional parameters depending on port
                                                         type. */

    t_FmPortExceptionCallback   *f_Exception;       /**< Relevant for IM only Callback routine to be called on BUSY exception */
    t_Handle                    h_App;              /**< A handle to an application layer object; This handle will
                                                         be passed by the driver upon calling the above callbacks */
} t_FmPortParams;


/**************************************************************************//**
 @Function      FM_PORT_Config

 @Description   Creates a descriptor for the FM PORT module.

                The routine returns a handle (descriptor) to the FM PORT object.
                This descriptor must be passed as first parameter to all other
                FM PORT function calls.

                No actual initialization or configuration of FM hardware is
                done by this routine.

 @Param[in]     p_FmPortParams   - Pointer to data structure of parameters

 @Retval        Handle to FM object, or NULL for Failure.
*//***************************************************************************/
t_Handle FM_PORT_Config(t_FmPortParams *p_FmPortParams);

/**************************************************************************//**
 @Function      FM_PORT_Init

 @Description   Initializes the FM PORT module by defining the software structure
                and configuring the hardware registers.

 @Param[in]     h_FmPort - FM PORT module descriptor

 @Return        E_OK on success; Error code otherwise.
*//***************************************************************************/
t_Error FM_PORT_Init(t_Handle h_FmPort);

/**************************************************************************//**
 @Function      FM_PORT_Free

 @Description   Frees all resources that were assigned to FM PORT module.

                Calling this routine invalidates the descriptor.

 @Param[in]     h_FmPort - FM PORT module descriptor

 @Return        E_OK on success; Error code otherwise.
*//***************************************************************************/
t_Error FM_PORT_Free(t_Handle h_FmPort);


/**************************************************************************//**
 @Group         FM_PORT_advanced_init_grp    FM Port Advanced Configuration Unit

 @Description   Configuration functions used to change default values.

 @{
*//***************************************************************************/

/**************************************************************************//**
 @Description   enum for defining QM frame dequeue
*//***************************************************************************/
typedef enum e_FmPortDeqType {
   e_FM_PORT_DEQ_TYPE1,             /**< Dequeue from the SP channel - with priority precedence,
                                         and Intra-Class Scheduling respected. */
   e_FM_PORT_DEQ_TYPE2,             /**< Dequeue from the SP channel - with active FQ precedence,
                                         and Intra-Class Scheduling respected. */
   e_FM_PORT_DEQ_TYPE3              /**< Dequeue from the SP channel - with active FQ precedence,
                                         and override Intra-Class Scheduling */
} e_FmPortDeqType;

/**************************************************************************//**
 @Description   enum for defining QM frame dequeue
*//***************************************************************************/
typedef enum e_FmPortDeqPrefetchOption {
   e_FM_PORT_DEQ_NO_PREFETCH,       /**< QMI preforms a dequeue action for a single frame
                                         only when a dedicated portID Tnum is waiting. */
   e_FM_PORT_DEQ_PARTIAL_PREFETCH,  /**< QMI preforms a dequeue action for 3 frames when
                                         one dedicated portId tnum is waiting. */
   e_FM_PORT_DEQ_FULL_PREFETCH      /**< QMI preforms a dequeue action for 3 frames when
                                         no dedicated portId tnums are waiting. */

} e_FmPortDeqPrefetchOption;

/**************************************************************************//**
 @Description   enum for defining port default color
*//***************************************************************************/
typedef enum e_FmPortColor {
    e_FM_PORT_COLOR_GREEN,          /**< Default port color is green */
    e_FM_PORT_COLOR_YELLOW,         /**< Default port color is yellow */
    e_FM_PORT_COLOR_RED,            /**< Default port color is red */
    e_FM_PORT_COLOR_OVERRIDE        /**< Ignore color */
} e_FmPortColor;

/**************************************************************************//**
 @Description   A structure for defining Dual Tx rate limiting scale
*//***************************************************************************/
typedef enum e_FmPortDualRateLimiterScaleDown {
    e_FM_PORT_DUAL_RATE_LIMITER_NONE = 0,           /**< Use only single rate limiter  */
    e_FM_PORT_DUAL_RATE_LIMITER_SCALE_DOWN_BY_2,    /**< Divide high rate limiter by 2 */
    e_FM_PORT_DUAL_RATE_LIMITER_SCALE_DOWN_BY_4,    /**< Divide high rate limiter by 4 */
    e_FM_PORT_DUAL_RATE_LIMITER_SCALE_DOWN_BY_8     /**< Divide high rate limiter by 8 */
} e_FmPortDualRateLimiterScaleDown;


/**************************************************************************//**
 @Description   A structure for defining FM port resources
*//***************************************************************************/
typedef struct t_FmPortRsrc {
    uint32_t    num;                /**< Committed required resource */
    uint32_t    extra;              /**< Extra (not committed) required resource */
} t_FmPortRsrc;

/**************************************************************************//**
 @Description   A structure for defining observed pool depletion
*//***************************************************************************/
typedef struct t_FmPortObservedBufPoolDepletion {
    t_FmBufPoolDepletion    poolDepletionParams;/**< parameters to define pool depletion */
    t_FmExtPools            poolsParams;        /**< Which external buffer pools are observed
                                                     (up to FM_PORT_MAX_NUM_OF_OBSERVED_EXT_POOLS),
                                                     and their sizes. */
} t_FmPortObservedBufPoolDepletion;

/**************************************************************************//**
 @Description   A structure for defining Tx rate limiting
*//***************************************************************************/
typedef struct t_FmPortRateLimit {
    uint16_t                            maxBurstSize;           /**< in KBytes for Tx ports, in frames
                                                                     for OP ports. (note that
                                                                     for early chips burst size is
                                                                     rounded up to a multiply of 1000 frames).*/
    uint32_t                            rateLimit;              /**< in Kb/sec for Tx ports, in frame/sec for
                                                                     OP ports. Rate limit refers to
                                                                     data rate (rather than line rate). */
    e_FmPortDualRateLimiterScaleDown    rateLimitDivider;       /**< For OP ports only. Not-valid
                                                                     for some earlier chip revisions */
} t_FmPortRateLimit;

/**************************************************************************//**
 @Description   A structure for defining the parameters of
                the Rx port performance counters
*//***************************************************************************/
typedef struct t_FmPortPerformanceCnt {
    uint8_t     taskCompVal;            /**< Task compare value */
    uint8_t     queueCompVal;           /**< Rx queue/Tx confirm queue compare
                                             value (unused for H/O) */
    uint8_t     dmaCompVal;             /**< Dma compare value */
    uint32_t    fifoCompVal;            /**< Fifo compare value (in bytes) */
} t_FmPortPerformanceCnt;

/**************************************************************************//**
 @Function      FM_PORT_ConfigNumOfOpenDmas

 @Description   Calling this routine changes the max number of open DMA's
                available for this port. It changes this parameter in the
                internal driver data base from its default configuration
                [OP: 1]
                [1G-RX, 1G-TX: 1 (+1)]
                [10G-RX, 10G-TX: 8 (+8)]

 @Param[in]     h_FmPort    A handle to a FM Port module.
 @Param[in]     p_OpenDmas  A pointer to a structure of parameters defining
                            the open DMA allocation.

 @Return        E_OK on success; Error code otherwise.

 @Cautions      Allowed only following FM_PORT_Config() and before FM_PORT_Init().
*//***************************************************************************/
t_Error FM_PORT_ConfigNumOfOpenDmas(t_Handle h_FmPort, t_FmPortRsrc *p_OpenDmas);

/**************************************************************************//**
 @Function      FM_PORT_ConfigNumOfTasks

 @Description   Calling this routine changes the max number of tasks
                available for this port. It changes this parameter in the
                internal driver data base from its default configuration
                [OP: 1]
                [1G-RX, 1G-TX: 3 (+2)]
                [10G-RX, 10G-TX: 16 (+8)]

 @Param[in]     h_FmPort        A handle to a FM Port module.
 @Param[in]     p_NumOfTasks    A pointer to a structure of parameters defining
                                the tasks allocation.

 @Return        E_OK on success; Error code otherwise.

 @Cautions      Allowed only following FM_PORT_Config() and before FM_PORT_Init().
*//***************************************************************************/
t_Error FM_PORT_ConfigNumOfTasks(t_Handle h_FmPort, t_FmPortRsrc *p_NumOfTasks);

/**************************************************************************//**
 @Function      FM_PORT_ConfigSizeOfFifo

 @Description   Calling this routine changes the max FIFO size configured for this port.

                This function changes the internal driver data base from its
                default configuration. Please refer to the driver's User Guide for
                information on default FIFO sizes in the various devices.
                [OP: 2KB]
                [1G-RX, 1G-TX: 11KB]
                [10G-RX, 10G-TX: 12KB]

 @Param[in]     h_FmPort        A handle to a FM Port module.
 @Param[in]     p_SizeOfFifo    A pointer to a structure of parameters defining
                                the FIFO allocation.

 @Return        E_OK on success; Error code otherwise.

 @Cautions      Allowed only following FM_PORT_Config() and before FM_PORT_Init().
*//***************************************************************************/
t_Error FM_PORT_ConfigSizeOfFifo(t_Handle h_FmPort, t_FmPortRsrc *p_SizeOfFifo);

/**************************************************************************//**
 @Function      FM_PORT_ConfigDeqHighPriority

 @Description   Calling this routine changes the dequeue priority in the
                internal driver data base from its default configuration
                1G: [DEFAULT_PORT_deqHighPriority_1G]
                10G: [DEFAULT_PORT_deqHighPriority_10G]

                May be used for Non-Rx ports only

 @Param[in]     h_FmPort    A handle to a FM Port module.
 @Param[in]     highPri     TRUE to select high priority, FALSE for normal operation.

 @Return        E_OK on success; Error code otherwise.

 @Cautions      Allowed only following FM_PORT_Config() and before FM_PORT_Init().
*//***************************************************************************/
t_Error FM_PORT_ConfigDeqHighPriority(t_Handle h_FmPort, bool highPri);

/**************************************************************************//**
 @Function      FM_PORT_ConfigDeqPrefetchOption

 @Description   Calling this routine changes the dequeue prefetch option parameter in the
                internal driver data base from its default configuration
                [DEFAULT_PORT_deqPrefetchOption]
                Note: Available for some chips only

                May be used for Non-Rx ports only

 @Param[in]     h_FmPort            A handle to a FM Port module.
 @Param[in]     deqPrefetchOption   New option

 @Return        E_OK on success; Error code otherwise.

 @Cautions      Allowed only following FM_PORT_Config() and before FM_PORT_Init().
*//***************************************************************************/
t_Error FM_PORT_ConfigDeqPrefetchOption(t_Handle h_FmPort, e_FmPortDeqPrefetchOption deqPrefetchOption);

/**************************************************************************//**
 @Function      FM_PORT_ConfigBufferPrefixContent

 @Description   Defines the structure, size and content of the application buffer.
                The prefix will
                In Tx ports, if 'passPrsResult', the application
                should set a value to their offsets in the prefix of
                the FM will save the first 'privDataSize', than,
                depending on 'passPrsResult' and 'passTimeStamp', copy parse result
                and timeStamp, and the packet itself (in this order), to the
                application buffer, and to offset.
                Calling this routine changes the buffer margins definitions
                in the internal driver data base from its default
                configuration: Data size:  [DEFAULT_PORT_bufferPrefixContent_privDataSize]
                               Pass Parser result: [DEFAULT_PORT_bufferPrefixContent_passPrsResult].
                               Pass timestamp: [DEFAULT_PORT_bufferPrefixContent_passTimeStamp].

                May be used for all ports

 @Param[in]     h_FmPort                        A handle to a FM Port module.
 @Param[in,out] p_FmBufferPrefixContent         A structure of parameters describing the
                                                structure of the buffer.
                                                Out parameter: Start margin - offset
                                                of data from start of external buffer.

 @Return        E_OK on success; Error code otherwise.

 @Cautions      Allowed only following FM_PORT_Config() and before FM_PORT_Init().
*//***************************************************************************/
t_Error FM_PORT_ConfigBufferPrefixContent(t_Handle                      h_FmPort,
                                          t_FmBufferPrefixContent       *p_FmBufferPrefixContent);

/**************************************************************************//**
 @Function      FM_PORT_ConfigExtBufPools

 @Description   This routine should be called for OP ports
                that internally use BM buffer pools. In such cases, e.g. for fragmentation and
                re-assembly, the FM needs new BM buffers. By calling this routine the user
                specifies the BM buffer pools that should be used.

                Note: Available for some chips only

                May be used for OP ports only

 @Param[in]     h_FmPort            A handle to a FM Port module.
 @Param[in]     p_FmExtPools        A structure of parameters for the external pools.

 @Return        E_OK on success; Error code otherwise.

 @Cautions      Allowed only following FM_PORT_Config() and before FM_PORT_Init().
*//***************************************************************************/
t_Error FM_PORT_ConfigExtBufPools(t_Handle h_FmPort, t_FmExtPools *p_FmExtPools);

/**************************************************************************//**
 @Function      FM_PORT_ConfigErrorsToDiscard

 @Description   Calling this routine changes the behaviour on error parameter
                in the internal driver data base from its default configuration:
                [DEFAULT_PORT_errorsToDiscard].
                If a requested error was previously defined as "ErrorsToEnqueue" it's
                definition will change and the frame will be discarded.
                Errors that were not defined either as "ErrorsToEnqueue" nor as
                "ErrorsToDiscard", will be forwarded to CPU.

                May be used for Rx and OP ports only

 @Param[in]     h_FmPort    A handle to a FM Port module.
 @Param[in]     errs        A list of errors to discard

 @Return        E_OK on success; Error code otherwise.

 @Cautions      Allowed only following FM_PORT_Config() and before FM_PORT_Init().
*//***************************************************************************/
t_Error FM_PORT_ConfigErrorsToDiscard(t_Handle h_FmPort, fmPortFrameErrSelect_t errs);

/**************************************************************************//**
 @Function      FM_PORT_ConfigMaxFrameLength

 @Description   Changes the definition of the max size of frame that should be
                transmitted/received on this port from its default value [DEFAULT_PORT_maxFrameLength].
                This parameter is used for confirmation of the minimum Fifo
                size calculations and only for Tx ports or ports working in
                independent mode. This should be larger than the maximum possible
                MTU that will be used for this port (i.e. its MAC).

 @Param[in]     h_FmPort        A handle to a FM Port module.
 @Param[in]     length          Max size of frame

 @Return        E_OK on success; Error code otherwise.

 @Cautions      Allowed only following FM_PORT_Config() and before FM_PORT_Init().
                This routine is to be used only if Independent-Mode is enabled.
*//***************************************************************************/
t_Error FM_PORT_ConfigMaxFrameLength(t_Handle h_FmPort, uint16_t length);

/**************************************************************************//*
 @Function      FM_PORT_ConfigInternalBuffOffset

 @Description   Configures internal buffer offset.

                May be used for Rx and OP ports only

 @Param[in]     h_FmPort            A handle to a FM Port module.
 @Param[in]     val                 New value

 @Return        E_OK on success; Error code otherwise.

 @Cautions      Allowed only following FM_PORT_Config() and before FM_PORT_Init().
*//***************************************************************************/
t_Error FM_PORT_ConfigInternalBuffOffset(t_Handle h_FmPort, uint8_t val);

/** @} */ /* end of FM_PORT_advanced_init_grp group */
/** @} */ /* end of FM_PORT_init_grp group */


/**************************************************************************//**
 @Group         FM_PORT_runtime_control_grp FM Port Runtime Control Unit

 @Description   FM Port Runtime control unit API functions, definitions and enums.

 @{
*//***************************************************************************/

/**************************************************************************//**
 @Description   enum for defining FM Port counters
*//***************************************************************************/
typedef enum e_FmPortCounters {
    e_FM_PORT_COUNTERS_CYCLE,                       /**< BMI performance counter */
    e_FM_PORT_COUNTERS_TASK_UTIL,                   /**< BMI performance counter */
    e_FM_PORT_COUNTERS_QUEUE_UTIL,                  /**< BMI performance counter */
    e_FM_PORT_COUNTERS_DMA_UTIL,                    /**< BMI performance counter */
    e_FM_PORT_COUNTERS_FIFO_UTIL,                   /**< BMI performance counter */
    e_FM_PORT_COUNTERS_RX_PAUSE_ACTIVATION,         /**< BMI Rx only performance counter */
    e_FM_PORT_COUNTERS_FRAME,                       /**< BMI statistics counter */
    e_FM_PORT_COUNTERS_DISCARD_FRAME,               /**< BMI statistics counter */
    e_FM_PORT_COUNTERS_DEALLOC_BUF,                 /**< BMI deallocate buffer statistics counter */
    e_FM_PORT_COUNTERS_RX_BAD_FRAME,                /**< BMI Rx only statistics counter */
    e_FM_PORT_COUNTERS_RX_LARGE_FRAME,              /**< BMI Rx only statistics counter */
    e_FM_PORT_COUNTERS_RX_FILTER_FRAME,             /**< BMI Rx & OP only statistics counter */
    e_FM_PORT_COUNTERS_RX_LIST_DMA_ERR,             /**< BMI Rx, OP & HC only statistics counter */
    e_FM_PORT_COUNTERS_RX_OUT_OF_BUFFERS_DISCARD,   /**< BMI Rx, OP & HC statistics counter */
    e_FM_PORT_COUNTERS_PREPARE_TO_ENQUEUE_COUNTER,  /**< BMI Rx, OP & HC only statistics counter */
    e_FM_PORT_COUNTERS_WRED_DISCARD,                /**< BMI OP & HC only statistics counter */
    e_FM_PORT_COUNTERS_LENGTH_ERR,                  /**< BMI non-Rx statistics counter */
    e_FM_PORT_COUNTERS_UNSUPPRTED_FORMAT,           /**< BMI non-Rx statistics counter */
    e_FM_PORT_COUNTERS_DEQ_TOTAL,                   /**< QMI total QM dequeues counter */
    e_FM_PORT_COUNTERS_ENQ_TOTAL,                   /**< QMI total QM enqueues counter */
    e_FM_PORT_COUNTERS_DEQ_FROM_DEFAULT,            /**< QMI counter */
    e_FM_PORT_COUNTERS_DEQ_CONFIRM                  /**< QMI counter */
} e_FmPortCounters;

typedef struct t_FmPortBmiStats {
    uint32_t cntCycle;
    uint32_t cntTaskUtil;
    uint32_t cntQueueUtil;
    uint32_t cntDmaUtil;
    uint32_t cntFifoUtil;
    uint32_t cntRxPauseActivation;
    uint32_t cntFrame;
    uint32_t cntDiscardFrame;
    uint32_t cntDeallocBuf;
    uint32_t cntRxBadFrame;
    uint32_t cntRxLargeFrame;
    uint32_t cntRxFilterFrame;
    uint32_t cntRxListDmaErr;
    uint32_t cntRxOutOfBuffersDiscard;
    uint32_t cntWredDiscard;
    uint32_t cntLengthErr;
    uint32_t cntUnsupportedFormat;
} t_FmPortBmiStats;

/**************************************************************************//**
 @Description   Structure for Port id parameters.
                Fields commented 'IN' are passed by the port module to be used
                by the FM module.
                Fields commented 'OUT' will be filled by FM before returning to port.
*//***************************************************************************/
typedef struct t_FmPortCongestionGrps {
    uint16_t    numOfCongestionGrpsToConsider;          /**< The number of required CGs
                                                             to define the size of the following array */
    uint8_t     congestionGrpsToConsider[FM_PORT_NUM_OF_CONGESTION_GRPS];
                                                        /**< An array of CG indexes;
                                                             Note that the size of the array should be
                                                             'numOfCongestionGrpsToConsider'. */
    bool        pfcPrioritiesEn[FM_PORT_NUM_OF_CONGESTION_GRPS][FM_MAX_NUM_OF_PFC_PRIORITIES];
                                                        /**< a matrix that represents the map between the CG ids
                                                             defined in 'congestionGrpsToConsider' to the priorties
                                                             mapping array. */
} t_FmPortCongestionGrps;

/**************************************************************************//**
 @Function      FM_PORT_DumpRegs

 @Description   Dump all regs.

                Calling this routine invalidates the descriptor.

 @Param[in]     h_FmPort - FM PORT module descriptor

 @Return        E_OK on success; Error code otherwise.

 @Cautions      Allowed only following FM_PORT_Init().
*//***************************************************************************/
t_Error FM_PORT_DumpRegs(t_Handle h_FmPort);

/**************************************************************************//**
 @Function      FM_PORT_GetBufferTimeStamp

 @Description   Returns the time stamp in the data buffer.
                Relevant for Rx ports for getting the buffer time stamp.
                See FM_PORT_ConfigBufferPrefixContent for data buffer prefix
                configuration.

 @Param[in]     h_FmPort    - FM PORT module descriptor
 @Param[in]     p_Data      - A pointer to the data buffer.

 @Return        A pointer to the hash result on success, NULL otherwise.

 @Cautions      Allowed only following FM_PORT_Init().
*//***************************************************************************/
uint64_t * FM_PORT_GetBufferTimeStamp(t_Handle h_FmPort, char *p_Data);

/**************************************************************************//**
 @Function      FM_PORT_Disable

 @Description   Gracefully disable an FM port. The port will not start new tasks after all
                tasks associated with the port are terminated.

 @Param[in]     h_FmPort    A handle to a FM Port module.

 @Return        E_OK on success; Error code otherwise.

 @Cautions      Allowed only following FM_PORT_Init().
                This is a blocking routine, it returns after port is
                gracefully stopped, i.e. the port will not except new frames,
                but it will finish all frames or tasks which were already began
*//***************************************************************************/
t_Error FM_PORT_Disable(t_Handle h_FmPort);

/**************************************************************************//**
 @Function      FM_PORT_Enable

 @Description   A runtime routine provided to allow disable/enable of port.

 @Param[in]     h_FmPort    A handle to a FM Port module.

 @Return        E_OK on success; Error code otherwise.

 @Cautions      Allowed only following FM_PORT_Init().
*//***************************************************************************/
t_Error FM_PORT_Enable(t_Handle h_FmPort);

/* Query the initialized port's current enable state without changing it. */
t_Error FM_PORT_GetEnabled(t_Handle h_FmPort, bool *p_Enabled);

/* Whether the port has finished stopping: disabled, and its registers report
 * no frame still in hand. FM_PORT_Disable() gives up waiting for that after a
 * bounded time and succeeds anyway, so a caller that has to know nothing is
 * moving any more asks here, and asks again until it is so. */
t_Error FM_PORT_GetStopped(t_Handle h_FmPort, bool *p_Stopped);

/* Whether the port hands received frames to its PCD rather than enqueueing
 * them directly (BMI-to-BMI). Only Rx and offline-parsing ports can have a
 * PCD; any other port reports false. */
t_Error FM_PORT_IsPcdAttached(t_Handle h_FmPort, bool *p_Attached);

/* While fenced, FM_PORT_Enable() fails with E_BUSY, whoever calls it, and the
 * port stays as it is; disabling it still works. For an owner that has stopped
 * the port and must keep it stopped until it says otherwise: an enable that
 * completed before the fence went up is undone by the owner's disable after
 * it, and none can complete after. */
t_Error FM_PORT_SetFenced(t_Handle h_FmPort, bool fenced);

/* Sends a disabled Rx or offline-parsing port's frames straight to its
 * default queue, as FM_PORT_DetachPCD() does, but keeps everything the PCD
 * was given, so the same call with bypass false gives it back unchanged. No
 * host command: the port is disabled, and the caller has seen it stop
 * (FM_PORT_GetStopped()), so no frame of it can be inside the PCD when the
 * registers change. E_INVALID_STATE for an enabled port or one without a
 * PCD; idempotent either way. */
t_Error FM_PORT_BypassPCD(t_Handle h_FmPort, bool bypass);


/**************************************************************************//**
 @Function      FM_PORT_GetCounter

 @Description   Reads one of the FM PORT counters.

 @Param[in]     h_FmPort            A handle to a FM Port module.
 @Param[in]     fmPortCounter       The requested counter.

 @Return        Counter's current value.

 @Cautions      Allowed only following FM_PORT_Init().
                Note that it is user's responsibility to call this routine only
                for enabled counters, and there will be no indication if a
                disabled counter is accessed.
*//***************************************************************************/
uint32_t FM_PORT_GetCounter(t_Handle h_FmPort, e_FmPortCounters fmPortCounter);

/**************************************************************************//**
 @Function      FM_PORT_SetRxL4ChecksumVerify

 @Description   This routine is relevant for Rx ports (1G and 10G). The routine
                set/clear the L3/L4 checksum verification (on RX side).
                Note that this takes affect only if hw-parser is enabled!

 @Param[in]     h_FmPort        A handle to a FM Port module.
 @Param[in]     enable          boolean indicates whether to do L3/L4 checksum
                                on frames or not.

 @Return        E_OK on success; Error code otherwise.

 @Cautions      Allowed only following FM_PORT_Init().
*//***************************************************************************/
t_Error FM_PORT_SetRxL4ChecksumVerify(t_Handle h_FmPort, bool enable);

/**************************************************************************//**
 @Function      FM_PORT_SetDiscardMask

 @Description   Sets user provided DiscardMask value  to Port BMI register 
			rfsdm in case of rx
			ofsdm in case of op port

                used for Rx and OP ports only

 @Param[in]     h_FmPort    A handle to a FM Port module.
 @Param[in]     errs        A list of errors to discard the frame.

 @Return        E_OK on success; Error code otherwise.

 @Cautions      Allowed only following FM_PORT_Config() and before FM_PORT_Init().
*//***************************************************************************/
#if defined(CONFIG_INET_IPSEC_OFFLOAD) || defined(CONFIG_INET6_IPSEC_OFFLOAD)
t_Error FM_PORT_SetDiscardMask(t_Handle h_FmPort, fmPortFrameErrSelect_t errs);
#endif

/**************************************************************************//**
 @Group         FM_PORT_pcd_runtime_control_grp FM Port PCD Runtime Control Unit

 @Description   FM Port PCD Runtime control unit API functions, definitions and enums.

 @{
*//***************************************************************************/

/**************************************************************************//**
 @Description   A structure defining the KG scheme after the parser.
                This is relevant only to change scheme selection mode - from
                direct to indirect and vice versa, or when the scheme is selected directly,
                to select the scheme id.

*//***************************************************************************/
typedef struct t_FmPcdKgSchemeSelect {
    bool        direct;                 /**< TRUE to use 'h_Scheme' directly, FALSE to use LCV. */
    t_Handle    h_DirectScheme;         /**< Scheme handle, selects the scheme after parser;
                                             Relevant only when 'direct' is TRUE. */
} t_FmPcdKgSchemeSelect;

/**************************************************************************//**
 @Description   A structure of scheme parameters
*//***************************************************************************/
typedef struct t_FmPcdPortSchemesParams {
    uint8_t     numOfSchemes;                           /**< Number of schemes for port to be bound to. */
    t_Handle    h_Schemes[FM_PCD_KG_NUM_OF_SCHEMES];    /**< Array of 'numOfSchemes' schemes for the
                                                             port to be bound to */
} t_FmPcdPortSchemesParams;

/**************************************************************************//**
 @Description   Union for defining port protocol parameters for parser
*//***************************************************************************/
typedef union u_FmPcdHdrPrsOpts {
    /* MPLS */
    struct {
        bool            labelInterpretationEnable;  /**< When this bit is set, the last MPLS label will be
                                                         interpreted as described in HW spec table. When the bit
                                                         is cleared, the parser will advance to MPLS next parse */
        e_NetHeaderType nextParse;                  /**< must be equal or higher than IPv4 */
    } mplsPrsOptions;
    /* VLAN */
    struct {
        uint16_t        tagProtocolId1;             /**< User defined Tag Protocol Identifier, to be recognized
                                                         on VLAN TAG on top of 0x8100 and 0x88A8 */
        uint16_t        tagProtocolId2;             /**< User defined Tag Protocol Identifier, to be recognized
                                                         on VLAN TAG on top of 0x8100 and 0x88A8 */
    } vlanPrsOptions;
    /* PPP */
    struct{
        bool            enableMTUCheck;             /**< Check validity of MTU according to RFC2516 */
    } pppoePrsOptions;

    /* IPV6 */
    struct{
        bool            routingHdrEnable;          /**< TRUE to enable routing header, otherwise ignore */
    } ipv6PrsOptions;

    /* UDP */
    struct{
        bool            padIgnoreChecksum;          /**< TRUE to ignore pad in checksum */
    } udpPrsOptions;

    /* TCP */
    struct {
        bool            padIgnoreChecksum;          /**< TRUE to ignore pad in checksum */
    } tcpPrsOptions;
} u_FmPcdHdrPrsOpts;

/**************************************************************************//**
 @Description   A structure for defining each header for the parser
*//***************************************************************************/
typedef struct t_FmPcdPrsAdditionalHdrParams {
    e_NetHeaderType         hdr;            /**< Selected header; use  HEADER_TYPE_NONE
                                                 to indicate that sw parser is to run first
                                                 (before HW parser, and independent of the
                                                 existence of any protocol), in this case,
                                                 swPrsEnable must be set, and all other
                                                 parameters are irrelevant.  */
    bool                    errDisable;     /**< TRUE to disable error indication */
    bool                    swPrsEnable;    /**< Enable jump to SW parser when this
                                                 header is recognized by the HW parser. */
    uint8_t                 indexPerHdr;    /**< Normally 0, if more than one sw parser
                                                 attachments exists for the same header,
                                                 (in the main sw parser code) use this
                                                 index to distinguish between them. */
    bool                    usePrsOpts;     /**< TRUE to use parser options. */
    u_FmPcdHdrPrsOpts       prsOpts;        /**< A union according to header type,
                                                 defining the parser options selected.*/
} t_FmPcdPrsAdditionalHdrParams;

/**************************************************************************//**
 @Description   struct for defining port PCD parameters
*//***************************************************************************/
typedef struct t_FmPortPcdPrsParams {
    uint8_t                         prsResultPrivateInfo;           /**< The private info provides a method of inserting
                                                                         port information into the parser result. This information
                                                                         may be extracted by Keygen and be used for frames
                                                                         distribution when a per-port distinction is required,
                                                                         it may also be used as a port logical id for analyzing
                                                                         incoming frames. */
    uint8_t                         parsingOffset;                  /**< Number of bytes from beginning of packet to start parsing */
    e_NetHeaderType                 firstPrsHdr;                    /**< The type of the first header expected at 'parsingOffset' */
    bool                            includeInPrsStatistics;         /**< TRUE to include this port in the parser statistics;
                                                                         NOTE: this field is not valid when the FM is in "guest" mode
                                                                               and IPC is not available. */
    uint8_t                         numOfHdrsWithAdditionalParams;  /**< Normally 0, some headers may get
                                                                         special parameters */
    t_FmPcdPrsAdditionalHdrParams   additionalParams[FM_PCD_PRS_NUM_OF_HDRS];
                                                                    /**< 'numOfHdrsWithAdditionalParams'  structures
                                                                         of additional parameters
                                                                         for each header that requires them */
    bool                            setVlanTpid1;                   /**< TRUE to configure user selection of Ethertype to
                                                                         indicate a VLAN tag (in addition to the TPID values
                                                                         0x8100 and 0x88A8). */
    uint16_t                        vlanTpid1;                      /**< extra tag to use if setVlanTpid1=TRUE. */
    bool                            setVlanTpid2;                   /**< TRUE to configure user selection of Ethertype to
                                                                         indicate a VLAN tag (in addition to the TPID values
                                                                         0x8100 and 0x88A8). */
    uint16_t                        vlanTpid2;                      /**< extra tag to use if setVlanTpid1=TRUE. */
} t_FmPortPcdPrsParams;

/**************************************************************************//**
 @Description   struct for defining coarse alassification parameters
*//***************************************************************************/
typedef struct t_FmPortPcdCcParams {
    t_Handle            h_CcTree;                       /**< A handle to a CC tree */
} t_FmPortPcdCcParams;

/**************************************************************************//**
 @Description   struct for defining keygen parameters
*//***************************************************************************/
typedef struct t_FmPortPcdKgParams {
    uint8_t             numOfSchemes;                   /**< Number of schemes for port to be bound to. */
    t_Handle            h_Schemes[FM_PCD_KG_NUM_OF_SCHEMES];
                                                        /**< Array of 'numOfSchemes' schemes handles for the
                                                             port to be bound to */
    bool                directScheme;                   /**< TRUE for going from parser to a specific scheme,
                                                             regardless of parser result */
    t_Handle            h_DirectScheme;                 /**< relevant only if direct == TRUE, Scheme handle,
                                                             as returned by FM_PCD_KgSetScheme */
} t_FmPortPcdKgParams;

/**************************************************************************//**
 @Description   struct for defining policer parameters
*//***************************************************************************/
typedef struct t_FmPortPcdPlcrParams {
    t_Handle                h_Profile;          /**< Selected profile handle */
} t_FmPortPcdPlcrParams;

/**************************************************************************//**
 @Description   struct for defining port PCD parameters
*//***************************************************************************/
typedef struct t_FmPortPcdParams {
    e_FmPortPcdSupport      pcdSupport;         /**< Relevant for Rx and offline ports only.
                                                     Describes the active PCD engines for this port. */
    t_Handle                h_NetEnv;           /**< HL Unused in PLCR only mode */
    t_FmPortPcdPrsParams    *p_PrsParams;       /**< Parser parameters for this port */
    t_FmPortPcdCcParams     *p_CcParams;        /**< Coarse classification parameters for this port */
    t_FmPortPcdKgParams     *p_KgParams;        /**< Keygen parameters for this port */
    t_FmPortPcdPlcrParams   *p_PlcrParams;      /**< Policer parameters for this port; Relevant for one of
                                                     following cases:
                                                     e_FM_PORT_PCD_SUPPORT_PLCR_ONLY or
                                                     e_FM_PORT_PCD_SUPPORT_PRS_AND_PLCR were selected,
                                                     or if any flow uses a KG scheme were policer
                                                     profile is not generated
                                                     ('bypassPlcrProfileGeneration selected'). */
    t_Handle                h_IpReassemblyManip; /**< Reserved in Mono; must be NULL. */
    t_Handle                h_CapwapReassemblyManip; /**< Reserved in Mono; must be NULL. */
} t_FmPortPcdParams;

/**************************************************************************//**
 @Description   A structure for defining the Parser starting point
*//***************************************************************************/
typedef struct t_FmPcdPrsStart {
    uint8_t             parsingOffset;  /**< Number of bytes from beginning of packet to
                                             start parsing */
    e_NetHeaderType     firstPrsHdr;    /**< The type of the first header axpected at
                                             'parsingOffset' */
} t_FmPcdPrsStart;

/**************************************************************************//**
 @Description   struct for defining external buffer margins
*//***************************************************************************/
typedef struct t_FmPortVSPAllocParams {
    uint8_t     numOfProfiles;          /**< Number of Virtual Storage Profiles; must be a power of 2 */
    uint8_t     dfltRelativeId;         /**< The default Virtual-Storage-Profile-id dedicated to Rx/OP port
                                             The same default Virtual-Storage-Profile-id will be for coupled Tx port
                                             if relevant function called for Rx port */
    t_Handle    h_FmTxPort;             /**< Handle to coupled Tx Port; not relevant for OP port. */
} t_FmPortVSPAllocParams;

/**************************************************************************//**
 @Function      FM_PORT_SetPCD

 @Description   Calling this routine defines the port's PCD configuration.
                It changes it from its default configuration which is PCD
                disabled (BMI to BMI) and configures it according to the passed
                parameters.

                May be used for Rx and OP ports only

 @Param[in]     h_FmPort        A handle to a FM Port module.
 @Param[in]     p_FmPortPcd     A Structure of parameters defining the port's PCD
                                configuration.

 @Return        E_OK on success; Error code otherwise.

 @Cautions      Allowed only following FM_PORT_Init().
*//***************************************************************************/
t_Error FM_PORT_SetPCD(t_Handle h_FmPort, t_FmPortPcdParams *p_FmPortPcd);

/**************************************************************************//**
 @Function      FM_PORT_DeletePCD

 @Description   Calling this routine releases the port's PCD configuration.
                The port returns to its default configuration which is PCD
                disabled (BMI to BMI) and all PCD configuration is removed.

                May be used for Rx and OP ports which are
                in PCD mode  only

 @Param[in]     h_FmPort        A handle to a FM Port module.

 @Return        E_OK on success; Error code otherwise.

 @Cautions      Allowed only following FM_PORT_Init().
*//***************************************************************************/
t_Error FM_PORT_DeletePCD(t_Handle h_FmPort);

/**************************************************************************//**
 @Function      FM_PORT_DetachPCD

 @Description   Calling this routine detaches the port from its PCD functionality.
                The port returns to its default flow which is BMI to BMI.

                May be used for Rx and OP ports. An initialized port without
                PCD configuration is already detached and returns E_OK;
                incomplete PCD setup or cleanup still returns an error.

 @Param[in]     h_FmPort        A handle to a FM Port module.

 @Return        E_OK on success; Error code otherwise.

 @Cautions      Allowed only following FM_PORT_Init().
*//***************************************************************************/
t_Error FM_PORT_DetachPCD(t_Handle h_FmPort);

/**************************************************************************//**
 @Function      FM_PORT_PcdPlcrAllocProfiles

 @Description   This routine may be called only for ports that use the Policer in
                order to allocate private policer profiles.

 @Param[in]     h_FmPort            A handle to a FM Port module.
 @Param[in]     numOfProfiles       The number of required policer profiles

 @Return        E_OK on success; Error code otherwise.

 @Cautions      Allowed only following FM_PORT_Init() and FM_PCD_Init(),
                and before FM_PORT_SetPCD().
*//***************************************************************************/
t_Error FM_PORT_PcdPlcrAllocProfiles(t_Handle h_FmPort, uint16_t numOfProfiles);

/**************************************************************************//**
 @Function      FM_PORT_PcdPlcrFreeProfiles

 @Description   This routine should be called for freeing private policer profiles.

 @Param[in]     h_FmPort            A handle to a FM Port module.

 @Return        E_OK on success; Error code otherwise.

 @Cautions      Allowed only following FM_PORT_Init() and FM_PCD_Init(),
                and before FM_PORT_SetPCD().
*//***************************************************************************/
t_Error FM_PORT_PcdPlcrFreeProfiles(t_Handle h_FmPort);

/**************************************************************************//**
 @Function      FM_PORT_VSPAlloc

 @Description   This routine allocated VSPs per port and forces the port to work
                in VSP mode. Note that the port is initialized by default with the
                physical-storage-profile only.

 @Param[in]     h_FmPort    A handle to a FM Port module.
 @Param[in]     p_Params    A structure of parameters for allocation VSP's per port

 @Return        E_OK on success; Error code otherwise.

 @Cautions      Allowed only following FM_PORT_Init(), and before FM_PORT_SetPCD()
                and also before FM_PORT_Enable(); i.e. the port should be disabled.
*//***************************************************************************/
t_Error FM_PORT_VSPAlloc(t_Handle h_FmPort, t_FmPortVSPAllocParams *p_Params);

/** @} */ /* end of FM_PORT_pcd_runtime_control_grp group */
/** @} */ /* end of FM_PORT_runtime_control_grp group */


/**************************************************************************//**
 @Group         FM_PORT_runtime_data_grp FM Port Runtime Data-path Unit

 @Description   FM Port Runtime data unit API functions, definitions and enums.
                This API is valid only if working in Independent-Mode.

 @{
*//***************************************************************************/

/** @} */ /* end of FM_PORT_runtime_data_grp group */
/** @} */ /* end of FM_PORT_grp group */
/** @} */ /* end of FM_grp group */

#endif /* __FM_PORT_EXT */
