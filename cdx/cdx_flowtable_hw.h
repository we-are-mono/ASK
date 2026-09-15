/* SPDX-License-Identifier: GPL-2.0-or-later */
#ifndef CDX_FLOWTABLE_HW_H
#define CDX_FLOWTABLE_HW_H

#include "cdx_flowtable_backend.h"

/* CDX-internal firmware encoder. Only the backend and final CDX shutdown
 * call these operations, with cdx_info->ctrl.mutex held. */
int cdx_ft_hw_add(const struct cdx_ft_rule *rule, struct cdx_ft_hw **result);
void cdx_ft_hw_stats(struct cdx_ft_hw *hw, struct cdx_ft_counters *stats);
/* Always consumes *hw. 0: removed and synchronized. -EAGAIN: unlinked but
 * quarantined. -EIO: removal unproven; caller must stop further admission and
 * quiesce the datapath. The backend retains failed deletions without allocating
 * new storage. A repeated delete with *hw == NULL does not erase prior errors. */
int cdx_ft_hw_del(struct cdx_ft_hw **hw);
unsigned int cdx_ft_hw_pending(void);
int cdx_ft_hw_retry(void);
/* Only after dpa_cfg_quiesce has succeeded; requires the control mutex. */
void cdx_ft_hw_quiesced(void);

#endif
