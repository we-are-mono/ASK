/* SPDX-License-Identifier: GPL-2.0-or-later */
#ifndef CDX_XLAT_TEST_H
#define CDX_XLAT_TEST_H

/* Removes every direction the feasibility hook installed (cdx_xlat_test.c);
 * takes cdx_info->ctrl.mutex. */
void cdx_xlat_test_flush(void);

#endif
