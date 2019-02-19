/* error-mapping.c - Scute error mapping interface.
 * Copyright (C) 2006 g10 Code GmbH
 *
 * This file is part of Scute.
 *
 * Scute is free software; you can redistribute it and/or modify it
 * under the terms of the GNU Lesser General Public License as
 * published by the Free Software Foundation; either version 2.1 of
 * the License, or (at your option) any later version.
 *
 * Scute is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this program; if not, see <https://gnu.org/licenses/>.
 * SPDX-License-Identifier: LGPL-2.1-or-later
 */

#ifndef ERROR_MAPPING_H
#define ERROR_MAPPING_H	1

#include <errno.h>

#include <gpg-error.h>

#include "cryptoki.h"

/* Map a system error code to a cryptoki return value.  */
CK_RV scute_sys_to_ck (int err);

/* Map a GnuPG error code to a cryptoki return value.  */
CK_RV scute_gpg_err_to_ck (gpg_error_t err);

#endif /* !ERROR_MAPPING_H */
