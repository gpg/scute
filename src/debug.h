/* debug.c - Debug interface.
 * Copyright (C) 2006, 2008 g10 Code GmbH
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

#ifndef DEBUG_H
#define DEBUG_H	1

#include <stdio.h>

#define DEBUG_PREFIX "scute: "

#define DBG_CRIT 0
#define DBG_INFO (1 << 0)
#define DBG_ASSUAN (1 << 1)

extern FILE *_scute_debug_stream;
extern unsigned int _scute_debug_flags;

#define DEBUG(flag, format, ...)  \
  do \
    { \
      if (_scute_debug_flags & (flag) || flag == DBG_CRIT) \
        fprintf (_scute_debug_stream, \
                 DEBUG_PREFIX "%s: " format "\n", __func__, ##__VA_ARGS__); \
    } \
  while (0)

void _scute_debug_init (void);


#endif /* !DEBUG_H */
