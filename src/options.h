/* options.h - Global options.
 * Copyright (C) 2020 g10 Code GmbH
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

#ifndef OPTIONS_H
#define OPTIONS_H 1

/* Global options.  */
typedef struct {
  char *user;
  int debug_flags;
  int only_marked;
  int assume_single_threaded;
} _scute_opt_t;

extern _scute_opt_t _scute_opt;


/*-- readconf.c --*/
void _scute_read_conf (void);


#endif /*OPTIONS_H*/
