/* debug.c - Cryptoki implementation.
   Copyright (C) 2008 g10 Code GmbH

   This file is part of Scute.
 
   Scute is free software; you can redistribute it and/or modify it
   under the terms of the GNU General Public License as published by
   the Free Software Foundation; either version 2 of the License, or
   (at your option) any later version.

   Scute is distributed in the hope that it will be useful, but
   WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
   General Public License for more details.

   You should have received a copy of the GNU General Public License
   along with Scute; if not, write to the Free Software Foundation,
   Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA

   In addition, as a special exception, g10 Code GmbH gives permission
   to link this library: with the Mozilla Foundation's code for
   Mozilla (or with modified versions of it that use the same license
   as the "Mozilla" code), and distribute the linked executables.  You
   must obey the GNU General Public License in all respects for all of
   the code used other than "Mozilla".  If you modify this file, you
   may extend this exception to your version of the file, but you are
   not obligated to do so.  If you do not wish to do so, delete this
   exception statement from your version.  */

#if HAVE_CONFIG_H
#include <config.h>
#endif

#include <ctype.h>
#include <stdio.h>
#include <stdlib.h>

#include <assuan.h>
#include <gpg-error.h>
#include <string.h>

#include "debug.h"


FILE *_scute_debug_stream;

unsigned int _scute_debug_flags;


#ifdef HAVE_W32_SYSTEM
#define PATHSEP_C ';'
#else
#define PATHSEP_C ':'
#endif


/* Remove leading and trailing white spaces.  */
static char *
trim_spaces (char *str)
{
  char *string, *p, *mark;

  string = str;
  /* Find first non space character.  */
  for (p = string; *p && isspace (*(unsigned char *) p); p++)
    ;
  /* Move characters.  */
  for (mark = NULL; (*string = *p); string++, p++)
    if (isspace (*(unsigned char *) p))
      {
	if (!mark)
	  mark = string;
      }
    else
      mark = NULL;
  if (mark)
    *mark = '\0';	/* Remove trailing spaces.  */

  return str;
}

#include <errno.h>

void
_scute_debug_init (void)
{
  static int initialized;

  if (!initialized)
    {
      char *e;
      const char *s1, *s2;
      FILE *stream;

      e = getenv ("SCUTE_DEBUG");

      initialized = 1;
     
      stream = stderr;
      if (e)
	{
	  _scute_debug_flags = atoi (e);
	  s1 = strchr (e, PATHSEP_C);
	  if (s1)
	    {
#ifndef HAVE_W32_SYSTEM
	      if (getuid () == geteuid ())
		{
#endif
		  char *p;
		  FILE *fp;

		  s1++;
		  if (!(s2 = strchr (s1, PATHSEP_C)))
		    s2 = s1 + strlen (s1);
		  p = malloc (s2 - s1 + 1);
		  if (p)
		    {
		      memcpy (p, s1, s2 - s1);
		      p[s2-s1] = 0;
		      trim_spaces (p);
		      fp = fopen (p,"a");
		      if (fp)
			{
			  setvbuf (fp, NULL, _IOLBF, 0);
			  stream = fp;
			}
		      free (p);
		    }
#ifndef HAVE_W32_SYSTEM
		}
#endif
	    }
        }

      if (_scute_debug_flags > 0)
        fprintf (stream, "scute debug init: flags=0x%x\n", _scute_debug_flags);

      assuan_set_assuan_log_prefix ("scute-assuan");
      _scute_debug_stream = stream;
    }
}
