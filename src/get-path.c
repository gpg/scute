/* agent.c - Talking to gpg-agent.
 * Copyright (C) 2008 g10 Code GmbH
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

#if HAVE_CONFIG_H
#include <config.h>
#endif
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#ifdef HAVE_W32_SYSTEM
# include <windows.h>
# include <shlobj.h>
# include <io.h>
#endif

#include <gpg-error.h>
#include "debug.h"
#include "support.h"


#ifndef HAVE_STPCPY
static char *
my_stpcpy (char *a, const char *b)
{
    while( *b )
	*a++ = *b++;
    *a = 0;

    return (char*)a;
}
# undef stpcpy
# define stpcpy(a,b) my_stpcpy ((a), (b))
#endif /* !HAVE_STPCPY */




#ifdef HAVE_W32_SYSTEM
#define RTLD_LAZY 0

static __inline__ void *
dlopen (const char * name, int flag)
{
  void * hd = LoadLibrary (name);
  (void)flag;
  return hd;
}

static __inline__ void *
dlsym (void * hd, const char * sym)
{
  if (hd && sym)
    {
      void * fnc = GetProcAddress (hd, sym);
      if (!fnc)
        return NULL;
      return fnc;
    }
  return NULL;
}

static __inline__ int
dlclose (void * hd)
{
  if (hd)
    {
      FreeLibrary (hd);
      return 0;
    }
  return -1;
}


/* Return a string from the W32 Registry or NULL in case of error.
   Caller must release the return value.  A NULL for root is an alias
   for HKEY_CURRENT_USER, HKEY_LOCAL_MACHINE in turn. */
static char *
read_w32_registry_string (const char *root, const char *dir, const char *name)
{
  HKEY root_key, key_handle;
  DWORD n1, nbytes, type;
  char *result = NULL;

  if ( !root )
    root_key = HKEY_CURRENT_USER;
  else if ( !strcmp( root, "HKEY_CLASSES_ROOT" ) )
    root_key = HKEY_CLASSES_ROOT;
  else if ( !strcmp( root, "HKEY_CURRENT_USER" ) )
    root_key = HKEY_CURRENT_USER;
  else if ( !strcmp( root, "HKEY_LOCAL_MACHINE" ) )
    root_key = HKEY_LOCAL_MACHINE;
  else if ( !strcmp( root, "HKEY_USERS" ) )
    root_key = HKEY_USERS;
  else if ( !strcmp( root, "HKEY_PERFORMANCE_DATA" ) )
    root_key = HKEY_PERFORMANCE_DATA;
  else if ( !strcmp( root, "HKEY_CURRENT_CONFIG" ) )
    root_key = HKEY_CURRENT_CONFIG;
  else
    return NULL;

  if ( RegOpenKeyEx ( root_key, dir, 0, KEY_READ, &key_handle ) )
    {
      if (root)
        return NULL; /* no need for a RegClose, so return direct */
      /* It seems to be common practise to fall back to HKLM. */
      if (RegOpenKeyEx (HKEY_LOCAL_MACHINE, dir, 0, KEY_READ, &key_handle) )
        return NULL; /* still no need for a RegClose, so return direct */
    }

  nbytes = 1;
  if ( RegQueryValueEx( key_handle, name, 0, NULL, NULL, &nbytes ) )
    {
      if (root)
        goto leave;
      /* Try to fallback to HKLM also vor a missing value.  */
      RegCloseKey (key_handle);
      if (RegOpenKeyEx (HKEY_LOCAL_MACHINE, dir, 0, KEY_READ, &key_handle) )
        return NULL; /* Nope.  */
      if (RegQueryValueEx ( key_handle, name, 0, NULL, NULL, &nbytes))
        goto leave;
    }
  result = malloc ( (n1=nbytes+1) );
  if ( !result )
    goto leave;
  if ( RegQueryValueEx ( key_handle, name, 0, &type, result, &n1 ) )
    {
      free(result); result = NULL;
      goto leave;
    }
  result[nbytes] = 0; /* Make sure it is really a string.  */
  if (type == REG_EXPAND_SZ && strchr (result, '%'))
    {
      char *tmp;

      n1 += 1000;
      tmp = malloc (n1+1);
      if (!tmp)
        goto leave;
      nbytes = ExpandEnvironmentStrings (result, tmp, n1);
      if (nbytes && nbytes > n1)
        {
          free (tmp);
          n1 = nbytes;
          tmp = malloc (n1 + 1);
          if (!tmp)
            goto leave;
          nbytes = ExpandEnvironmentStrings (result, tmp, n1);
          if (nbytes && nbytes > n1) {
            free (tmp); /* Oops - truncated, better don't expand at all. */
            goto leave;
          }
          tmp[nbytes] = 0;
          free (result);
          result = tmp;
        }
      else if (nbytes)  /* Okay, reduce the length. */
        {
          tmp[nbytes] = 0;
          free (result);
          result = malloc (strlen (tmp)+1);
          if (!result)
            result = tmp;
          else
            {
              strcpy (result, tmp);
              free (tmp);
            }
        }
      else  /* Error - don't expand. */
        {
          free (tmp);
        }
    }

 leave:
  RegCloseKey( key_handle );
  return result;
}


/* This is a helper function to load and run a Windows function from
   either of one DLLs. */
static HRESULT
w32_shgetfolderpath (HWND a, int b, HANDLE c, DWORD d, LPSTR e)
{
  static int initialized;
  static HRESULT (WINAPI * func)(HWND,int,HANDLE,DWORD,LPSTR);

  if (!initialized)
    {
      static char *dllnames[] = { "shell32.dll", "shfolder.dll", NULL };
      void *handle;
      int i;

      initialized = 1;

      for (i=0, handle = NULL; !handle && dllnames[i]; i++)
        {
          handle = dlopen (dllnames[i], RTLD_LAZY);
          if (handle)
            {
              func = dlsym (handle, "SHGetFolderPathA");
              if (!func)
                {
                  dlclose (handle);
                  handle = NULL;
                }
            }
        }
    }

  if (func)
    return func (a,b,c,d,e);
  else
    return -1;
}


static char *
find_program_in_inst_dir (const char *name)
{
  char *result = NULL;
  char *tmp;

  tmp = read_w32_registry_string ("HKEY_LOCAL_MACHINE",
				  "Software\\GNU\\GnuPG",
				  "Install Directory");
  if (!tmp)
    return NULL;

  result = malloc (strlen (tmp) + 1 + strlen (name) + 1);
  if (!result)
    {
      free (tmp);
      return NULL;
    }

  strcpy (stpcpy (stpcpy (result, tmp), "\\"), name);
  free (tmp);
  if (access (result, F_OK))
    {
      free (result);
      return NULL;
    }

  return result;
}



static char *
find_program_at_standard_place (const char *name)
{
  char path[MAX_PATH];
  char *result = NULL;

  if (w32_shgetfolderpath (NULL, CSIDL_PROGRAM_FILES, NULL, 0, path) >= 0)
    {
      result = malloc (strlen (path) + 1 + strlen (name) + 1);
      if (result)
        {
          strcpy (stpcpy (stpcpy (result, path), "\\"), name);
          if (access (result, F_OK))
            {
              free (result);
              result = NULL;
            }
        }
    }
  return result;
}
#endif


/* Return the file name of the gpgconf utility.  */
const char *
get_gpgconf_path (void)
{
  static const char *pgmname;

#ifdef HAVE_W32_SYSTEM
  if (!pgmname)
    pgmname = find_program_in_inst_dir ("gpgconf.exe");
  if (!pgmname)
    pgmname = find_program_at_standard_place ("GNU\\GnuPG\\gpgconf.exe");
#endif
  if (!pgmname)
    pgmname = "gpgconf";
  return pgmname;
}


/* Return the bindir where the main binaries are installed.  This may
 * return NULL.  */
static const char *
get_bindir (void)
{
  static char *bindir;
  gpg_error_t err = 0;
  char buffer[512];
  FILE *fp;

  if (!bindir)
    {
      snprintf (buffer, sizeof buffer, "%s --null --list-dirs bindir",
                get_gpgconf_path ());
#ifdef HAVE_W32_SYSTEM
      fp = _popen (buffer, "r");
#else
      fp = popen (buffer, "r");
#endif
      if (fp)
        {
          int i, c;

          for (i=0; i < sizeof buffer - 1  && (c = getc (fp)) != EOF; i++)
            buffer[i] = c;
          if (c == EOF && ferror (fp))
            err = gpg_error_from_syserror ();
          else if (!(i < sizeof buffer - 1))
            err = gpg_error (GPG_ERR_NO_AGENT);  /* Path too long.  */
          else if (!i || buffer[i-1])
            err = gpg_error (GPG_ERR_NO_AGENT);  /* No terminating nul. */
          else if (!(bindir = strdup (buffer)))
            err = gpg_error_from_syserror ();

          pclose (fp);
        }
      else
        err = gpg_error_from_syserror ();

      if (err)
        DEBUG (DBG_CRIT, "error locating GnuPG's installation directory: %s",
               gpg_strerror (err));
    }

  return bindir;
}


const char *
get_gpgsm_path (void)
{
  static char *pgmname;
#ifdef HAVE_W32_SYSTEM
  static const char gpgsm[] = "gpgsm.exe";
#else
  static const char gpgsm[] = "gpgsm";
#endif

  if (!pgmname)
    {
      char *buffer;
      const char *bindir = get_bindir ();
      if (!bindir)
        return gpgsm;  /* Error fallback without any path component.  */

      buffer = malloc (strlen (bindir) + 1 + strlen (gpgsm) + 1);
      if (!buffer)
        return gpgsm;  /* Error fallback.  */

      strcpy (stpcpy (stpcpy (buffer, bindir), "/"), gpgsm);
      pgmname = buffer;
    }

  return pgmname;
}
