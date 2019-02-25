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


/* Malloced string with GnuPG's version.  NULL if gnupg is notproperly
 * installed.  */
static char *gnupg_version_string;




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


/* Read a line form the output of COMMAND via popen and return that
 * line at BUFFER which has been allocated by the caller with BUFSIZE
 * bytes.  On success BUFFER contains a string with the first line.
 * Command and buffer may have the same address.  If no output is
 * expected BUFFER can be given as NULL. */
gpg_error_t
read_first_line (const char *command, char *buffer, size_t bufsize)
{
  gpg_error_t err;
  FILE *fp;

  if (buffer && bufsize < 2)
    return gpg_error (GPG_ERR_BUFFER_TOO_SHORT);

#ifdef HAVE_W32_SYSTEM
  fp = _popen (command, "r");
#else
  fp = popen (command, "r");
#endif
  if (fp)
    {
      int i, c;

      if (buffer)
        {
          for (i=0; i < bufsize - 1 && (c=getc(fp)) != EOF && c != '\n'; i++)
            buffer[i] = c;
          buffer [i] = 0;  /* Terminate string.  */
          if (c == EOF && ferror (fp))
            err = gpg_error_from_syserror ();    /* Read error.  */
          else if (!(i < bufsize - 1))
            err = gpg_error (GPG_ERR_NO_AGENT);  /* Path too long.  */
          else if (!i || c != '\n')
            err = gpg_error (GPG_ERR_NO_AGENT);  /* No terminating LF. */
          else
            err = 0;
        }
      else
        err = 0;
      pclose (fp);
    }
  else
    {
      err = gpg_error_from_syserror ();
      DEBUG (DBG_CRIT, "popen(%s) failed: %s",
             command, gpg_strerror (err));
    }

  return err;
}



/* Extract the version string of a program from STRING.  The version
 * number is expected to be in GNU style format:
 *
 *   foo 1.2.3
 *   foo (bar system) 1.2.3
 *   foo 1.2.3 cruft
 *   foo (bar system) 1.2.3 cruft.
 *
 * Spaces and tabs are skipped and used as delimiters, a term in
 * (nested) parenthesis before the version string is skipped, the
 * version string may consist of any non-space and non-tab characters
 * but needs to start with a digit.
 */
static const char *
extract_version_string (const char *string, size_t *r_len)
{
  const char *s;
  int count, len;

  for (s=string; *s; s++)
    if (*s == ' ' || *s == '\t')
        break;
  while (*s == ' ' || *s == '\t')
    s++;
  if (*s == '(')
    {
      for (count=1, s++; count && *s; s++)
        if (*s == '(')
          count++;
        else if (*s == ')')
          count--;
    }
  /* For robustness we look for a digit.  */
  while ( *s && !(*s >= '0' && *s <= '9') )
    s++;
  if (*s >= '0' && *s <= '9')
    {
      for (len=0; s[len]; len++)
        if (s[len] == ' ' || s[len] == '\t')
          break;
    }
  else
    len = 0;

  *r_len = len;
  return s;
}


/* Return the file name of the gpgconf utility.  As a side-effect the
 * version number of gnupg is also figured out the first time this
 * function is called.  */
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
  if (!gnupg_version_string)
    {
      char buffer[512];
      const char *s;
      size_t n;

      snprintf (buffer, sizeof buffer, "%s --version", pgmname);
      if (!read_first_line (buffer, buffer, sizeof buffer))
        {
          s = extract_version_string (buffer, &n);
          gnupg_version_string = malloc (n+1);
          if (gnupg_version_string)
            {
              memcpy (gnupg_version_string, s, n);
              gnupg_version_string[n] = 0;
            }
        }
    }
  return pgmname;
}


/* Return the version of GnuPG. */
int
get_gnupg_version (int *minor)
{
  int major;
  const char *s;

  if (!gnupg_version_string)
    {
      *minor = 0;
      return 0;
    }

  major = atoi (gnupg_version_string);
  s = strchr (gnupg_version_string, '.');
  *minor = s? atoi (s+1) : 0;

  return major;
}


/* Return true if GnuPG is older than MAJOR.MINOR.MICRO. */
int
is_gnupg_older_than (int major, int minor, int micro)
{
  int my_major, my_minor, my_micro;
  const char *s;

  if (!gnupg_version_string)
    return 1;

  my_minor = my_micro = 0;
  my_major = atoi (gnupg_version_string);
  s = strchr (gnupg_version_string, '.');
  if (s)
    {
      my_minor = atoi (++s);
      s = strchr (s, '.');
      if (s)
        my_micro = atoi (++s);
    }
  if (my_major < major)
    return 1;
  if (my_major > major)
    return 0;

  if (my_minor < minor)
    return 1;
  if (my_minor > minor)
    return 0;

  if (my_micro < micro)
    return 1;
  return 0;
}


/* Return the bindir where the main binaries are installed.  This may
 * return NULL.  */
static const char *
get_bindir (void)
{
  static char *bindir;
  gpg_error_t err = 0;
  char buffer[512];

  if (!bindir)
    {
      snprintf (buffer, sizeof buffer, "%s --list-dirs bindir",
                get_gpgconf_path ());
      err = read_first_line (buffer, buffer, sizeof buffer);
      if (!err)
        {
          bindir = strdup (buffer);
          if (!bindir)
            err = gpg_error_from_syserror ();
        }
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
