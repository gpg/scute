/* agent.c - Talking to gpg-agent.
 * Copyright (C) 2006, 2007, 2008, 2015, 2019 g10 Code GmbH
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

#include <stdlib.h>
#include <stdio.h>
#include <locale.h>
#include <errno.h>
#include <string.h>
#include <stdarg.h>

#ifdef HAVE_W32_SYSTEM
# define PATHSEP_C ';'
# define WINVER 0x0500  /* Required for AllowSetForegroundWindow.  */
# include <winsock2.h>
# include <windows.h>
#else
# define PATHSEP_C ':'
#endif

#include <assuan.h>
#include <gpg-error.h>

#include "debug.h"
#include "support.h"
#include "sexp-parse.h"
#include "cert.h"
#include "agent.h"


/* The global agent context.  */
static assuan_context_t agent_ctx;



/* Hack required for Windows.  */
void
gnupg_allow_set_foregound_window (pid_t pid)
{
  if (!pid || pid == (pid_t)(-1))
    return;
#ifdef HAVE_W32_SYSTEM
  else if (!AllowSetForegroundWindow (pid))
    DEBUG (DBG_CRIT, "AllowSetForegroundWindow(%lu) failed: %u\n",
	   (unsigned long)pid, (unsigned int)GetLastError ());
#endif
}



/* Establish a connection to a running GPG agent.  */
static gpg_error_t
agent_connect (assuan_context_t *ctx_r)
{
  gpg_error_t err = 0;
  assuan_context_t ctx = NULL;
  char buffer[512];

#ifndef HAVE_W32_SYSTEM
  DEBUG (DBG_INFO, "agent_connect: uid=%lu euid=%lu",
         (unsigned long)getuid (), (unsigned long)geteuid ());
#endif
  /* Use gpgconf to make sure that gpg-agent is started and to obtain
   * the socket name.  For older version of gnupg we will fallback to
   * using two gpgconf commands with the same effect.  */
  /* FIXME: We should make sure that USER has no spaces.  */
  snprintf (buffer, sizeof buffer, "%s %s%s --show-socket --launch gpg-agent",
            get_gpgconf_path (),
            _scute_opt.user? "--chuid=":"",
            _scute_opt.user? _scute_opt.user:"");
  err = read_first_line (buffer, buffer, sizeof buffer);
  if (gpg_err_code (err) == GPG_ERR_NO_AGENT && is_gnupg_older_than (2, 2, 14))
    {
      snprintf (buffer, sizeof buffer, "%s --launch gpg-agent",
                get_gpgconf_path ());
      err = read_first_line (buffer, NULL, 0);
      if (!err)
        {
          snprintf (buffer, sizeof buffer, "%s --list-dirs agent-socket",
                    get_gpgconf_path ());
          err = read_first_line (buffer, buffer, sizeof buffer);
        }
    }
  DEBUG (DBG_INFO, "agent_connect: agent socket is '%s'", buffer);

  /* Then connect to the socket we got. */
  if (!err)
    {
      err = assuan_new (&ctx);
      if (!err)
        {
          err = assuan_socket_connect (ctx, buffer, 0, 0);
          if (!err)
            {
              *ctx_r = ctx;
              if (_scute_opt.debug_flags & DBG_ASSUAN)
                assuan_set_log_stream (*ctx_r, _scute_debug_stream);
            }
          else
            assuan_release (ctx);
        }
    }

  /* We do not try any harder. If gpg-connect-agent somehow failed
   * to give us a suitable socket, we probably cannot do better. */
  if (err)
    DEBUG (DBG_CRIT, "cannot connect to GPG agent: %s", gpg_strerror (err));

  return err;
}

/*
 * Check whether STRING starts with KEYWORD.  The keyword is
 * delimited by end of string, a space or a tab.  Returns NULL if not
 * found or a pointer into STRING to the next non-space character
 * after the KEYWORD (which may be end of string).
 */
static char *
has_leading_keyword (const char *string, const char *keyword)
{
  size_t n = strlen (keyword);

  if (!strncmp (string, keyword, n)
      && (!string[n] || string[n] == ' ' || string[n] == '\t'))
    {
      string += n;
      while (*string == ' ' || *string == '\t')
        string++;
      return (char*)string;
    }
  return NULL;
}


/* This is the default inquiry callback.  It mainly handles the
   Pinentry notifications.  */
static gpg_error_t
default_inq_cb (void *opaque, const char *line)
{
  const char *s;
  (void)opaque;

  if ((s = has_leading_keyword (line, "PINENTRY_LAUNCHED")))
    {
      gnupg_allow_set_foregound_window ((pid_t)strtoul (s, NULL, 10));
      /* We do not pass errors to avoid breaking other code.  */
    }
  else
    DEBUG (DBG_CRIT, "ignoring gpg-agent inquiry `%s'\n", line);

  return 0;
}


/* Send a simple command to the agent.  */
static gpg_error_t
agent_simple_cmd (assuan_context_t ctx, const char *fmt, ...)
{
  gpg_error_t err;
  char *optstr;
  va_list arg;
  int res;

  va_start (arg, fmt);
  res = vasprintf (&optstr, fmt, arg);
  va_end (arg);

  if (res < 0)
    return gpg_error_from_errno (errno);

  err = assuan_transact (ctx, optstr, NULL, NULL, default_inq_cb,
			 NULL, NULL, NULL);
  if (err)
    DEBUG (DBG_CRIT, "gpg-agent command '%s' failed: %s", optstr,
	   gpg_strerror (err));
  free (optstr);

  return err;
}


/* Configure the GPG agent at connection CTX.  */
static gpg_error_t
agent_configure (assuan_context_t ctx)
{
  gpg_error_t err = 0;
  char *dft_display = NULL;
  char *dft_ttyname = NULL;
  char *dft_ttytype = NULL;
#if defined(HAVE_SETLOCALE) && (defined(LC_CTYPE) || defined(LC_MESSAGES))
  char *old_lc = NULL;
  char *dft_lc = NULL;
#endif
  char *dft_xauthority = NULL;
  char *dft_pinentry_user_data = NULL;

  err = agent_simple_cmd (ctx, "RESET");
  if (err)
    return err;

  /* Set up display, terminal and locale options.  */
  dft_display = getenv ("DISPLAY");
  if (dft_display)
    err = agent_simple_cmd (ctx, "OPTION display=%s", dft_display);
  if (err)
    return err;

  dft_ttyname = getenv ("GPG_TTY");
  if ((!dft_ttyname || !*dft_ttyname) && ttyname (0))
    dft_ttyname = ttyname (0);
  if (dft_ttyname)
    {
      err = agent_simple_cmd (ctx, "OPTION ttyname=%s", dft_ttyname);
      if (err)
	return err;
    }

  dft_ttytype = getenv ("TERM");
  if (dft_ttytype)
    err = agent_simple_cmd (ctx, "OPTION ttytype=%s", dft_ttytype);
  if (err)
    return err;

#if defined(HAVE_SETLOCALE) && defined(LC_CTYPE)
  old_lc = setlocale (LC_CTYPE, NULL);
  if (old_lc)
    {
      old_lc = strdup (old_lc);
      if (!old_lc)
	return gpg_error_from_errno (errno);
    }
  dft_lc = setlocale (LC_CTYPE, "");
  if (dft_lc)
    err = agent_simple_cmd ("OPTION lc-ctype=%s", dft_lc);
  if (old_lc)
    {
      setlocale (LC_CTYPE, old_lc);
      free (old_lc);
    }
#endif
  if (err)
    return err;

#if defined(HAVE_SETLOCALE) && defined(LC_MESSAGES)
  old_lc = setlocale (LC_MESSAGES, NULL);
  if (old_lc)
    {
      old_lc = strdup (old_lc);
      if (!old_lc)
	err = gpg_error_from_errno (errno);
    }
  dft_lc = setlocale (LC_MESSAGES, "");
  if (dft_lc)
    err = agent_simple_cmd ("OPTION lc-messages=%s", dft_lc);
  if (old_lc)
    {
      setlocale (LC_MESSAGES, old_lc);
      free (old_lc);
    }
#endif

  dft_xauthority = getenv ("XAUTHORITY");
  if (dft_xauthority)
    err = agent_simple_cmd (ctx, "OPTION xauthority=%s", dft_xauthority);
  if (gpg_err_code (err) == GPG_ERR_UNKNOWN_OPTION)
    err = 0;
  else if (err)
    return err;

  dft_pinentry_user_data = getenv ("PINENTRY_USER_DATA");
  if (dft_pinentry_user_data)
    err = agent_simple_cmd (ctx, "OPTION pinentry_user_data=%s",
	                    dft_pinentry_user_data);
  if (err && gpg_err_code (err) != GPG_ERR_UNKNOWN_OPTION)
    return err;

  err = agent_simple_cmd (ctx, "OPTION allow-pinentry-notify");
  if (err && gpg_err_code (err) != GPG_ERR_UNKNOWN_OPTION)
    return err;

  return err;
}


/* Check for a broken pipe, that is a lost connection to the agent.
 * Update the gloabls so that a re-connect is done the next time.
 * Returns ERR or the modified code GPG_ERR_NO_AGENT.  */
static gpg_error_t
check_broken_pipe (gpg_error_t err)
{
  /* Note that Scute _currently_ uses GPG_ERR_SOURCE_ANY.  */
  if (gpg_err_code (err) == GPG_ERR_EPIPE
      && gpg_err_source (err) == GPG_ERR_SOURCE_ANY)
    {
      DEBUG (DBG_INFO, "Broken connection to the gpg-agent");
      scute_agent_finalize ();
      err = gpg_error (GPG_ERR_NO_AGENT);
    }
  return err;
}


/* If the connection to the agent was lost earlier and detected by
 * check_broken_pipe we try to reconnect.  */
static gpg_error_t
ensure_agent_connection (void)
{
  gpg_error_t err;

  if (agent_ctx)
    return 0;  /* Connection still known.  */

  DEBUG (DBG_INFO, "Re-connecting to gpg-agent");
  err = agent_connect (&agent_ctx);
  if (err)
    return err;

  err = agent_configure (agent_ctx);
  return check_broken_pipe (err);
}


/* Try to connect to the agent via socket.  Handle the server's
   initial greeting.  This is used only once when SCute is loaded.
   Re-connection is done using ensure_agent_connection.  */
gpg_error_t
scute_agent_initialize (void)
{
  gpg_error_t err = 0;

  if (agent_ctx)
    {
      DEBUG (DBG_CRIT, "GPG Agent connection already established");
      return 0;
    }

  DEBUG (DBG_INFO, "Establishing connection to gpg-agent");
  err = agent_connect (&agent_ctx);
  if (err)
    return err;

  err = agent_configure (agent_ctx);
  if (err)
    scute_agent_finalize ();

  return err;
}



/* Return a new malloced string by unescaping the string S.  Escaping
   is percent escaping and '+'/space mapping.  A binary nul will
   silently be replaced by a 0xFF.  Function returns NULL to indicate
   an out of memory status.  */
static char *
unescape_status_string (const unsigned char *src)
{
  char *buffer;
  char *dst;

  buffer = malloc (strlen (src) + 1);
  if (!buffer)
    return NULL;

  dst = buffer;
  while (*src)
    {
      if (*src == '%' && src[1] && src[2])
        {
          src++;
          *dst = xtoi_2 (src);
          if (*dst == '\0')
            *dst = '\xff';
          dst++;
          src += 2;
        }
      else if (*src == '+')
        {
          *(dst++) = ' ';
          src++;
        }
      else
        *(dst++) = *(src++);
    }
  *dst = 0;

  return buffer;
}


/* Take a 20 byte hexencoded string and put it into the provided
   20 byte buffer FPR in binary format.  Returns true if successful,
   and false otherwise.  */
static int
unhexify_fpr (const char *hexstr, unsigned char *fpr)
{
  const char *src;
  int cnt;

  /* Check for invalid or wrong length.  */
  for (src = hexstr, cnt = 0; hexdigitp (src); src++, cnt++)
    ;
  if ((*src && !spacep (src)) || (cnt != 40))
    return 0;

  for (src = hexstr, cnt = 0; *src && !spacep (src); src += 2, cnt++)
    fpr[cnt] = xtoi_2 (src);

  return 1;
}

/* Return true if HEXSTR is a valid keygrip.  */
static unsigned int
hexgrip_valid_p (const char *hexstr)
{
  const char *s;
  int n;

  for (s=hexstr, n=0; hexdigitp (s); s++, n++)
    ;
  if ((*s && *s != ' ') || n != 40)
    return 0; /* Bad keygrip */
  else
    return 1; /* Valid.  */
}


/* Take the serial number from LINE and return it verbatim in a newly
   allocated string.  We make sure that only hex characters are
   returned.  */
static char *
store_serialno (const char *line)
{
  const char *src;
  char *ptr;

  for (src = line; hexdigitp (src); src++)
    ;
  ptr = malloc (src + 1 - line);

  if (ptr)
    {
      memcpy (ptr, line, src - line);
      ptr[src - line] = 0;
    }

  return ptr;
}


/* Release the card info structure INFO.  */
void
scute_agent_release_card_info (struct agent_card_info_s *info)
{
  if (!info)
    return;

  free (info->serialno);
  free (info->cardtype);
  free (info->disp_name);
  free (info->disp_lang);
  free (info->pubkey_url);
  free (info->login_data);
  while (info->kinfo)
    {
      key_info_t ki = info->kinfo->next;
      free (info->kinfo);
      info->kinfo = ki;
    }

  memset (info, 0, sizeof (*info));
}


/* Return the key info object for the key KEYREF.  If it is not found
 * NULL is returned.  */
key_info_t
scute_find_kinfo (agent_card_info_t info, const char *keyref)
{
  key_info_t kinfo;

  for (kinfo = info->kinfo; kinfo; kinfo = kinfo->next)
    if (!strcmp (kinfo->keyref, keyref))
      return kinfo;
  return NULL;
}


/* Create a new key info object with KEYREF.  All fields but the
 * keyref are zeroed out.  The created object is appended to the list
 * at INFO. */
static key_info_t
create_kinfo (agent_card_info_t info, const char *keyref)
{
  key_info_t kinfo, ki;

  kinfo = calloc (1, sizeof *kinfo + strlen (keyref));
  if (!kinfo)
    return NULL;
  strcpy (kinfo->keyref, keyref);

  if (!info->kinfo)
    info->kinfo = kinfo;
  else
    {
      for (ki=info->kinfo; ki->next; ki = ki->next)
        ;
      ki->next = kinfo;
    }
  return kinfo;
}


/* FIXME: We are not returning out of memory errors.  */
static gpg_error_t
learn_status_cb (void *opaque, const char *line)
{
  agent_card_info_t parm = opaque;
  const char *keyword = line;
  int keywordlen;
  key_info_t kinfo;
  const char *keyref;
  int i;

  for (keywordlen = 0; *line && !spacep (line); line++, keywordlen++)
    ;
  while (spacep (line))
    line++;

  if (keywordlen == 8 && !memcmp (keyword, "SERIALNO", keywordlen))
    {
      free (parm->serialno);
      parm->serialno = store_serialno (line);
    }
  else if (keywordlen == 7 && !memcmp (keyword, "APPTYPE", keywordlen))
    {
      parm->is_piv = !strcmp (line, "piv");
      parm->is_opgp = !strcmp (line, "openpgp");
    }
  else if (keywordlen == 8 && !memcmp (keyword, "CARDTYPE", keywordlen))
    {
      free (parm->cardtype);
      parm->cardtype = unescape_status_string (line);
    }
  else if (keywordlen == 9 && !memcmp (keyword, "DISP-NAME", keywordlen))
    {
      if (parm->disp_name)
	free (parm->disp_name);
      parm->disp_name = unescape_status_string (line);
    }
  else if (keywordlen == 9 && !memcmp (keyword, "DISP-LANG", keywordlen))
    {
      if (parm->disp_lang)
	free (parm->disp_lang);
      parm->disp_lang = unescape_status_string (line);
    }
  else if (keywordlen == 8 && !memcmp (keyword, "DISP-SEX", keywordlen))
    {
      parm->disp_sex = *line == '1'? 1 : *line == '2' ? 2: 0;
    }
  else if (keywordlen == 10 && !memcmp (keyword, "PUBKEY-URL", keywordlen))
    {
      if (parm->pubkey_url)
	free (parm->pubkey_url);
      parm->pubkey_url = unescape_status_string (line);
    }
  else if (keywordlen == 10 && !memcmp (keyword, "LOGIN-DATA", keywordlen))
    {
      if (parm->login_data)
	free (parm->login_data);
      parm->login_data = unescape_status_string (line);
    }
  else if (keywordlen == 11 && !memcmp (keyword, "SIG-COUNTER", keywordlen))
    {
      parm->sig_counter = strtoul (line, NULL, 0);
    }
  else if (keywordlen == 10 && !memcmp (keyword, "CHV-STATUS", keywordlen))
    {
      char *p, *buf;

      buf = p = unescape_status_string (line);
      if (buf)
        {
          while (spacep (p))
            p++;
          parm->chv1_cached = atoi (p);
          while (*p && !spacep (p))
            p++;
          while (spacep (p))
            p++;
          for (i = 0; *p && i < 3; i++)
            {
              parm->chvmaxlen[i] = atoi (p);
              while (*p && !spacep (p))
                p++;
              while (spacep (p))
                p++;
            }
          for (i=0; *p && i < 3; i++)
            {
              parm->chvretry[i] = atoi (p);
              while (*p && !spacep (p))
                p++;
              while (spacep (p))
                p++;
            }
          free (buf);
        }
    }
  else if (keywordlen == 7 && !memcmp (keyword, "KEY-FPR", keywordlen))
    {
      int no = atoi (line);
      while (*line && !spacep (line))
        line++;
      while (spacep (line))
        line++;
      if (no == 1)
        parm->fpr1valid = unhexify_fpr (line, parm->fpr1);
      else if (no == 2)
        parm->fpr2valid = unhexify_fpr (line, parm->fpr2);
      else if (no == 3)
        parm->fpr3valid = unhexify_fpr (line, parm->fpr3);
    }
  else if (keywordlen == 6 && !memcmp (keyword, "CA-FPR", keywordlen))
    {
      int no = atoi (line);
      while (*line && !spacep (line))
        line++;
      while (spacep (line))
        line++;
      if (no == 1)
        parm->cafpr1valid = unhexify_fpr (line, parm->cafpr1);
      else if (no == 2)
        parm->cafpr2valid = unhexify_fpr (line, parm->cafpr2);
      else if (no == 3)
        parm->cafpr3valid = unhexify_fpr (line, parm->cafpr3);
    }
  else if (keywordlen == 11 && !memcmp (keyword, "KEYPAIRINFO", keywordlen))
    {
      /* The format of such a line is:
       *   KEYPAIRINFO <hexgrip> <keyref> [<usage>]
       */
      const char *hexgrip = line;
      char *line_buffer, *p;
      const char *usage;

      while (*line && !spacep (line))
        line++;
      while (spacep (line))
        line++;

      p = line_buffer = strdup (line);
      if (!line_buffer)
        goto no_core;
      keyref = line_buffer;
      while (*p && !spacep (p))
        p++;
      if (*p)
        {
          *p++ = 0;
          while (spacep (p))
            p++;
          usage = p;
          while (*p && !spacep (p))
            p++;
          *p = 0;
        }
      else
        usage = "";

      if (hexgrip_valid_p (hexgrip))
        {
          /* Check whether we already have an item for the keyref.  */
          kinfo = scute_find_kinfo (parm, keyref);
          if (!kinfo)  /* New entry.  */
            {
              kinfo = create_kinfo (parm, keyref);
              if (!kinfo)
                goto no_core;
            }
          else /* Existing entry - clear grip and usage.  */
            {
              *kinfo->grip = 0;
              memset (&kinfo->usage, 0, sizeof kinfo->usage);
            }

          strncpy (kinfo->grip, hexgrip, sizeof kinfo->grip);
          kinfo->grip[sizeof kinfo->grip -1] = 0;
          for (; *usage; usage++)
            {
              switch (*usage)
                {
                case 's': kinfo->usage.sign = 1; break;
                case 'c': kinfo->usage.cert = 1; break;
                case 'a': kinfo->usage.auth = 1; break;
                case 'e': kinfo->usage.encr = 1; break;
                }
            }
        }
      free (line_buffer);
    }
  else if (keywordlen == 6 && !memcmp (keyword, "EXTCAP", keywordlen))
    {
      char *p, *p2, *buf;
      int abool;

      buf = p = unescape_status_string (line);
      if (buf)
        {
          for (p = strtok (buf, " "); p; p = strtok (NULL, " "))
            {
              p2 = strchr (p, '=');
              if (p2)
                {
                  *p2++ = 0;
                  abool = (*p2 == '1');
                  if (!strcmp (p, "gc"))
                    parm->rng_available = abool;
                  /* We're currently not interested in the
                   * other capabilities. */
                }
            }
          free (buf);
        }
    }
  return 0;

 no_core:
  return gpg_error_from_syserror ();
}


/* Call the agent to learn about a smartcard.  */
gpg_error_t
scute_agent_learn (struct agent_card_info_s *info)
{
  gpg_error_t err;
  int has_opt_all = 0;

  memset (info, 0, sizeof (*info));
  err = ensure_agent_connection ();
  if (!err && !agent_simple_cmd (agent_ctx,
                                 "SCD GETINFO cmd_has_option SERIALNO all"))
    has_opt_all = 1; /* SERIALNO --all and LEARN --multi is okay.  */

  if (!err)
    {
      /* First do a serialno to reset the card-removed-flag and also
       * to make sure that additional applications are enabled.  We do
       * not check the error here as we catch that after the LEARN.  */
      agent_simple_cmd (agent_ctx, (has_opt_all? "SCD SERIALNO --all"
                                    /*       */: "SCD SERIALNO"      ));
      err = assuan_transact (agent_ctx,
                             (has_opt_all? "SCD LEARN --force --multi"
                              /*       */: "SCD LEARN --force"),
                             NULL, NULL,
                             default_inq_cb, NULL,
                             learn_status_cb, info);
    }

  if (gpg_err_source(err) == GPG_ERR_SOURCE_SCD
      && gpg_err_code (err) == GPG_ERR_CARD_REMOVED)
    {
      /* SCD session is in card removed state.  clear that state.
       * That should have been cleared by the initial SERIALNO but
       * other processes may race with that.  */
      err = assuan_transact (agent_ctx, (has_opt_all? "SCD SERIALNO --all"
                                         /*       */: "SCD SERIALNO"),
                             NULL, NULL, NULL, NULL, NULL, NULL);
      if (!err)
        {
          memset (info, 0, sizeof (*info));
          err = assuan_transact (agent_ctx,
                                 (has_opt_all? "SCD LEARN --force --multi"
                                  /*       */: "SCD LEARN --force"),
                                 NULL, NULL,
                                 default_inq_cb, NULL,
                                 learn_status_cb, info);
        }
    }

  return check_broken_pipe (err);
}



static gpg_error_t
geteventcounter_status_cb (void *opaque, const char *line)
{
  int *result = opaque;
  const char *keyword = line;
  int keywordlen;

  for (keywordlen=0; *line && !spacep (line); line++, keywordlen++)
    ;
  while (spacep (line))
    line++;

  if (keywordlen == 12 && !memcmp (keyword, "EVENTCOUNTER", keywordlen))
    {
      static int any_count;
      static unsigned int last_count;
      unsigned int count;

      if (sscanf (line, "%*u %*u %u ", &count) == 1)
        {
          if (any_count && last_count != count)
            *result = 1;
          any_count = 1;
          last_count = count;
        }
    }

  return 0;
}


static gpg_error_t
read_status_cb (void *opaque, const void *buffer, size_t length)
{
  char *flag = opaque;

  if (length == 0)
    *flag = 'r';
  else
    *flag = *((char *) buffer);

  return 0;
}


/* Check the agent status.  This returns 0 if a token is present,
   GPG_ERR_CARD_REMOVED if no token is present, and an error code
   otherwise.  */
gpg_error_t
scute_agent_check_status (void)
{
  static char last_flag;
  gpg_error_t err;
  int any = 0;
  char flag = '-';

  err = ensure_agent_connection ();
  if (err)
    return err;

  /* First we look at the eventcounter to see if anything happened at
     all.  This is a low overhead function which won't even clutter a
     gpg-agent log file.  There is no need for error checking here. */
  if (last_flag)
    {
      err = assuan_transact (agent_ctx, "GETEVENTCOUNTER",
                             NULL, NULL,
                             NULL, NULL,
                             geteventcounter_status_cb, &any);
      check_broken_pipe (err);
    }

  if (any || !last_flag)
    {
      err = assuan_transact (agent_ctx, "SCD GETINFO status",
                             read_status_cb, &flag,
                             default_inq_cb, NULL,
                             NULL, NULL);
      err = check_broken_pipe (err);
      if (err)
        return err;
      last_flag = flag;
    }
  else
    flag = last_flag;


  if (flag == 'r')
    return gpg_error (GPG_ERR_CARD_REMOVED);

  return 0;
}


/* We only support RSA signatures up to 4096 bits.  */
#define MAX_SIGNATURE_BITS 4096

/* Enough space to hold a 4096 bit RSA signature in an S-expression.  */
#define MAX_SIGNATURE_LEN 640	/* FIXME: magic value */

struct signature
{
  unsigned char data[MAX_SIGNATURE_LEN];
  int len;
};

static gpg_error_t
pksign_cb (void *opaque, const void *buffer, size_t length)
{
  struct signature *sig = opaque;

  if (sig->len + length > MAX_SIGNATURE_LEN)
    {
      DEBUG (DBG_INFO, "maximum signature length exceeded");
      return gpg_error (GPG_ERR_BAD_DATA);
    }

  memcpy (&sig->data[sig->len], buffer, length);
  sig->len += length;

  return 0;
}

/* Parse the result of an pksign operation which is a s-expression in
   canonical form that looks like (7:sig-val(3:rsa(1:s<LENGTH>:<DATA>))).
   The raw result is stored in RESULT of size *LEN, and *LEN is
   adjusted to the actual size.  */
static gpg_error_t
pksign_parse_result (const struct signature *sig,
                     unsigned char *result, unsigned int *len)
{
  gpg_error_t err;
  const unsigned char *s = sig->data;
  size_t n;
  int depth;

  if (*s++ != '(')
    gpg_error (GPG_ERR_INV_SEXP);

  n = snext (&s);
  if (! n)
    return gpg_error (GPG_ERR_INV_SEXP);
  if (! smatch (&s, n, "sig-val"))
    return gpg_error (GPG_ERR_UNKNOWN_SEXP);

  if (*s++ != '(')
    gpg_error (GPG_ERR_UNKNOWN_SEXP);

  n = snext (&s);
  if (! n)
    return gpg_error (GPG_ERR_INV_SEXP);
  if (! smatch (&s, n, "rsa"))
    return gpg_error (GPG_ERR_UNKNOWN_SEXP);

  if (*s++ != '(')
    gpg_error (GPG_ERR_UNKNOWN_SEXP);

  n = snext (&s);
  if (! n)
    return gpg_error (GPG_ERR_INV_SEXP);
  if (! smatch (&s, n, "s"))
    return gpg_error (GPG_ERR_UNKNOWN_SEXP);

  n = snext (&s);
  if (! n)
    return gpg_error (GPG_ERR_INV_SEXP);

  /* Remove a possible prepended zero byte. */
  if (!*s && n > 1)
    {
      n -= 1;
      s += 1;
    }

  if (*len < (unsigned int) n)
    return gpg_error (GPG_ERR_INV_LENGTH);

  *len = (unsigned int) n;
  memcpy (result, s, n);
  s += n;

  depth = 3;
  err = sskip (&s, &depth);
  if (err)
    return err;
  if (s - sig->data != sig->len || depth != 0)
    return gpg_error (GPG_ERR_INV_SEXP);

  return 0;
}

/* Decodes the hash DATA of size LEN (if necessary).  Returns a
   pointer to the raw hash data in R_DATA, the size in R_LEN, and the
   name of the hash function in R_HASH.

   Prior to TLSv1.2, the hash function was the concatenation of MD5
   and SHA1 applied to the data respectively, and no encoding was
   applied.  From TLSv1.2 on, the hash value is prefixed with an hash
   identifier and encoded using ASN1.

   FIXME: Reference.  */
static gpg_error_t
decode_hash (const unsigned char *data, int len,
             const unsigned char **r_data, size_t *r_len,
             const char **r_hash)
{
  static unsigned char rmd160_prefix[15] = /* Object ID is 1.3.36.3.2.1 */
    { 0x30, 0x21, 0x30, 0x09, 0x06, 0x05, 0x2b, 0x24, 0x03,
      0x02, 0x01, 0x05, 0x00, 0x04, 0x14  };
  static unsigned char sha1_prefix[15] =   /* (1.3.14.3.2.26) */
    { 0x30, 0x21, 0x30, 0x09, 0x06, 0x05, 0x2b, 0x0e, 0x03,
      0x02, 0x1a, 0x05, 0x00, 0x04, 0x14  };
  static unsigned char sha224_prefix[19] = /* (2.16.840.1.101.3.4.2.4) */
    { 0x30, 0x2D, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48,
      0x01, 0x65, 0x03, 0x04, 0x02, 0x04, 0x05, 0x00, 0x04,
      0x1C  };
  static unsigned char sha256_prefix[19] = /* (2.16.840.1.101.3.4.2.1) */
    { 0x30, 0x31, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86,
      0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x01, 0x05,
      0x00, 0x04, 0x20  };
  static unsigned char sha384_prefix[19] = /* (2.16.840.1.101.3.4.2.2) */
    { 0x30, 0x41, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86,
      0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x02, 0x05,
      0x00, 0x04, 0x30  };
  static unsigned char sha512_prefix[19] = /* (2.16.840.1.101.3.4.2.3) */
    { 0x30, 0x51, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86,
      0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x03, 0x05,
      0x00, 0x04, 0x40  };

#define HANDLE(hash,hashlen)                                            \
  if (len == sizeof hash ## _prefix + (hashlen)                         \
      && !memcmp (data, hash ## _prefix, sizeof hash ## _prefix))       \
    {                                                                   \
      *r_data = data + sizeof hash ## _prefix;                          \
      *r_len = hashlen;                                                 \
      *r_hash = #hash;                                                  \
    }

  if (len == 36)
    {
      /* Prior to TLSv1.2, a combination of MD5 and SHA1 was used.  */
      *r_data = data;
      *r_len = 36;
      *r_hash = "tls-md5sha1";
    }
      /* TLSv1.2 encodes the hash value using ASN1.  */
  else HANDLE (sha1,   20)
  else HANDLE (rmd160, 20)
  else HANDLE (sha224, 28)
  else HANDLE (sha256, 32)
  else HANDLE (sha384, 48)
  else HANDLE (sha512, 64)
    else
      return gpg_error (GPG_ERR_INV_ARG);

#undef HANDLE

  return 0;
}


struct sethash_inq_parm_s
{
  assuan_context_t ctx;
  const void *data;
  size_t datalen;
};


/* This is the inquiry callback required by the SETHASH command.  */
static gpg_error_t
sethash_inq_cb (void *opaque, const char *line)
{
  gpg_error_t err = 0;
  struct sethash_inq_parm_s *parm = opaque;

  if (has_leading_keyword (line, "TBSDATA"))
    {
      err = assuan_send_data (parm->ctx, parm->data, parm->datalen);
    }
  else
    err = default_inq_cb (opaque, line);

  return err;
}

/* Call the agent to sign (DATA,LEN) using the key described by
 * HEXGRIP.  Stores the signature in SIG_RESULT and its length at
 * SIG_LEN; SIGLEN must initially point to the allocated size of
 * SIG_RESULT.  */
gpg_error_t
scute_agent_sign (const char *hexgrip, CK_MECHANISM_TYPE mechtype,
                  unsigned char *data, int len,
		  unsigned char *sig_result, unsigned int *sig_len)
{
  char cmd[150];
  gpg_error_t err;
  const char *hash;
  const unsigned char *raw_data;
  size_t raw_len;
#define MAX_DATA_LEN	64	/* Size of an SHA512 sum.  */
  unsigned char pretty_data[2 * MAX_DATA_LEN + 1];
  int i;
  struct signature sig;
  int nopadding = (mechtype == CKM_RSA_X_509);

  sig.len = 0;

  if (sig_len == NULL)
    return gpg_error (GPG_ERR_INV_ARG);

  if (nopadding)
    {
      raw_data = data;
      raw_len = len;
      hash = NULL;
    }
  else
    {
      err = decode_hash (data, len, &raw_data, &raw_len, &hash);
      if (err)
        return err;
    }

  if (sig_result == NULL)
    {
      *sig_len = raw_len;
      return 0;
    }

  if (!hexgrip || !sig_result)
    return gpg_error (GPG_ERR_INV_ARG);

  snprintf (cmd, sizeof (cmd), "SIGKEY %s", hexgrip);

  err = ensure_agent_connection ();
  if (err)
    return err;
  err = assuan_transact (agent_ctx, cmd, NULL, NULL, default_inq_cb,
                         NULL, NULL, NULL);
  err = check_broken_pipe (err);
  if (err)
    return err;

  if (nopadding)
    {
      struct sethash_inq_parm_s parm;

      parm.ctx = agent_ctx;
      parm.data = raw_data;
      parm.datalen = raw_len;
      snprintf (cmd, sizeof (cmd), "SETHASH %s --inquire",
                (raw_len && raw_data[raw_len -1] == 0xBC)? "--pss":"");
      err = assuan_transact (agent_ctx, cmd, NULL, NULL,
                             sethash_inq_cb, &parm, NULL, NULL);
    }
  else
    {
      for (i = 0; i < raw_len; i++)
        snprintf (&pretty_data[2 * i], 3, "%02X", raw_data[i]);
      pretty_data[2 * raw_len] = '\0';
      snprintf (cmd, sizeof (cmd), "SETHASH --hash=%s %s", hash, pretty_data);
      err = assuan_transact (agent_ctx, cmd, NULL, NULL, default_inq_cb,
                             NULL, NULL, NULL);
    }
  err = check_broken_pipe (err);
  if (err)
    return err;

  err = assuan_transact (agent_ctx, "PKSIGN",
			 pksign_cb, &sig, default_inq_cb, NULL, NULL, NULL);
  err = check_broken_pipe (err);
  if (err)
    return err;

  err = pksign_parse_result (&sig, sig_result, sig_len);
  return err;
}



struct pkdecrypt_parm_s
{
  unsigned int len;
  unsigned char data[512];
  assuan_context_t ctx;
  const unsigned char *ciphertext;
  size_t ciphertextlen;
};


static gpg_error_t
pkdecrypt_data_cb (void *opaque, const void *buffer, size_t length)
{
  struct pkdecrypt_parm_s *parm = opaque;

  if (parm->len + length > sizeof parm->data)
    {
      DEBUG (DBG_INFO, "maximum decryption result length exceeded");
      return gpg_error (GPG_ERR_BAD_DATA);
    }

  memcpy (parm->data + parm->len, buffer, length);
  parm->len += length;

  return 0;
}


/* Handle the inquiries from pkdecrypt.  Note, we only send the data,
 * assuan_transact takes care of flushing and writing the "END".  */
static gpg_error_t
pkdecrypt_inq_cb (void *opaque, const char *line)
{
  struct pkdecrypt_parm_s *parm = opaque;
  gpg_error_t err;
  const char *keyword = line;
  int keywordlen;

  for (keywordlen = 0; *line && !spacep (line); line++, keywordlen++)
    ;
  while (spacep (line))
    line++;

  if (keywordlen == 10 && !memcmp (keyword, "CIPHERTEXT", 10))
    err = assuan_send_data (parm->ctx, parm->ciphertext, parm->ciphertextlen);
  else
    err = default_inq_cb (NULL, line);

  return err;
}



/* Parse the result of a pkdecrypt operation which is an s-expression
 * in canonical form that looks like
 * (5:value<NDATA>:<DATA>).
 *
 * The raw result is stored in RESULT which has a size of *R_LEN, and
 * *R_LEN is adjusted to the actual size.  */
static gpg_error_t
pkdecrypt_parse_result (struct pkdecrypt_parm_s *ctx,
                        unsigned char *result, unsigned int *r_len)
{
  char *buf = ctx->data;
  size_t len = ctx->len;
  char *endp, *raw;
  size_t n, rawlen;

  if (len < 13 || memcmp (buf, "(5:value", 8) )
    return gpg_error (GPG_ERR_INV_SEXP);
  len -= 8;
  buf += 8;

  n = strtoul (buf, &endp, 10);
  if (!n || *endp != ':')
    return gpg_error (GPG_ERR_INV_SEXP);
  endp++;
  if ((endp-buf)+n > len)
    return gpg_error (GPG_ERR_INV_SEXP); /* Oops: Inconsistent S-Exp. */

  /* Let (RAW,RAWLEN) describe the pkcs#1 block and remove that padding.  */
  raw = endp;
  rawlen = n;

  if (rawlen < 10)  /* 0x00 + 0x02 + <1_random> + 0x00 + <16-session> */
    return gpg_error (GPG_ERR_INV_SESSION_KEY);

  if (raw[0] || raw[1] != 2 )  /* Wrong block type version. */
    return gpg_error (GPG_ERR_INV_SESSION_KEY);

  for (n=2; n < rawlen && raw[n]; n++) /* Skip the random bytes. */
    ;
  if (n+1 >= rawlen || raw[n] )
    return gpg_error (GPG_ERR_INV_SESSION_KEY);
  n++; /* Skip the zero byte */

  if (*r_len < (rawlen - n))
    return gpg_error (GPG_ERR_TOO_LARGE);
  memcpy (result, raw + n, rawlen - n);
  *r_len = rawlen - n;
  return 0;
}


/* Call the agent to decrypt (ENCDATA,ENCDATALEN) using the key
 * described by HEXGRIP.  Stores the plaintext at R_PLAINDATA and its
 * length at R_PLAINDATALEN; R_PLAINDATALEN must initially point to
 * the allocated size of R_PLAINDATA and is updated to the actual used
 * size on return.  */
gpg_error_t
scute_agent_decrypt (const char *hexgrip,
                     unsigned char *encdata, int encdatalen,
                     unsigned char *r_plaindata, unsigned int *r_plaindatalen)
{
  char cmd[150];
  gpg_error_t err;
  struct pkdecrypt_parm_s pkdecrypt;
  char *s_data;
  size_t s_datalen;

  if (!hexgrip || !encdata || !encdatalen || !r_plaindatalen)
    return gpg_error (GPG_ERR_INV_ARG);

  if (!r_plaindata)
    {
      /* Fixme: We do not return the minimal required length but our
       * internal buffer size.  */
      pkdecrypt.len = *r_plaindatalen;
      *r_plaindatalen = sizeof pkdecrypt.data - 1;
      if (pkdecrypt.len > sizeof pkdecrypt.data - 1)
        return gpg_error (GPG_ERR_INV_LENGTH);
      return 0;
    }

  err = ensure_agent_connection ();
  if (err)
    return err;

  snprintf (cmd, sizeof (cmd), "SETKEY %s", hexgrip);
  err = assuan_transact (agent_ctx, cmd,
                         NULL, NULL,
                         default_inq_cb, NULL,
			 NULL, NULL);
  err = check_broken_pipe (err);
  if (err)
    return err;

  /* Convert the input into an appropriate s-expression as expected by
   * gpg-agent which is:
   *
   *  (enc-val
   *    (flags pkcs1)
   *    (rsa
   *      (a VALUE)))
   *
   * Out of convenience we append a non-counted extra nul to the
   * created canonical s-expression.
   */
  s_data = malloc (100 + encdatalen);
  if (!s_data)
    return gpg_error_from_syserror ();
  snprintf (s_data, 50, "(7:enc-val(5:flags5:pkcs1)(3:rsa(1:a%d:",
            encdatalen);
  s_datalen = strlen (s_data);
  memcpy (s_data + s_datalen, encdata, encdatalen);
  s_datalen += encdatalen;
  memcpy (s_data + s_datalen, ")))", 4);
  s_datalen += 3;

  pkdecrypt.len = 0;
  pkdecrypt.ctx = agent_ctx;
  pkdecrypt.ciphertext = s_data;
  pkdecrypt.ciphertextlen = s_datalen;
  err = assuan_transact (agent_ctx, "PKDECRYPT",
			 pkdecrypt_data_cb, &pkdecrypt,
                         pkdecrypt_inq_cb, &pkdecrypt,
                         NULL, NULL);
  err = check_broken_pipe (err);
  if (!err)
    err = pkdecrypt_parse_result (&pkdecrypt, r_plaindata, r_plaindatalen);

  free (s_data);
  return err;
}


/* Determine if FPR is trusted.  */
gpg_error_t
scute_agent_is_trusted (const char *fpr, bool *is_trusted)
{
  gpg_error_t err;
  bool trusted = false;
  char cmd[150];

  err = ensure_agent_connection ();
  if (err)
    return err;

  snprintf (cmd, sizeof (cmd), "ISTRUSTED %s", fpr);
  err = assuan_transact (agent_ctx, cmd, NULL, NULL, default_inq_cb,
			 NULL, NULL, NULL);
  err = check_broken_pipe (err);
  if (err && gpg_err_code (err) != GPG_ERR_NOT_TRUSTED)
    return err;
  else if (!err)
    trusted = true;

  *is_trusted = trusted;
  return 0;
}


#define GET_CERT_INIT_SIZE 2048

struct get_cert_s
{
  unsigned char *cert_der;
  int cert_der_len;
  int cert_der_size;
};


gpg_error_t
get_cert_data_cb (void *opaque, const void *data, size_t data_len)
{
  struct get_cert_s *cert_s = opaque;
  int needed_size;

  needed_size = cert_s->cert_der_len + data_len;
  if (needed_size > cert_s->cert_der_size)
    {
      unsigned char *new_cert_der;
      int new_cert_der_size = cert_s->cert_der_size;

      if (new_cert_der_size == 0)
	new_cert_der_size = GET_CERT_INIT_SIZE;
      while (new_cert_der_size < needed_size)
	new_cert_der_size *= 2;

      if (cert_s->cert_der == NULL)
	new_cert_der = malloc (new_cert_der_size);
      else
	new_cert_der = realloc (cert_s->cert_der, new_cert_der_size);

      if (new_cert_der == NULL)
	return gpg_error_from_syserror ();

      cert_s->cert_der = new_cert_der;
      cert_s->cert_der_size = new_cert_der_size;
    }

  memcpy (cert_s->cert_der + cert_s->cert_der_len, data, data_len);
  cert_s->cert_der_len += data_len;

  return 0;
}


/* Try to get certificate for CERTREF.  */
gpg_error_t
scute_agent_get_cert (const char *certref, struct cert *cert)
{
  gpg_error_t err;
  char cmd[150];
  struct get_cert_s cert_s;

  cert_s.cert_der = NULL;
  cert_s.cert_der_len = 0;
  cert_s.cert_der_size = 0;

  err = ensure_agent_connection ();
  if (err)
    return err;

  snprintf (cmd, sizeof (cmd), "SCD READCERT %s", certref);
  err = assuan_transact (agent_ctx, cmd, get_cert_data_cb, &cert_s,
			 NULL, NULL, NULL, NULL);
  err = check_broken_pipe (err);
  /* Just to be safe... */
  if (!err && (cert_s.cert_der_len <= 16 || cert_s.cert_der[0] != 0x30))
    {
      DEBUG (DBG_INFO, "bad card certificate rejected");
      err = gpg_error (GPG_ERR_BAD_CERT);
    }
  if (err)
    {
      if (cert_s.cert_der)
	free (cert_s.cert_der);
      return err;
    }

  DEBUG (DBG_INFO, "got certificate from card with length %i",
	 cert_s.cert_der_len);

  cert->cert_der = cert_s.cert_der;
  cert->cert_der_len = cert_s.cert_der_len;
  strncpy (cert->certref, certref, sizeof cert->certref -1);
  cert->certref[sizeof cert->certref - 1] = 0;

  return 0;
}

struct random_request
{
    unsigned char *buffer;
    size_t len;
};

gpg_error_t
get_challenge_data_cb (void *opaque, const void *line, size_t len)
{
  struct random_request *request = opaque;

  if (len != request->len)
    return gpg_error (GPG_ERR_INV_LENGTH);

  memcpy (request->buffer, line, len);

  return 0;
}

gpg_error_t
scute_agent_get_random (unsigned char *data, size_t len)
{
    char command[16];
    gpg_error_t err;
    struct random_request request;

    err = ensure_agent_connection ();
    if (err)
      return err;

    snprintf (command, sizeof(command), "SCD RANDOM %zu", len);

    request.buffer = data;
    request.len = len;
    err = assuan_transact (agent_ctx, command, get_challenge_data_cb,
                           &request, NULL, NULL, NULL, NULL);
    err = check_broken_pipe (err);
    return err;
}


void
scute_agent_finalize (void)
{
  if (!agent_ctx)
    {
      DEBUG (DBG_CRIT, "no GPG Agent connection established");
      return;
    }

  DEBUG (DBG_INFO, "releasing agent context");
  assuan_release (agent_ctx);
  agent_ctx = NULL;
}
