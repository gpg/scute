/* agent.c - Talking to gpg-agent.
   Copyright (C) 2006, 2007, 2008 g10 Code GmbH

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

#include <stdlib.h>
#include <stdio.h>
#include <locale.h>
#include <errno.h>
#include <string.h>
#include <stdarg.h>

#include <assuan.h>
#include <gpg-error.h>

#include "debug.h"
#include "support.h"
#include "agent.h"

#ifdef HAVE_W32_SYSTEM
#define PATHSEP_C ';'
#else
#define PATHSEP_C ':'
#endif


/* The global agent context.  */
static assuan_context_t agent_ctx = NULL;


#ifdef HAVE_W32_SYSTEM
/* Helper function to build_w32_commandline. */
static char *
build_w32_commandline_copy (char *buffer, const char *string)
{
  char *p = buffer;
  const char *s;

  if (!*string) /* Empty string. */
    p = stpcpy (p, "\"\"");
  else if (strpbrk (string, " \t\n\v\f\""))
    {
      /* Need top do some kind of quoting.  */
      p = stpcpy (p, "\"");
      for (s=string; *s; s++)
        {
          *p++ = *s;
          if (*s == '\"')
            *p++ = *s;
        }
      *p++ = '\"';
      *p = 0;
    }
  else
    p = stpcpy (p, string);

  return p;
}


/* Build a command line for use with W32's CreateProcess.  On success
   CMDLINE gets the address of a newly allocated string.  */
static gpg_error_t
build_w32_commandline (const char *pgmname, const char * const *argv, 
                       char **cmdline)
{
  int i, n;
  const char *s;
  char *buf, *p;

  *cmdline = NULL;
  n = 0;
  s = pgmname;
  n += strlen (s) + 1 + 2;  /* (1 space, 2 quoting */
  for (; *s; s++)
    if (*s == '\"')
      n++;  /* Need to double inner quotes.  */
  for (i=0; (s=argv[i]); i++)
    {
      n += strlen (s) + 1 + 2;  /* (1 space, 2 quoting */
      for (; *s; s++)
        if (*s == '\"')
          n++;  /* Need to double inner quotes.  */
    }
  n++;

  buf = p = malloc (n);
  if (!buf)
    return gpg_error_from_syserror ();

  p = build_w32_commandline_copy (p, pgmname);
  for (i=0; argv[i]; i++) 
    {
      *p++ = ' ';
      p = build_w32_commandline_copy (p, argv[i]);
    }

  *cmdline= buf;
  return 0;
}
#endif /*HAVE_W32_SYSTEM*/


/* Spawn a new process and immediatley detach from it.  The name of
   the program to exec is PGMNAME and its arguments are in ARGV (the
   programname is automatically passed as first argument).  An error
   is returned if pgmname is not executable; to make this work it is
   necessary to provide an absolute file name.  All standard file
   descriptors are connected to /dev/null.  */
static gpg_error_t
spawn_process_detached (const char *pgmname, const char *argv[])
{
#ifdef HAVE_W32_SYSTEM
  gpg_error_t err;
  SECURITY_ATTRIBUTES sec_attr;
  PROCESS_INFORMATION pi = 
    {
      NULL,      /* Returns process handle.  */
      0,         /* Returns primary thread handle.  */
      0,         /* Returns pid.  */
      0          /* Returns tid.  */
    };
  STARTUPINFO si;
  int cr_flags;
  char *cmdline;

  if (access (pgmname, X_OK))
    return gpg_error_from_syserror ();

  /* Prepare security attributes.  */
  memset (&sec_attr, 0, sizeof sec_attr );
  sec_attr.nLength = sizeof sec_attr;
  sec_attr.bInheritHandle = FALSE;
  
  /* Build the command line.  */
  err = build_w32_commandline (pgmname, argv, &cmdline);
  if (err)
    return err; 

  /* Start the process.  */
  memset (&si, 0, sizeof si);
  si.cb = sizeof (si);
  si.dwFlags = STARTF_USESHOWWINDOW;
  si.wShowWindow = SW_MINIMIZE;

  cr_flags = (CREATE_DEFAULT_ERROR_MODE
              | GetPriorityClass (GetCurrentProcess ())
              | CREATE_NEW_PROCESS_GROUP
              | DETACHED_PROCESS); 
  DEBUG ("CreateProcess(detached), path=`%s' cmdline=`%s'\n",
	 pgmname, cmdline);
  if (!CreateProcess (pgmname,       /* Program to start.  */
                      cmdline,       /* Command line arguments.  */
                      &sec_attr,     /* Process security attributes.  */
                      &sec_attr,     /* Thread security attributes.  */
                      FALSE,         /* Inherit handles.  */
                      cr_flags,      /* Creation flags.  */
                      NULL,          /* Environment.  */
                      NULL,          /* Use current drive/directory.  */
                      &si,           /* Startup information. */
                      &pi            /* Returns process information.  */
                      ))
    {
      DEBUG ("CreateProcess(detached) failed: %i\n", GetLastError ());
      free (cmdline);
      return gpg_error (GPG_ERR_GENERAL);
    }
  free (cmdline);
  cmdline = NULL;

  DEBUG ("CreateProcess(detached) ready: hProcess=%p hThread=%p"
	 " dwProcessID=%d dwThreadId=%d\n",
	 pi.hProcess, pi.hThread,
	 (int) pi.dwProcessId, (int) pi.dwThreadId);

  CloseHandle (pi.hThread); 

  return 0;

#else
  pid_t pid;
  int i;

  if (getuid() != geteuid())
    return gpg_error (GPG_ERR_BUG);

  if (access (pgmname, X_OK))
    return gpg_error_from_syserror ();

  pid = fork ();
  if (pid == (pid_t)(-1))
    {
      DEBUG (_("error forking process: %s\n"), strerror (errno));
      return gpg_error_from_syserror ();
    }
  if (!pid)
    {
      gcry_control (GCRYCTL_TERM_SECMEM);
      if (setsid() == -1 || chdir ("/"))
        _exit (1);
      pid = fork (); /* Double fork to let init take over the new child. */
      if (pid == (pid_t)(-1))
        _exit (1);
      if (pid)
        _exit (0);  /* Let the parent exit immediately. */

      do_exec (pgmname, argv, -1, -1, -1, NULL);

      /*NOTREACHED*/
    }
  
  if (waitpid (pid, NULL, 0) == -1)
    DEBUG ("waitpid failed in spawn_process_detached: %s", strerror (errno));

  return 0;
#endif /* !HAVE_W32_SYSTEM*/
}


/* Establish a connection to a running GPG agent.  */
static gpg_error_t
agent_connect (assuan_context_t *ctx_r)
{
  /* If we ever failed to connect via a socket we will force the use
     of the pipe based server for the lifetime of the process.  */
  static int force_pipe_server = 0;

  gpg_error_t err = 0;
  char *infostr;
  char *ptr;

 restart:

  infostr = force_pipe_server ? NULL : getenv ("GPG_AGENT_INFO");
  if (!infostr || !*infostr)
    {
      char *sockname;

      /* First check whether we can connect at the standard
         socket.  */
      sockname = make_filename (default_homedir (), "S.gpg-agent", NULL);
      if (! sockname)
	return gpg_error_from_errno (errno);
	
      err = assuan_socket_connect (ctx_r, sockname, 0);

      if (err)
        {
	  const char *agent_program;

          /* With no success start a new server.  */
	  DEBUG ("no running GPG agent, starting one");
          
          agent_program = get_gpg_agent_path ();

#ifdef HAVE_W32_SYSTEM
          {
            /* Under Windows we start the server in daemon mode.  This
               is because the default is to use the standard socket
               and thus there is no need for the GPG_AGENT_INFO
               envvar.  This is possible as we don't have a real unix
               domain socket but use a plain file and thus there is no
               need to care about non-local file systems. */
            const char *argv[3];

            argv[0] = "--daemon";
            argv[1] = "--use-standard-socket"; 
            argv[2] = NULL;  

            err = spawn_process_detached (agent_program, argv);
            if (err)
              DEBUG ("failed to start agent `%s': %s\n",
		     agent_program, gpg_strerror (err));
            else
              {
                /* Give the agent some time to prepare itself. */
                _sleep (3);
                /* Now try again to connect the agent.  */
                err = assuan_socket_connect (ctx_r, sockname, 0);
              }
          }
#else /*!HAVE_W32_SYSTEM*/
          {
            const char *pgmname;
            const char *argv[3];
            int no_close_list[3];
            int i;

            if ( !(pgmname = strrchr (agent_program, '/')))
              pgmname = agent_program;
            else
              pgmname++;
            
            argv[0] = pgmname;
            argv[1] = "--server";
            argv[2] = NULL;
            
            i=0;
            no_close_list[i++] = fileno (stderr);
            no_close_list[i] = -1;
            
            /* Connect to the agent and perform initial handshaking. */
            err = assuan_pipe_connect (ctx_r, agent_program, argv,
				       no_close_list);
          }
#endif /*!HAVE_W32_SYSTEM*/
        }
      free (sockname);
    }
  else
    {
      int pid;
      int protocol_version;

      infostr = strdup (infostr);
      if (!infostr)
	return gpg_error_from_errno (errno);

      if (!(ptr = strchr (infostr, PATHSEP_C)) || ptr == infostr)
	{
	  DEBUG ("malformed GPG_AGENT_INFO environment variable");
	  free (infostr);
	  force_pipe_server = 1;
	  goto restart;
	}

      *(ptr++) = 0;
      pid = atoi (ptr);
      while (*ptr && *ptr != PATHSEP_C)
	ptr++;
      protocol_version = *ptr ? atoi (ptr + 1) : 0;
      if (protocol_version != 1)
	{
	  DEBUG ("GPG agent protocol version '%d' not supported",
		 protocol_version);
	  free (infostr);
	  force_pipe_server = 1;
	  goto restart;
	}
      
      err = assuan_socket_connect (ctx_r, infostr, pid);
      free (infostr);
      if (err)
	{
	  DEBUG ("cannot connect to GPG agent: %s", gpg_strerror (err));
	  force_pipe_server = 1;
	  goto restart;
	}
    }

  if (err)
    {
      DEBUG ("cannot connect to GPG agent: %s", gpg_strerror (err));
      return gpg_error (GPG_ERR_NO_AGENT);
    }

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

  err = assuan_transact (ctx, optstr, NULL, NULL, NULL, NULL, NULL, NULL);
  if (err)
    DEBUG ("gpg-agent command '%s' failed: %s", optstr, gpg_strerror (err));
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
  if (!dft_ttyname)
    return 0;

  err = agent_simple_cmd (ctx, "OPTION ttyname=%s", dft_ttyname);
  if (err)
    return err;

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
    err = agent_simple_cmd (ctx, "OPTION xauthority=%s", dft_display);
  if (err)
    return err;

  dft_pinentry_user_data = getenv ("PINENTRY_USER_DATA");
  if (dft_pinentry_user_data)
    err = agent_simple_cmd (ctx, "OPTION pinentry_user_data=%s", dft_display);
  if (err)
    return err;

  return err;
}


/* Try to connect to the agent via socket.  Handle the server's
   initial greeting.  */
gpg_error_t
scute_agent_initialize (void)
{
  gpg_error_t err = 0;

  if (agent_ctx)
    {
      DEBUG ("GPG Agent connection already established");
      return 0;
    }

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


/* Take a 20 byte hexencoded string and put it into the the provided
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

  cnt /= 2;
  for (src = hexstr, cnt = 0; *src && !spacep (src); src += 2, cnt++)
    fpr[cnt] = xtoi_2 (src);

  return 1;
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
  free (info->disp_name);
  free (info->disp_lang);
  free (info->pubkey_url);
  free (info->login_data);

  memset (info, 0, sizeof (*info));
}


/* FIXME: We are not returning out of memory errors.  */
static gpg_error_t
learn_status_cb (void *opaque, const char *line)
{
  struct agent_card_info_s *parm = opaque;
  const char *keyword = line;
  int keywordlen;
  int i;

  for (keywordlen = 0; *line && !spacep (line); line++, keywordlen++)
    ;
  while (spacep (line))
    line++;

  if (keywordlen == 8 && !memcmp (keyword, "SERIALNO", keywordlen))
    {
      if (parm->serialno)
	free (parm->serialno);
      parm->serialno = store_serialno (line);
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
      const char *grip = line;
      while (*line && !spacep (line))
        line++;

      if (line - grip == 40)
	{
	  while (spacep (line))
	    line++;
	  if (!memcmp (line, "OPENPGP.", 8))
	    {
	      int no;
	      line += 8;

	      no = atoi (line);

	      if (no == 1)
		{
		  memcpy (parm->grip1, grip, 40);
		  parm->grip1valid = 1;
		}
	      else if (no == 2)
		{
		  memcpy (parm->grip2, grip, 40);
		  parm->grip2valid = 1;
		}
	      else if (no == 3)
		{
		  memcpy (parm->grip3, grip, 40);
		  parm->grip3valid = 1;
		}
	    }
	}
    }
  return 0;
}


/* Call the agent to learn about a smartcard.  */
gpg_error_t
scute_agent_learn (struct agent_card_info_s *info)
{
  gpg_error_t err;

  memset (info, 0, sizeof (*info));
  err = assuan_transact (agent_ctx, "LEARN --send",
			 NULL, NULL, NULL, NULL, learn_status_cb, info);

  return err;
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
  gpg_error_t err;
  char flag = '-';

  err = assuan_transact (agent_ctx, "SCD GETINFO status",
			 read_status_cb, &flag, NULL, NULL, NULL, NULL);

  if (err)
    return err;

  if (flag == 'r')
    return gpg_error (GPG_ERR_CARD_REMOVED);

  return 0;
}


#define MAX_SIGNATURE_LEN 256

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
    return gpg_error (GPG_ERR_BAD_DATA);

  memcpy (&sig->data[sig->len], buffer, length);
  sig->len += length;

  return 0;
}


#define SIG_PREFIX "(7:sig-val(3:rsa(1:s128:"
#define SIG_PREFIX_LEN (sizeof (SIG_PREFIX) - 1)
#define SIG_POSTFIX ")))"
#define SIG_POSTFIX_LEN (sizeof (SIG_POSTFIX) - 1)
#define SIG_LEN 128

/* Call the agent to learn about a smartcard.  */
gpg_error_t
scute_agent_sign (char *grip, unsigned char *data, int len,
		  unsigned char *sig_result, unsigned int *sig_len)
{
  char cmd[150];
  gpg_error_t err;
#define MAX_DATA_LEN 36
  unsigned char pretty_data[2 * MAX_DATA_LEN + 1];
  int i;
  struct signature sig;

  sig.len = 0;

  if (sig_len == NULL)
    return gpg_error (GPG_ERR_INV_ARG);

  if (sig_result == NULL)
    {
      *sig_len = SIG_LEN;
      return 0;
    }

  if (len > MAX_DATA_LEN)
    return gpg_error (GPG_ERR_INV_ARG);

  if (grip == NULL || sig_result == NULL || *sig_len < SIG_LEN)
    return gpg_error (GPG_ERR_INV_ARG);

  snprintf (cmd, sizeof (cmd), "SIGKEY %s", grip);
  err = assuan_transact (agent_ctx, cmd, NULL, NULL, NULL, NULL, NULL, NULL);
  if (err)
    return err;

  for (i = 0; i < len; i++)
    sprintf (&pretty_data[2 * i], "%02X", data[i]);
  pretty_data[2 * len] = '\0';

  snprintf (cmd, sizeof (cmd), "sethash --hash=tls-md5sha1 %s", pretty_data);
  err = assuan_transact (agent_ctx, cmd, NULL, NULL, NULL, NULL, NULL, NULL);
  if (err)
    return err;

  err = assuan_transact (agent_ctx, "PKSIGN",
			 pksign_cb, &sig, NULL, NULL, NULL, NULL);
  if (err)
    return err;

  if (sig.len != SIG_PREFIX_LEN + SIG_LEN + SIG_POSTFIX_LEN)
    return gpg_error (GPG_ERR_BAD_SIGNATURE);
  if (memcmp (sig.data, SIG_PREFIX, SIG_PREFIX_LEN))
    return gpg_error (GPG_ERR_BAD_SIGNATURE);
  if (memcmp (sig.data + sig.len - SIG_POSTFIX_LEN,
	      SIG_POSTFIX, SIG_POSTFIX_LEN))
    return gpg_error (GPG_ERR_BAD_SIGNATURE);

  memcpy (sig_result, sig.data + SIG_PREFIX_LEN, SIG_LEN);
  *sig_len = SIG_LEN;
  
  return 0;
}


/* Determine if FPR is trusted.  */
gpg_error_t scute_agent_is_trusted (char *fpr, bool *is_trusted)
{
  gpg_error_t err;
  bool trusted = false;
  char cmd[150];

  snprintf (cmd, sizeof (cmd), "ISTRUSTED %s", fpr);
  err = assuan_transact (agent_ctx, cmd, NULL, NULL, NULL, NULL, NULL, NULL);
  if (err && gpg_err_code (err) != GPG_ERR_NOT_TRUSTED)
    return err;
  else if (!err)
    trusted = true;

  *is_trusted = trusted;
  return 0;
}


void
scute_agent_finalize (void)
{
  if (!agent_ctx)
    {
      DEBUG ("no GPG Agent connection established");
      return;
    }

  assuan_disconnect (agent_ctx);
  agent_ctx = NULL;
}
