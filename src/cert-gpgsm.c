/* cert-gpgsm.c - Scute certificate searching.
   Copyright (C) 2006 g10 Code GmbH

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

#include <time.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <stdbool.h>

#include <gpg-error.h>
#include <assuan.h>

#include "cert.h"
#include "support.h"


/* The maximum length of a key listing line.  We take the double of
   the allowed Assuan line length to avoid a memmove after a part of a
   line has been processed.  FIXME: There is actually no limit on the
   length of the line. */
#define MAX_LINE_LEN	(1024*2)

struct search_ctx
{
  /* The pending line in an active key listing.  */
  char pending[MAX_LINE_LEN + 1];
  unsigned int pending_len;

  /* The caller's search callback, invoked for each certificate.  */
  cert_search_cb_t search_cb;
  void *search_cb_hook;

  /* The current certificate.  */
  struct cert cert;
};


/* Release allocated storage for the certificate CERT and reset the
   certificate.  */
static void
cert_reset (struct cert *cert)
{
  if (cert->issuer_serial)
    free (cert->issuer_serial);
  if (cert->issuer_name)
    free (cert->issuer_name);
  if (cert->uid)
    free (cert->uid);
  if (cert->cert_der)
    free (cert->cert_der);

  memset (cert, '\0', sizeof (struct cert));
}


/* Support routines for key list processing.  */

#define atoi_1(p)   (*(p) - '0' )
#define atoi_2(p)   ((atoi_1(p) * 10) + atoi_1((p)+1))
#define atoi_4(p)   ((atoi_2(p) * 100) + atoi_2((p)+2))

/* Parse the string TIMESTAMP into a time_t.  The string may either be
   seconds since Epoch or in the ISO 8601 format like
   "20390815T143012".  Returns 0 for an empty string or seconds since
   Epoch. Leading spaces are skipped. If ENDP is not NULL, it will
   point to the next non-parsed character in TIMESTRING. */
static time_t
parse_timestamp (const char *timestamp, char **endp)
{
  /* Need to skip leading spaces, because that is what strtoul does
     but not our ISO 8601 checking code. */
  while (*timestamp && *timestamp== ' ')
    timestamp++;
  if (!*timestamp)
    return 0;

  if (strlen (timestamp) >= 15 && timestamp[8] == 'T')
    {
      struct tm buf;
      int year;

      year = atoi_4 (timestamp);
      if (year < 1900)
        return (time_t)(-1);

      /* Fixme: We would better use a configure test to see whether
         mktime can handle dates beyond 2038. */
      if (sizeof (time_t) <= 4 && year >= 2038)
        return (time_t)2145914603; /* 2037-12-31 23:23:23 */

      memset (&buf, 0, sizeof buf);
      buf.tm_year = year - 1900;
      buf.tm_mon = atoi_2 (timestamp+4) - 1; 
      buf.tm_mday = atoi_2 (timestamp+6);
      buf.tm_hour = atoi_2 (timestamp+9);
      buf.tm_min = atoi_2 (timestamp+11);
      buf.tm_sec = atoi_2 (timestamp+13);

      if (endp)
        *endp = (char*)(timestamp + 15);
      return timegm (&buf);
    }
  else
    return (time_t)strtoul (timestamp, endp, 10);
}


/* Decode the C formatted string SRC and store the result in the
   buffer *DESTP which is LEN bytes long.  If LEN is zero, then a
   large enough buffer is allocated with malloc and *DESTP is set to
   the result.  Currently, LEN is only used to specify if allocation
   is desired or not, the caller is expected to make sure that *DESTP
   is large enough if LEN is not zero.  */
static gpg_error_t
decode_c_string (const char *src, char **destp, size_t len)
{
  char *dest;

  /* Set up the destination buffer.  */
  if (len)
    {
      if (len < strlen (src) + 1)
	return gpg_error (GPG_ERR_INTERNAL);

      dest = *destp;
    }
  else
    {
      /* The converted string will never be larger than the original
	 string.  */
      dest = malloc (strlen (src) + 1);
      if (!dest)
	return gpg_error_from_syserror ();

      *destp = dest;
    }

  /* Convert the string.  */
  while (*src)
    {
      if (*src != '\\')
	{
	  *(dest++) = *(src++);
	  continue;
	}

      switch (src[1])
	{
#define DECODE_ONE(match,result)	\
	case match:			\
	  src += 2;			\
	  *(dest++) = result;		\
	  break;

	  DECODE_ONE ('\'', '\'');
	  DECODE_ONE ('\"', '\"');
	  DECODE_ONE ('\?', '\?');
	  DECODE_ONE ('\\', '\\');
	  DECODE_ONE ('a', '\a');
	  DECODE_ONE ('b', '\b');
	  DECODE_ONE ('f', '\f');
	  DECODE_ONE ('n', '\n');
	  DECODE_ONE ('r', '\r');
	  DECODE_ONE ('t', '\t');
	  DECODE_ONE ('v', '\v');

	case 'x':
	  {
	    int val = xtoi_2 (&src[2]);

	    if (val == -1)
	      {
		/* Should not happen.  */
		*(dest++) = *(src++);
		*(dest++) = *(src++);
		if (*src)
		  *(dest++) = *(src++);
		if (*src)
		  *(dest++) = *(src++);
	      }
	    else
	      {
		if (!val)
		  {
		    /* A binary zero is not representable in a C
		       string.  */
		    *(dest++) = '\\';
		    *(dest++) = '0'; 
		  }
		else 
		  *((unsigned char *) dest++) = val;
		src += 4;
	      }
	  }
	  break;

	default:
	  {
	    /* Should not happen.  */
	    *(dest++) = *(src++);
	    *(dest++) = *(src++);
	  }
        } 
    }
  *(dest++) = 0;

  return 0;
}


/* The cert handler for certificate searches.  This is invoked for
   each complete certificate found by search_certs_line, and the last
   pending certificate when EOF is encountered by search_certs.  */
static gpg_error_t
search_certs_cert (struct search_ctx *ctx)
{
  return (*ctx->search_cb) (ctx->search_cb_hook, &ctx->cert);
}


/* The line handler for certificate searches.  This is invoked for
   each complete line found by search_certs.  */
static gpg_error_t
search_certs_line (struct search_ctx *ctx)
{
  char *line;
  enum { RT_NONE, RT_CRT, RT_CRS, RT_FPR, RT_GRP, RT_UID } rectype = RT_NONE;
#define NR_FIELDS 16
  char *field[NR_FIELDS];
  int fields = 0;
  struct cert *cert;

  /* Strip a trailing carriage return.  */
  if (ctx->pending_len > 0
      && ctx->pending[ctx->pending_len - 1] == '\r')
    ctx->pending_len--;
  ctx->pending[ctx->pending_len - 1] = '\0';
  ctx->pending_len = 0;

  cert = &ctx->cert;
  line = ctx->pending;
  while (line && fields < NR_FIELDS)
    {
      field[fields++] = line;
      line = strchr (line, ':');
      if (line)
	*(line++) = '\0';
    }

  if (!strcmp (field[0], "crt"))
    rectype = RT_CRT;
  else if (!strcmp (field[0], "crs"))
    rectype = RT_CRS;
  else if (!strcmp (field[0], "fpr"))
    rectype = RT_FPR;
  else if (!strcmp (field[0], "grp"))
    rectype = RT_GRP;
  else if (!strcmp (field[0], "uid"))
    rectype = RT_UID;
  else 
    rectype = RT_NONE;

  switch (rectype)
    {
    case RT_CRT:
    case RT_CRS:
      /* Reinitialize CERT.  */
      if (cert->valid)
	{
	  gpg_error_t err;

	  err = search_certs_cert (ctx);
	  if (err)
	    return err;

	  cert_reset (cert);
	}

      cert->valid = true;

#if 0
      /* Field 2 has the trust info.  */
      if (fields >= 2)
	set_mainkey_trust_info (key, field[1]);
#endif

      /* Field 3 has the key length.  */
      if (fields >= 3)
	{
	  int i = atoi (field[2]);
	  /* Ignore invalid values.  */
	  if (i > 1)
	    cert->length = i; 
	}

      /* Field 4 has the public key algorithm.  */
      if (fields >= 4)
	{
	  int i = atoi (field[3]);
	  if (i >= 1 && i < 128)
	    cert->pubkey_algo = i;
	}

      /* Field 5 has the long keyid.  Allow short key IDs for the
	 output of an external keyserver listing.  */
      if (fields >= 5 && strlen (field[4]) <= sizeof (cert->keyid) - 1)
	strcpy (cert->keyid, field[4]);

      /* Field 6 has the timestamp (seconds).  */
      if (fields >= 6)
	cert->timestamp = parse_timestamp (field[5], NULL);

      /* Field 7 has the expiration time (seconds).  */
      if (fields >= 7)
	cert->expires = parse_timestamp (field[6], NULL);

      /* Field 8 has the X.509 serial number.  */
      if (fields >= 8)
	{
	  cert->issuer_serial = strdup (field[7]);
	  if (!cert->issuer_serial)
	    return gpg_error_from_syserror ();
	}

#if 0
      /* Field 9 has the ownertrust.  */
      if (fields >= 9)
	set_ownertrust (key, field[8]);
#endif

      /* Field 10 is the issuer name.  */
      if (fields >= 10)
	if (decode_c_string (field[9], &cert->issuer_name, 0))
	  return gpg_error (GPG_ERR_ENOMEM);	/* FIXME */

      /* Field 11 has the signature class.  */

#if 0
      /* Field 12 has the capabilities.  */
      if (fields >= 12)
	set_mainkey_capability (key, field[11]);
#endif
      break;

    case RT_UID:
      if (cert->valid)
	{
	  /* Field 2 has the trust info, and field 10 has the user ID.
	     Note that more than one UID field can appear.  We only
	     remember the last one.  It's not used anyway.  */
	  if (fields >= 10 && !cert->uid)
	    {
	      if (decode_c_string (field[9], &cert->uid, 0))
		return gpg_error (GPG_ERR_ENOMEM);	/* FIXME */
	    }
	}
      break;

    case RT_FPR:
      if (cert->valid)
	{
	  /* Field 10 has the fingerprint (take only the first one).  */
	  if (fields >= 10 && strlen (field[9]) <= sizeof (cert->fpr) - 1)
	    strcpy (cert->fpr, field[9]);

	  /* Field 13 has the gpgsm chain ID (take only the first one).  */
	  if (fields >= 13 && strlen (field[12])
	      <= sizeof (cert->chain_id) - 1)
	    strcpy (cert->chain_id, field[12]);
	}
      break;

    case RT_GRP:
      if (cert->valid)
	{
	  /* Field 10 has the key grip.  */
	  if (fields >= 10 && strlen (field[9]) <= sizeof (cert->grip) - 1)
	    strcpy (cert->grip, field[9]);
	}
      break;

    case RT_NONE:
      /* Unknown record.  */
      break;
    }

  return 0;
}


/* This is the data line callback handler provided to assuan_transact
   in scute_gpgsm_search_certs.  It buffers incomplete lines, and also
   handles the EOF signal provided directly by
   scute_gpgsm_search_certs.  */
static gpg_error_t
search_certs (void *hook, char *line, size_t line_len)
{
  struct search_ctx *ctx = hook;
  gpg_error_t err;

  if (!line)
    {
      /* This indicates an EOF.  */

      /* Check for a pending line, in case GPGSM didn't close with a
	 newline.  */
      if (ctx->pending_len)
	{
	  err = search_certs_line (ctx);
	  if (err)
	    return err;
	}

      /* Check for a pending certificate.  */
      if (ctx->cert.valid)
	return search_certs_cert (ctx);

      return 0;
    }

  while (line_len)
    {
      if (*line == '\n')
	{
	  err = search_certs_line (ctx);
	  if (err)
	    return err;
	}
      else
	{
	  if (ctx->pending_len >= MAX_LINE_LEN)
	    return gpg_error (GPG_ERR_LINE_TOO_LONG);

	  ctx->pending[ctx->pending_len++] = *line;
	}
      line++;
      line_len--;
    }

  return 0;
}


/* Invoke SEARCH_CB for each certificate found using assuan connection
   CTX to GPGSM.  */
static gpg_error_t
scute_gpgsm_search_certs (assuan_context_t ctx, cert_search_cb_t search_cb,
			  void *search_cb_hook)
{
  gpg_error_t err;
  struct search_ctx search;

  err = assuan_transact (ctx, "OPTION with-key-data", NULL, NULL,
			 NULL, NULL, NULL, NULL);
  if (err)
    return err;

  search.pending_len = 0;
  search.search_cb = search_cb;
  search.search_cb_hook = search_cb_hook;
  memset (&search.cert, '\0', sizeof (search.cert));

  err = assuan_transact (ctx, "DUMPKEYS", &search_certs, &search, NULL,
			 NULL, NULL, NULL);
  if (err)
    goto out;

  /* Signal the EOF.  This is not done by Assuan for us.  */
  err = search_certs (&search, NULL, 0);
  if (err)
    goto out;

 out:
  cert_reset (&search.cert);
  return err;
}


struct search_ctx_by_field
{
  /* What we are searching for.  */
  enum { SEARCH_BY_GRIP, SEARCH_BY_FPR } field;

  /* The pattern we are looking for.  */
  const char *pattern;

  cert_search_cb_t search_cb;
  void *search_cb_hook;
};
  

/* This is a compatibility function for GPGSM 2.0.0, which does not
   support the --data option with the EXPORT command.  */
static gpg_error_t
export_cert_compat (char *fpr, struct cert *cert)
{
  gpg_error_t err;
  assuan_context_t ctx;
  const char *argv[] = { "gpgsm", "--server", NULL };
  int got;
#define COMMANDLINELEN 80
  char cmd[COMMANDLINELEN];
  int output_fds[2];
  int child_fds[2];

#define MAX_CERT_SIZE 4096
  cert->cert_der = malloc (MAX_CERT_SIZE);
  if (!cert->cert_der)
    return gpg_error_from_syserror ();

  if(pipe (output_fds) < 0)
    return gpg_error_from_syserror ();

  child_fds[0] = output_fds[1];
  child_fds[1] = -1;

  err = assuan_pipe_connect (&ctx, GPGSM_PATH, argv, child_fds);
  close (output_fds[1]);
  if (err)
    {
      close (output_fds[0]);
      return err;
    }

  snprintf (cmd, sizeof (cmd), "OUTPUT FD=%i", output_fds[1]);
  err = assuan_transact (ctx, cmd, NULL, NULL, NULL, NULL, NULL, NULL);
  if (err)
    goto export_out;

  /* FIXME: This will only work if the certificate is small and fits
     into the pipe buffer completely!!!  */
  snprintf (cmd, sizeof (cmd), "EXPORT %s\n", cert->fpr);
  err = assuan_transact (ctx, cmd, NULL, NULL, NULL, NULL, NULL, NULL);
  if (err)
    goto export_out;

  do
    {
      got = read (output_fds[0], cert->cert_der + cert->cert_der_len,
		  MAX_CERT_SIZE - cert->cert_der_len);
      if (got > 0)
	cert->cert_der_len += got;
    }
  while (!err && got > 0 && cert->cert_der_len < MAX_CERT_SIZE);
  
  if (got < 0 || cert->cert_der_len == MAX_CERT_SIZE)
    err = gpg_error (GPG_ERR_GENERAL);

 export_out:
  assuan_disconnect (ctx);
  close (output_fds[0]);
  return err;
}


struct export_hook
{
  /* The exported data.  */
  char *buffer;

  /* The length of the exported data buffer.  */
  unsigned int buffer_len;

  /* The size of the allocated exported data buffer.  */
  unsigned int buffer_size;
};

#define EXP_DATA_START 4096

static gpg_error_t
export_cert_cb (void *hook, char *line, size_t line_len)
{
  struct export_hook *exp = hook;

  if (exp->buffer_size - exp->buffer_len < line_len)
    {
      unsigned int new_buffer_size = exp->buffer_size ?
	(exp->buffer_size * 2) : EXP_DATA_START;
      char *new_buffer = realloc (exp->buffer, new_buffer_size);

      if (!new_buffer)
	return gpg_error_from_syserror ();

      exp->buffer = new_buffer;
      exp->buffer_size = new_buffer_size;
    }

  memcpy (exp->buffer + exp->buffer_len, line, line_len);
  exp->buffer_len += line_len;

  return 0;
}


static gpg_error_t
export_cert (char *fpr, struct cert *cert)
{
  gpg_error_t err;
  assuan_context_t ctx;
  const char *argv[] = { "gpgsm", "--server", NULL };
#define COMMANDLINELEN 80
  char cmd[COMMANDLINELEN];
  int output_fds[2];
  int child_fds[2];
  struct export_hook exp;

  if(pipe (output_fds) < 0)
    return gpg_error_from_syserror ();

  child_fds[0] = output_fds[1];
  child_fds[1] = -1;

  err = assuan_pipe_connect (&ctx, GPGSM_PATH, argv, child_fds);
  close (output_fds[1]);
  if (err)
    {
      close (output_fds[0]);
      return err;
    }

  exp.buffer = NULL;
  exp.buffer_len = 0;
  exp.buffer_size = 0;

  snprintf (cmd, sizeof (cmd), "EXPORT --data -- %s\n", cert->fpr);
  err = assuan_transact (ctx, cmd, export_cert_cb, &exp,
			 NULL, NULL, NULL, NULL);
  assuan_disconnect (ctx);
  close (output_fds[0]);

  if (!err)
    {
      cert->cert_der = exp.buffer;
      cert->cert_der_len = exp.buffer_len;
    }
  else if (gpg_err_code (err) == GPG_ERR_ASS_NO_OUTPUT)
    {
      /* For compatibility with GPGSM 2.0.0, we fall back to a work
	 around in that case.  */
      if (cert->cert_der)
	{
	  free (cert->cert_der);
	  cert->cert_der = NULL;
	}
      err = export_cert_compat (fpr, cert);
    }

  return err;
}


static gpg_error_t
search_certs_by_field (void *hook, struct cert *cert)
{
  struct search_ctx_by_field *ctx = hook;
  gpg_error_t err = 0;

  if ((ctx->field == SEARCH_BY_GRIP && !strcmp (ctx->pattern, cert->grip))
      || (ctx->field == SEARCH_BY_FPR && !strcmp (ctx->pattern, cert->fpr)))
    {
      if (strlen (cert->fpr) != 40)
	return gpg_error (GPG_ERR_GENERAL);

      err = export_cert (cert->fpr, cert);
      if (err)
	return err;

      err = (*ctx->search_cb) (ctx->search_cb_hook, cert);
    }

  return err;
}


/* Invoke SEARCH_CB for each certificate found using assuan connection
   CTX to GPGSM.  */
gpg_error_t
scute_gpgsm_search_certs_by_grip (const char *grip,
				  cert_search_cb_t search_cb,
				  void *search_cb_hook)
{
  gpg_error_t err;
  assuan_context_t ctx;
  const char *argv[] = { "gpgsm", "--server", NULL };
  struct search_ctx_by_field search;

  err = assuan_pipe_connect (&ctx, GPGSM_PATH, argv, NULL);
  if (err)
    return err;

  search.field = SEARCH_BY_GRIP;
  search.pattern = grip;
  search.search_cb = search_cb;
  search.search_cb_hook = search_cb_hook;

  err = scute_gpgsm_search_certs (ctx, &search_certs_by_field, &search);
  assuan_disconnect (ctx);
  return err;
}


/* Invoke SEARCH_CB for each certificate found using assuan connection
   CTX to GPGSM.  */
gpg_error_t
scute_gpgsm_search_certs_by_fpr (const char *fpr,
				 cert_search_cb_t search_cb,
				 void *search_cb_hook)
{
  gpg_error_t err;
  assuan_context_t ctx;
  const char *argv[] = { "gpgsm", "--server", NULL };
  struct search_ctx_by_field search;

  err = assuan_pipe_connect (&ctx, GPGSM_PATH, argv, NULL);
  if (err)
    return err;

  search.field = SEARCH_BY_FPR;
  search.pattern = fpr;
  search.search_cb = search_cb;
  search.search_cb_hook = search_cb_hook;

  err = scute_gpgsm_search_certs (ctx, &search_certs_by_field, &search);
  assuan_disconnect (ctx);
  return err;
}
