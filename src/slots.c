/* slots.c - Slot management.
 * Copyright (C) 2006, 2019 g10 Code GmbH
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

#include <assert.h>
#include <stdbool.h>
#include <string.h>
#include <stdlib.h>

#include "cryptoki.h"
#include "table.h"
#include "error-mapping.h"
#include "slots.h"
#include "agent.h"
#include "support.h"
#include "gpgsm.h"

#include "debug.h"

/* A session is just a slot identifier with a per-slot session
   identifier.  */
/* Must be power of two.  */
#define SLOT_MAX		(1 << 15)
#define SESSION_SLOT_MASK	(SLOT_MAX - 1)
#define SESSION_SLOT_SHIFT	16
#define SESSION_MAX		(1 << SESSION_SLOT_SHIFT)
#define SESSION_ID_MASK		(SESSION_MAX - 1)

/* Get slot ID from session.  */
#define SESSION_SLOT(session) \
  ((session >> SESSION_SLOT_SHIFT) & SESSION_SLOT_MASK)

/* Get session ID from session.  */
#define SESSION_ID(session)	(session & SESSION_ID_MASK)

/* Because the slot is already 1-based, we can make the session 0-based.  */
#define SESSION_BUILD_ID(slot, session) \
  (((slot & SESSION_SLOT_MASK) << SESSION_SLOT_SHIFT) \
   | (session & SESSION_ID_MASK))


/* We use one-based IDs.  */
#define OBJECT_ID_TO_IDX(id) (id - 1)
#define OBJECT_IDX_TO_ID(idx) (idx + 1)

struct object
{
  CK_ATTRIBUTE_PTR attributes;
  CK_ULONG attributes_count;
};


/* A mechanism.  */
struct mechanism
{
  CK_MECHANISM_TYPE type;
  CK_MECHANISM_INFO info;
};

/* We use one-based IDs.  */
#define MECHANISM_ID_TO_IDX(id) (id - 1)
#define MECHANISM_IDX_TO_ID(idx) (idx + 1)


/* The session state.  */
struct session
{
  /* True iff read-write session.  */
  bool rw;

  /* The list of objects for the current search.  */
  object_iterator_t *search_result;

  /* The length of the list of objects for the current search.  */
  int search_result_len;

  /* The signing key.  */
  CK_OBJECT_HANDLE signing_key;

  /* The signing mechanism type.  */
  CK_MECHANISM_TYPE signing_mechanism_type;

  /* The decryption key.  */
  CK_OBJECT_HANDLE decryption_key;
};


/* The slot status.  */
typedef enum
  {
    SLOT_STATUS_USED = 0,
    SLOT_STATUS_DEAD = 1
  } slot_status_t;

struct slot
{
  /* The slot status.  Starts out as 0 (pristine).  */
  slot_status_t status;

  /* The slot login status.  Starts out as 0 (public).  */
  slot_login_t login;

  /* True iff a token is present.  */
  bool token_present;

  /* The supported mechanisms.  */
  scute_table_t mechanisms;

  /* The sessions.  */
  scute_table_t sessions;

  /* The objects on the token.  */
  scute_table_t objects;

  /* The keygrip to the key in hex string.  */
  char grip[41];

  /* The serial number.  */
  char serialno[33];

  /* Private data.  */
  CK_MECHANISM_TYPE key_type;
};


/* The slot table.  */
static scute_table_t slot_table;


/* Deallocator for mechanisms.  */
static void
mechanism_dealloc (void *data)
{
  free (data);
}


/* Allocator for mechanisms.  The hook must be a pointer to a CK_FLAGS
   that should be a combination of CKF_SIGN and/or CKF_DECRYPT.  */
static gpg_error_t
mechanism_alloc (void **data_r, void *hook)
{
  struct mechanism *mechanism;
  struct slot *slot = hook;
  int oid;
  CK_MECHANISM_TYPE m = CKM_VENDOR_DEFINED;

  /* Register the signing mechanism.  */

  oid = scute_table_first (slot->objects);
  while (!scute_table_last (slot->objects, oid))
    {
      struct object *object;
      CK_ATTRIBUTE_PTR attr;
      CK_ULONG attr_count;
      CK_ULONG i;

      object = scute_table_data (slot->objects, oid);
      if (!object)
        {
          attr = NULL;
          break;
        }

      attr = object->attributes;
      attr_count = object->attributes_count;

      for (i = 0; i < attr_count; i++)
        if (attr[i].type == CKA_ALLOWED_MECHANISMS)
          break;

      if (i != attr_count)
        {
          if (attr[i].ulValueLen == sizeof (CK_MECHANISM_TYPE))
            memcpy (&m, attr[i].pValue, attr[i].ulValueLen);
          break;
        }

      oid = scute_table_next (slot->objects, oid);
    }

  if (m == CKM_VENDOR_DEFINED)
    return gpg_error (GPG_ERR_BAD_DATA);

  mechanism = calloc (1, sizeof (*mechanism));
  if (mechanism == NULL)
    return gpg_error_from_syserror ();

  slot->key_type = mechanism->type = m;
  if (m == CKM_RSA_PKCS)
    {
      mechanism->info.ulMinKeySize = 1024;
      mechanism->info.ulMaxKeySize = 4096;
    }
  else
    {
      mechanism->info.ulMinKeySize = 256;
      mechanism->info.ulMaxKeySize = 512;
    }
  mechanism->info.flags = CKF_HW | CKF_SIGN;

  *data_r = mechanism;

  return 0;
}


static void
object_dealloc (void *data)
{
  struct object *obj = data;

  while (0 < obj->attributes_count--)
    free (obj->attributes[obj->attributes_count].pValue);
  free (obj->attributes);
  free (obj);
}


/* Allocator for objects.  The hook is currently unused.  */
static gpg_error_t
object_alloc (void **data_r, void *hook)
{
  struct object *object;

  (void) hook;

  object = calloc (1, sizeof (*object));
  if (object == NULL)
    return gpg_error_from_syserror ();

  *data_r = object;

  return 0;
}


static void
session_dealloc (void *data)
{
  struct session *session = data;

  if (session->search_result)
    free (session->search_result);
  free (session);
}


/* Allocator for sessions.  The hook is currently unused.  */
static gpg_error_t
session_alloc (void **data_r, void *hook)
{
  struct session *session;

  (void) hook;

  session = calloc (1, sizeof (*session));
  if (session == NULL)
    return gpg_error_from_syserror ();

  *data_r = session;

  return 0;
}


/* Deallocator for slots.  */
static void
slot_dealloc (void *data)
{
  struct slot *slot = data;

  scute_table_destroy (slot->sessions);
  scute_table_destroy (slot->mechanisms);
  scute_table_destroy (slot->objects);

  free (slot);
}


/* Allocator for slots.  The hook does not indicate anything at this
   point.  */
static gpg_error_t
slot_alloc (void **data_r, void *hook)
{
  gpg_error_t err;
  struct slot *slot;

  (void) hook;

  slot = calloc (1, sizeof (*slot));
  if (slot == NULL)
    return gpg_error_from_syserror ();

  err = scute_table_create (&slot->mechanisms, mechanism_alloc,
			    mechanism_dealloc);
  if (err)
    goto slot_alloc_out;

  err = scute_table_create (&slot->sessions, session_alloc, session_dealloc);
  if (err)
    goto slot_alloc_out;

  err = scute_table_create (&slot->objects, object_alloc, object_dealloc);
  if (err)
    goto slot_alloc_out;

  slot->status = SLOT_STATUS_USED;
  slot->token_present = false;
  slot->login = SLOT_LOGIN_PUBLIC;

  *data_r = slot;

 slot_alloc_out:
  if (err)
    slot_dealloc (slot);

  return err;
}


static gpg_error_t add_object (void *hook, CK_ATTRIBUTE_PTR attrp,
			       CK_ULONG attr_countp);
static gpg_error_t slot_init (slot_iterator_t id);


/* Initialize the slot list.  */
CK_RV
scute_slots_initialize (void)
{
  gpg_error_t err;
  struct keyinfo *keyinfo = NULL;
  struct keyinfo *ki;

  err = scute_agent_serialno ();
  if (err)
    {
      if (gpg_err_code (err) != GPG_ERR_ENODEV)
	return scute_gpg_err_to_ck (err);
    }

  err = scute_agent_keyinfo_list (&keyinfo);
  if (err)
    return scute_gpg_err_to_ck (err);

  err = scute_table_create (&slot_table, slot_alloc, slot_dealloc);
  if (err)
    return err;

  for (ki = keyinfo; ki; ki = ki->next)
    {
      struct slot *slot;
      int slot_idx;

      err = scute_table_alloc (slot_table, &slot_idx, (void **)&slot, NULL);
      if (err)
	{
	  scute_slots_finalize ();
	  break;
	}
      else
        {
          memset (slot->serialno, 0, sizeof (slot->serialno));
          if (ki->serialno)
            {
              int len;

              len = strlen (ki->serialno);
              if (len >= 32)
                memcpy (slot->serialno, &ki->serialno[len-32], 32);
              else
                memcpy (slot->serialno, ki->serialno, len);
            }
          memcpy (slot->grip, ki->grip, 41);

	  err = scute_gpgsm_get_cert (slot->grip, add_object, slot);
          if (!err)
            err = slot_init (slot_idx);
	  if (err)
	    {
	      scute_table_dealloc (slot_table, &slot_idx);
	      err = 0;
	    }
        }
    }

  scute_agent_free_keyinfo (keyinfo);
  return scute_gpg_err_to_ck (err);
}


void
scute_slots_finalize (void)
{
  if (!slot_table)
    return;

  /* This recursively releases all slots and any objects associated
     with them.  */
  scute_table_destroy (slot_table);

  slot_table = NULL;
}


/* Reset the slot SLOT after the token has been removed.  */
static void
slot_reset (slot_iterator_t id)
{
  struct slot *slot = scute_table_data (slot_table, id);
  int oid;

  /* This also resets the login state.  */
  slot_close_all_sessions (id);

  oid = scute_table_first (slot->objects);
  while (!scute_table_last (slot->objects, oid))
    scute_table_dealloc (slot->objects, &oid);
  assert (scute_table_used (slot->objects) == 0);

  slot->token_present = false;
}


static gpg_error_t
add_object (void *hook, CK_ATTRIBUTE_PTR attrp,
	    CK_ULONG attr_countp)
{
  gpg_error_t err;
  struct slot *slot = hook;
  struct object *object;
  unsigned int oidx;
  void *objp;

  err = scute_table_alloc (slot->objects, &oidx, &objp, NULL);
  if (err)
    return err;

  object = objp;
  object->attributes = attrp;
  object->attributes_count = attr_countp;

  return 0;
}


/* Initialize the slot after a token has been inserted.  */
static gpg_error_t
slot_init (slot_iterator_t id)
{
  gpg_error_t err = 0;
  struct slot *slot = scute_table_data (slot_table, id);
  int idx;

  /* FIXME: Perform the rest of the initialization of the
     token.  */
  slot->token_present = true;

  err = scute_table_alloc (slot->mechanisms, &idx, NULL, slot);

  if (err)
    slot_reset (id);

  return err;
}

/* Begin iterating over the list of slots.  */
CK_RV
slots_iterate_first (slot_iterator_t *slot)
{
  *slot = scute_table_first (slot_table);

  return CKR_OK;
}


/* Continue iterating over the list of slots.  */
CK_RV
slots_iterate_next (slot_iterator_t *slot)
{
  *slot = scute_table_next (slot_table, *slot);

  return CKR_OK;
}


/* Return true iff the previous slot was the last one.  */
bool
slots_iterate_last (slot_iterator_t *slot)
{
  return scute_table_last (slot_table, *slot);
}


/* Acquire the slot for the slot ID ID.  */
CK_RV
slots_lookup (CK_SLOT_ID id, slot_iterator_t *id_r)
{
  struct slot *slot = scute_table_data (slot_table, id);

  if (slot == NULL)
    return CKR_SLOT_ID_INVALID;

  *id_r = id;

  return CKR_OK;
}



/* Return true iff a token is present in slot SLOT.  */
bool
slot_token_present (slot_iterator_t id)
{
  struct slot *slot = scute_table_data (slot_table, id);

  return slot->token_present;
}


/* Return the token label.  We use the dispserialno here too because
 * Firefox prints that value in the prompt ("Stored at:").  */
const char *
slot_token_label (slot_iterator_t id)
{
  struct slot *slot = scute_table_data (slot_table, id);
  return slot->serialno;
}


/* Get the manufacturer of the token.  */
const char *
slot_token_manufacturer (slot_iterator_t id)
{
  /* FIXME */
  (void)id;
  return "scdaemon";
}


/* Get the application used on the token.  */
const char *
slot_token_application (slot_iterator_t id)
{
  struct slot *slot = scute_table_data (slot_table, id);

  if (!slot)
    return "[ooops]";

  /* slots_update() makes sure this is correct.  */

  /* FIXME */
  return "gpg-agent";
}


/* Get the LSB of serial number of the token.  */
const char *
slot_token_serial (slot_iterator_t id)
{
  struct slot *slot = scute_table_data (slot_table, id);
  return &slot->serialno[16];
}


/* Get the manufacturer of the token.  */
void
slot_token_version (slot_iterator_t id, CK_BYTE *hw_major, CK_BYTE *hw_minor,
		    CK_BYTE *fw_major, CK_BYTE *fw_minor)
{
  /* FIXME */
  (void)id;
  *hw_major = 0;
  *hw_minor = 0;
  *fw_major = 0;
  *fw_minor = 0;
}


/* Get the maximum and minimum pin length.  */
void
slot_token_maxpinlen (slot_iterator_t id, CK_ULONG *max, CK_ULONG *min)
{
  /* FIXME */
  (void)id;

  *max = 31;

  /* FIXME: This is true at least for the user pin (CHV1 and CHV2).  */
  *min = 6;
}


/* Get the maximum and the actual pin count.  */
void
slot_token_pincount (slot_iterator_t id, int *max, int *len)
{
  (void)id;

  *max = 3;
  /* FIXME */
  *len = 1;
}


/* Return the ID of slot SLOT.  */
CK_SLOT_ID
slot_get_id (slot_iterator_t slot)
{
  return slot;
}

/* Return true if the token supports the GET CHALLENGE operation. */
bool
slot_token_has_rng (slot_iterator_t id)
{
  struct slot *slot = scute_table_data (slot_table, id);

  (void)slot;

  /* FIXME */
  return 1;
}


/* Mechanism management.  */

/* Begin iterating over the list of mechanisms.  */
CK_RV
mechanisms_iterate_first (slot_iterator_t id,
			  mechanism_iterator_t *mechanism)
{
  struct slot *slot = scute_table_data (slot_table, id);

  *mechanism = scute_table_first (slot->mechanisms);

  return CKR_OK;
}


/* Continue iterating over the list of mechanisms.  */
CK_RV
mechanisms_iterate_next (slot_iterator_t id, mechanism_iterator_t *mechanism)
{
  struct slot *slot = scute_table_data (slot_table, id);

  *mechanism = scute_table_next (slot->mechanisms, *mechanism);

  return CKR_OK;
}


/* Return true iff the previous slot was the last one.  */
bool
mechanisms_iterate_last (slot_iterator_t id, mechanism_iterator_t *mechanism)
{
  struct slot *slot = scute_table_data (slot_table, id);

  return scute_table_last (slot->mechanisms, *mechanism);
}


/* Acquire the mechanism TYPE for the slot id ID.  */
CK_RV
mechanisms_lookup (slot_iterator_t id,  mechanism_iterator_t *mid_r,
		   CK_MECHANISM_TYPE type)
{
  struct slot *slot = scute_table_data (slot_table, id);
  int mid = scute_table_first (slot->mechanisms);

  while (!scute_table_last (slot->mechanisms, mid))
    {
      struct mechanism *mechanism = scute_table_data (slot->mechanisms, mid);

      if (mechanism->type == type)
	{
	  *mid_r = mid;
	  return CKR_OK;
	}

      mid = scute_table_next (slot->mechanisms, mid);
    }

  return CKR_MECHANISM_INVALID;
}


/* Return the type of mechanism MID in slot ID.  */
CK_MECHANISM_TYPE
mechanism_get_type (slot_iterator_t id, mechanism_iterator_t mid)
{
  struct slot *slot = scute_table_data (slot_table, id);
  struct mechanism *mechanism = scute_table_data (slot->mechanisms, mid);

  return mechanism->type;
}


/* Return the info of mechanism MID.  */
CK_MECHANISM_INFO_PTR
mechanism_get_info (slot_iterator_t id, mechanism_iterator_t mid)
{
  struct slot *slot = scute_table_data (slot_table, id);
  struct mechanism *mechanism = scute_table_data (slot->mechanisms, mid);

  return &mechanism->info;
}


/* Session management.  */
static int active_sessions;

/* Create a new session.  */
CK_RV
slot_create_session (slot_iterator_t id, session_iterator_t *session,
		     bool rw)
{
  int err;
  struct slot *slot = scute_table_data (slot_table, id);
  unsigned int tsid;
  void *rawp;
  struct session *session_p;

  assert (slot);

  if (scute_table_used (slot->sessions) == SESSION_MAX)
    return CKR_SESSION_COUNT;

  if (slot->login == SLOT_LOGIN_SO && !rw)
    return CKR_SESSION_READ_WRITE_SO_EXISTS;

  err = scute_table_alloc (slot->sessions, &tsid, &rawp, NULL);
  if (err)
    return scute_sys_to_ck (err);

  session_p = rawp;
  session_p->rw = rw;
  session_p->search_result = NULL;
  session_p->search_result_len = 0;
  session_p->signing_key = CK_INVALID_HANDLE;
  session_p->decryption_key = CK_INVALID_HANDLE;

  *session = SESSION_BUILD_ID (id, tsid);
  active_sessions++;

  return CKR_OK;
}

/* Look up session.  */
CK_RV
slots_lookup_session (CK_SESSION_HANDLE sid, slot_iterator_t *id,
		      session_iterator_t *session_id)
{
  CK_RV err;
  unsigned int idx = SESSION_SLOT (sid);
  unsigned session_idx = SESSION_ID (sid);
  struct slot *slot;

  /* Verify the slot.  */
  err = slots_lookup (SESSION_SLOT (sid), id);
  if (err)
    return err;

  *session_id = session_idx;

  /* Verify the session.  */
  slot = scute_table_data (slot_table, idx);
  if (!scute_table_data (slot->sessions, session_idx))
    return CKR_SESSION_HANDLE_INVALID;

  return 0;
}

/* Close the session.  */
CK_RV
slot_close_session (slot_iterator_t id, session_iterator_t sid)
{
  struct slot *slot = scute_table_data (slot_table, id);

  scute_table_dealloc (slot->sessions, &sid);

  /* At last session closed, return to public sessions.  */
  if (!scute_table_used (slot->sessions))
    slot->login = SLOT_LOGIN_PUBLIC;

  active_sessions--;
  return CKR_OK;
}


/* Close all sessions.  */
CK_RV
slot_close_all_sessions (slot_iterator_t id)
{
  struct slot *slot = scute_table_data (slot_table, id);
  int sid = scute_table_first (slot->sessions);

  while (!scute_table_last (slot->sessions, sid))
    {
      slot_close_session (id, sid);

      sid = scute_table_next (slot->sessions, sid);
    }
  assert (scute_table_used (slot->sessions) == 0);

  return CKR_OK;
}



/* Get the RW flag from the session SID in slot ID.  */
bool
session_get_rw (slot_iterator_t id, session_iterator_t sid)
{
  struct slot *slot = scute_table_data (slot_table, id);
  struct session *session = scute_table_data (slot->sessions, sid);

  return session->rw;
}


/* Get the login state from the slot ID.  */
slot_login_t
slot_get_login_status (slot_iterator_t id)
{
  struct slot *slot = scute_table_data (slot_table, id);

  return slot->login;
}


/* Object management.  */

/* Begin iterating over the list of objects.  */
CK_RV
objects_iterate_first (slot_iterator_t id, object_iterator_t *object)
{
  struct slot *slot = scute_table_data (slot_table, id);

  *object = scute_table_first (slot->objects);

  return CKR_OK;
}


/* Continue iterating over the list of objects.  */
CK_RV
objects_iterate_next (slot_iterator_t id, object_iterator_t *object)
{
  struct slot *slot = scute_table_data (slot_table, id);

  *object = scute_table_next (slot->objects, *object);

  return CKR_OK;
}


/* Return true iff the previous slot was the last one.  */
bool
objects_iterate_last (slot_iterator_t id, object_iterator_t *object)
{
  struct slot *slot = scute_table_data (slot_table, id);

  return scute_table_last (slot->objects, *object);
}


/* Return the max. number of objects in the slot.  May overcount
   somewhat.  */
CK_RV
slot_get_object_count (slot_iterator_t id, int *nr)
{
  struct slot *slot = scute_table_data (slot_table, id);

  *nr = scute_table_used (slot->objects);

  return CKR_OK;
}

/* Get the object information for object OBJECT_ID in slot ID.  */
CK_RV
slot_get_object (slot_iterator_t id, object_iterator_t oid,
		 CK_ATTRIBUTE_PTR *obj, CK_ULONG *obj_count)
{
  struct slot *slot = scute_table_data (slot_table, id);
  struct object *object = scute_table_data (slot->objects, oid);

  if (!object)
    return CKR_OBJECT_HANDLE_INVALID;

  *obj = object->attributes;
  *obj_count = object->attributes_count;

  return 0;
}


/* Set the result of a search for session SID in slot ID to
   SEARCH_RESULT and SEARCH_RESULT_LEN.  */
CK_RV
session_set_search_result (slot_iterator_t id, session_iterator_t sid,
			   object_iterator_t *search_result,
			   int search_result_len)
{
  struct slot *slot = scute_table_data (slot_table, id);
  struct session *session = scute_table_data (slot->sessions, sid);

  if (session->search_result && session->search_result != search_result)
    free (session->search_result);

  session->search_result = search_result;
  session->search_result_len = search_result_len;

  return 0;
}


/* Get the stored search result for the session SID in slot ID.  */
CK_RV
session_get_search_result (slot_iterator_t id, session_iterator_t sid,
			   object_iterator_t **search_result,
			   int *search_result_len)
{
  struct slot *slot = scute_table_data (slot_table, id);
  struct session *session = scute_table_data (slot->sessions, sid);

  assert (search_result);
  assert (search_result_len);

  *search_result = session->search_result;
  *search_result_len = session->search_result_len;

  return 0;
}


/* Set the signing key for session SID in slot ID to KEY.  This is the
 * core of C_SignInit.  */
CK_RV
session_set_signing_key (slot_iterator_t id, session_iterator_t sid,
			 object_iterator_t key,
                         CK_MECHANISM_TYPE mechanism_type)
{
  struct slot *slot = scute_table_data (slot_table, id);
  struct session *session = scute_table_data (slot->sessions, sid);
  CK_RV err;
  CK_ATTRIBUTE_PTR attr;
  CK_ULONG attr_count;
  CK_OBJECT_CLASS key_class = CKO_PRIVATE_KEY;

  err = slot_get_object (id, key, &attr, &attr_count);
  if (err)
    return err;

  while (attr_count-- > 0)
    if (attr->type == CKA_CLASS)
      break;

  if (attr_count == (CK_ULONG) -1)
    return CKR_KEY_HANDLE_INVALID;

  if (attr->ulValueLen != sizeof (key_class)
      || memcmp (attr->pValue, &key_class, sizeof (key_class)))
    return CKR_KEY_HANDLE_INVALID;

  /* It's the private key object.  */
  session->signing_key = key;
  session->signing_mechanism_type = mechanism_type;

  return 0;
}


/* The core of C_Sign - see there for a description.  */
CK_RV
session_sign (slot_iterator_t id, session_iterator_t sid,
	      CK_BYTE_PTR pData, CK_ULONG ulDataLen,
	      CK_BYTE_PTR pSignature, CK_ULONG_PTR pulSignatureLen)
{
  struct slot *slot = scute_table_data (slot_table, id);
  struct session *session = scute_table_data (slot->sessions, sid);
  int rc;
  gpg_error_t err;
  CK_ATTRIBUTE_PTR attr;
  CK_ULONG attr_count;
  CK_OBJECT_CLASS key_class = CKO_PRIVATE_KEY;
  unsigned int sig_len;
  CK_BYTE key_id[100];
  int i;

  if (!session->signing_key)
    return CKR_OPERATION_NOT_INITIALIZED;

  rc = slot_get_object (id, session->signing_key, &attr, &attr_count);
  if (rc)
    goto leave;
  if (attr_count == (CK_ULONG) -1)
    {
      rc = CKR_KEY_HANDLE_INVALID;
      goto leave;
    }
  if (attr->ulValueLen != sizeof (key_class)
      || memcmp (attr->pValue, &key_class, sizeof (key_class)))
    {
      rc = CKR_KEY_HANDLE_INVALID;
      goto leave;
    }

  /* Find the CKA_ID */
  for (i = 0; i < attr_count; i++)
    if (attr[i].type == CKA_ID)
      break;
  if (i == attr_count)
    {
      rc = CKR_GENERAL_ERROR;
      goto leave;
    }

  if (attr[i].ulValueLen >= sizeof key_id - 1)
    {
      rc = CKR_GENERAL_ERROR;
      goto leave;
    }
  strncpy (key_id, attr[i].pValue, attr[i].ulValueLen);
  key_id[attr[i].ulValueLen] = 0;
  DEBUG (DBG_INFO, "Found CKA_ID '%s'", key_id);

  /* It asks the length of signature.  */
  if (pSignature == NULL)
    {
      switch (slot->key_type)
        {
        case CKM_ECDSA_SHA256:
          *pulSignatureLen = 32 * 2;
          break;
        case CKM_ECDSA_SHA384:
          *pulSignatureLen = 48 * 2;
          break;
        case CKM_ECDSA_SHA512:
          *pulSignatureLen = 64 * 2;
          break;
        case CKM_RSA_PKCS:
        default:
          return CKR_GENERAL_ERROR;
        }
      return CKR_OK;
    }

  sig_len = *pulSignatureLen;
  err = scute_agent_sign (key_id, session->signing_mechanism_type,
                          pData, ulDataLen, pSignature, &sig_len);
  /* Take care of error codes which are not mapped by default.  */
  if (gpg_err_code (err) == GPG_ERR_INV_LENGTH)
    rc = CKR_BUFFER_TOO_SMALL;
  else if (gpg_err_code (err) == GPG_ERR_INV_ARG)
    rc = CKR_ARGUMENTS_BAD;
  else
    rc = scute_gpg_err_to_ck (err);
  /* Return the length.  */
  if (rc == CKR_OK || rc == CKR_BUFFER_TOO_SMALL)
    *pulSignatureLen = sig_len;

 leave:
  if (rc != CKR_OK && rc != CKR_BUFFER_TOO_SMALL)
    session->signing_key = 0;
  return rc;
}


/* Prepare a decryption for slot with SLOTID and the session SID using
 * MECHANISM and KEY.  This is the core of C_DecryptInit.  */
CK_RV
session_init_decrypt (slot_iterator_t slotid, session_iterator_t sid,
                      CK_MECHANISM *mechanism, object_iterator_t key)
{
  struct slot *slot;
  struct session *session;
  CK_RV rv;
  CK_ATTRIBUTE_PTR attr;
  CK_ULONG attr_count;
  CK_OBJECT_CLASS key_class = CKO_PRIVATE_KEY;

  if (mechanism->mechanism != CKM_RSA_PKCS)
    return CKR_MECHANISM_INVALID;

  slot = scute_table_data (slot_table, slotid);
  session = scute_table_data (slot->sessions, sid);

  rv = slot_get_object (slotid, key, &attr, &attr_count);
  if (rv)
    return rv;

  /* FIXME: What kind of strange loop is this?  */
  while (attr_count-- > 0)
    if (attr->type == CKA_CLASS)
      break;

  if (attr_count == (CK_ULONG) -1)
    return CKR_KEY_HANDLE_INVALID;

  if (attr->ulValueLen != sizeof (key_class)
      || memcmp (attr->pValue, &key_class, sizeof (key_class)))
    return CKR_KEY_HANDLE_INVALID;

  /* It's the private RSA key object.  */
  session->decryption_key = key;

  return 0;
}


/* The core of C_Decrypt - see there for a description.  */
CK_RV
session_decrypt (slot_iterator_t slotid, session_iterator_t sid,
                 CK_BYTE *encdata, CK_ULONG encdatalen,
                 CK_BYTE *r_plaindata, CK_ULONG *r_plaindatalen)
{
  CK_RV rv;
  gpg_error_t err;
  struct slot *slot;
  struct session *session;
  CK_ATTRIBUTE_PTR attr;
  CK_ULONG attr_count;
  CK_OBJECT_CLASS key_class = CKO_PRIVATE_KEY;
  CK_BYTE key_id[100];
  int i;
  unsigned int plaindatalen;

  slot = scute_table_data (slot_table, slotid);
  session = scute_table_data (slot->sessions, sid);

  if (!session->decryption_key)
    return CKR_OPERATION_NOT_INITIALIZED;

  rv = slot_get_object (slotid, session->decryption_key, &attr, &attr_count);
  if (rv)
    goto leave;
  if (attr_count == (CK_ULONG) -1)
    {
      rv = CKR_KEY_HANDLE_INVALID;
      goto leave;
    }
  if (attr->ulValueLen != sizeof (key_class)
      || memcmp (attr->pValue, &key_class, sizeof (key_class)))
    {
      rv = CKR_KEY_HANDLE_INVALID;
      goto leave;
    }

  /* Find the CKA_ID */
  for (i = 0; i < attr_count; i++)
    if (attr[i].type == CKA_ID)
      break;
  if (i == attr_count)
    {
      rv = CKR_GENERAL_ERROR;
      goto leave;
    }

  if (attr[i].ulValueLen >= sizeof key_id - 1)
    {
      rv = CKR_GENERAL_ERROR;
      goto leave;
    }
  strncpy (key_id, attr[i].pValue, attr[i].ulValueLen);
  key_id[attr[i].ulValueLen] = 0;
  DEBUG (DBG_INFO, "Found CKA_ID '%s'", key_id);

  plaindatalen = *r_plaindatalen;
  err = scute_agent_decrypt (key_id, encdata, encdatalen,
                             r_plaindata, &plaindatalen);
  DEBUG (DBG_INFO, "agent returned gpg error %d datalen=%u", err, plaindatalen);
  /* Take care of error codes which are not mapped by default.  */
  if (gpg_err_code (err) == GPG_ERR_INV_LENGTH)
    rv = CKR_BUFFER_TOO_SMALL;
  else if (gpg_err_code (err) == GPG_ERR_INV_ARG)
    rv = CKR_ARGUMENTS_BAD;
  else
    rv = scute_gpg_err_to_ck (err);
  /* Return the length.  */
  if (rv == CKR_OK || rv == CKR_BUFFER_TOO_SMALL)
    *r_plaindatalen = plaindatalen;

 leave:
  if (rv != CKR_BUFFER_TOO_SMALL)
    session->decryption_key = 0;
  DEBUG (DBG_INFO, "leaving decrypt with rv=%lu", rv);
  return rv;
}

CK_RV
scute_slots_rescan_if_no_sessions (void)
{
  if (active_sessions == 0)
    {
      scute_slots_finalize ();
      scute_slots_initialize ();
    }
  return CKR_OK;
}
