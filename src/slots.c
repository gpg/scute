/* slots.c - Slot management.
   Copyright (C) 2006 g10 Code GmbH

   This file is part of Scute[1].

   [1] Derived from the RSA Security Inc. PKCS #11 Cryptographic Token
   Interface (Cryptoki).
 
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

#include <assert.h>
#include <stdbool.h>
#include <string.h>

#include "cryptoki.h"
#include "table.h"
#include "error-mapping.h"
#include "slots.h"
#include "agent.h"
#include "support.h"

#include "debug.h"

#define MIN(a,b) ((a) < (b) ? (a) : (b))


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
  /* Every table entry must start with a void pointer, but we don't
     use it here.  */
  void *dummy;

  CK_ATTRIBUTE_PTR attributes;
  CK_ULONG attributes_count;
};


/* The dummy pointer we use for table entries.  */
#define DUMMY_PTR ((void *) 0xdeadbeef)

/* A mechanism.  */
struct mechanism
{
  /* Every table entry must start with a void pointer, but we don't
     use it here.  */
  void *dummy;

  CK_MECHANISM_TYPE type;
  CK_MECHANISM_INFO info;
};

/* We use one-based IDs.  */
#define MECHANISM_ID_TO_IDX(id) (id - 1)
#define MECHANISM_IDX_TO_ID(idx) (idx + 1)


/* The session state.  */
struct session
{
  /* Every table entry must start with a void pointer, but we don't
     use it here.  */
  void *dummy;

  /* True iff read-write session.  */
  bool rw;

  /* The list of objects for the current search.  */
  object_iterator_t *search_result;

  /* The length of the list of objects for the current search.  */
  int search_result_len;

  /* The signing key.  */
  CK_OBJECT_HANDLE signing_key;
};

/* The slot status.  */
typedef enum
  {
    SLOT_STATUS_USED = 0,
    SLOT_STATUS_DEAD = 1
  } slot_status_t;

struct slot
{
  /* Every table entry must start with a void pointer, but we don't
     use it here.  */
  void *dummy;

  /* The slot status.  Starts out as 0 (pristine).  */
  slot_status_t status;

  /* The slot login status.  Starts out as 0 (public).  */
  slot_login_t login;

  /* True iff a token is present.  */
  bool token_present;

  /* The supported mechanisms.  */
  struct hurd_table mechanisms;

  /* The sessions.  */
  struct hurd_table sessions;

  /* The objects on the token.  */
  struct hurd_table objects;

  /* The info about the current token.  */
  struct agent_card_info_s info;
};


/* The slot table.  */
static struct hurd_table slots = HURD_TABLE_INITIALIZER (sizeof (struct slot));

/* We use one-based IDs.  */
#define SLOT_ID_TO_IDX(id) (id - 1)
#define SLOT_IDX_TO_ID(idx) (idx + 1)


/* Initialize the slot list.  */
CK_RV
scute_slots_initialize (void)
{
  /* FIXME: Implement this properly.  Ensure that we stay within SLOT_MAX.
     Use a second slot for email?  */
  error_t err;
  unsigned int idx;
  struct mechanism mechanism;
  struct slot slot;

  slot.dummy = DUMMY_PTR;
  slot.status = SLOT_STATUS_USED;

  slot.token_present = false;
  slot.login = SLOT_LOGIN_PUBLIC;

  hurd_table_init (&slot.sessions, sizeof (struct session));
  hurd_table_init (&slot.mechanisms, sizeof (struct mechanism));

  mechanism.dummy = DUMMY_PTR;
  mechanism.type = CKM_RSA_PKCS;
  mechanism.info.ulMinKeySize = 1024;
  mechanism.info.ulMaxKeySize = 1024;
  mechanism.info.flags = CKF_HW | CKF_SIGN;

  err = hurd_table_enter (&slot.mechanisms, &mechanism, &idx);
  if (err)
    {
      hurd_table_destroy (&slot.mechanisms);
      hurd_table_destroy (&slot.sessions);
      return scute_sys_to_ck (err);
    }

  hurd_table_init (&slot.objects, sizeof (struct object));

  err = hurd_table_enter (&slots, &slot, &idx);
  if (err)
    {
      hurd_table_destroy (&slot.objects);
      hurd_table_destroy (&slot.mechanisms);
      hurd_table_destroy (&slot.sessions);
      return scute_sys_to_ck (err);
    }

  return CKR_OK;
}


void scute_slots_finalize (void)
{
  /* FIXME FIXME FIXME: Implement this.  */
}


static void
object_free (struct object *objp)
{
  while (0 < objp->attributes_count--)
    free (objp->attributes[objp->attributes_count].pValue);
  free (objp->attributes);
}


/* Update the slot SLOT.  */
CK_RV
slots_update_slot (slot_iterator_t id)
{
  unsigned int idx = SLOT_ID_TO_IDX (id);
  struct slot *slot = hurd_table_lookup (&slots, idx);
  gpg_error_t err;

  assert (slot);

  if (slot->token_present)
    {
      err = scute_agent_check_status ();
      if (gpg_err_code (err) == GPG_ERR_CARD_REMOVED)
	{
	  /* FIXME: Reset the whole thing.  */
      
	  /* FIXME: Code duplication with close_all_sessions.  */
	  HURD_TABLE_ITERATE (&slot->sessions, sid)
	    {
	      slot_close_session (id, sid);
	    }

	  HURD_TABLE_ITERATE (&slot->objects, oidx)
	    {
	      object_free (HURD_TABLE_LOOKUP (&slot->objects, oidx));
	      hurd_table_remove (&slot->objects, oidx);
	    }
	  
	  scute_agent_release_card_info (&slot->info);
	  slot->token_present = false;
	}
      else if (err)
	return scute_gpg_err_to_ck (err);
      else
	return 0;
    }

  /* At this point, the card was or is removed, and we need to reopen
     the session, if possible.  */
  err = scute_agent_learn (&slot->info);

  /* First check if this is really an OpenPGP card.  FIXME: Should
     probably report the error in a better way.  */
  if (!err && (!slot->info.serialno
	       || strncmp (slot->info.serialno, "D27600012401", 12)
	       || strlen (slot->info.serialno) != 32))
    {
      DEBUG ("Not an OpenPGP card");
      err = gpg_error (GPG_ERR_CARD_NOT_PRESENT);
    }

  if (gpg_err_code (err) == GPG_ERR_CARD_REMOVED
      || gpg_err_code (err) == GPG_ERR_CARD_NOT_PRESENT)
    /* Nothing to do.  */
    ;
  else if (err)
    return scute_gpg_err_to_ck (err);
  else
    {
      struct object objects[2];
      unsigned int oidxs[2];

      objects[0].dummy = DUMMY_PTR;
      objects[1].dummy = DUMMY_PTR;

      /* FIXME: Should be grip3.  */
      err = scute_gpgsm_get_cert (slot->info.grip3,
				  &objects[0].attributes,
				  &objects[0].attributes_count,
				  &objects[1].attributes,
				  &objects[1].attributes_count);
      if (err)
	return scute_gpg_err_to_ck (err);

      err = hurd_table_enter (&slot->objects, &objects[0], &oidxs[0]);
      if (err)
	{
	  object_free (&objects[0]);
	  object_free (&objects[1]);
	  return err;
	}

      err = hurd_table_enter (&slot->objects, &objects[1], &oidxs[1]);
      if (err)
	{
	  hurd_table_remove (&slot->objects, oidxs[0]);
	  object_free (&objects[0]);
	  object_free (&objects[1]);
	  return err;
	}

      /* FIXME: Perform the initialization of the token.  */
      slot->token_present = true;
    }

  return CKR_OK;
}


/* Update the slot list by finding new devices.  Please note that
   Mozilla NSS currently assumes that the slot list never shrinks (see
   TODO file for a discussion).  This is the only function allowed to
   manipulate the slot list.  */
CK_RV
slots_update (void)
{
  HURD_TABLE_ITERATE (&slots, idx)
    {
      CK_RV err;

      err = slots_update_slot (SLOT_IDX_TO_ID (idx));
      if (err)
	return err;
    }

  return CKR_OK;
}


/* Begin iterating over the list of slots.  If succeeds, will be
   followed up by a slot_iterate_end.  */
CK_RV
slots_iterate_begin (slot_iterator_t *slot)
{
  unsigned int idx = 0;

  /* FIXME: Protect against modification of slot status from here
     until slots_iterate_end.  */
  while (idx < HURD_TABLE_EXTENT (&slots) && !hurd_table_lookup (&slots, idx))
    idx++;

  *slot = SLOT_IDX_TO_ID (idx);

  return CKR_OK;
}


/* Continue iterating over the list of slots.  */
CK_RV
slots_iterate_next (slot_iterator_t *slot)
{
  unsigned int idx = SLOT_ID_TO_IDX (*slot);

  do
    idx++;
  while (idx < HURD_TABLE_EXTENT (&slots) && !hurd_table_lookup (&slots, idx));

  *slot = SLOT_IDX_TO_ID (idx);

  return CKR_OK;
}


/* Stop iterating over the list of slots.  */
CK_RV
slots_iterate_end (slot_iterator_t *slot)
{
  /* FIXME: Nothing to do at this point.  Release lock held by
     slots_iterate_begin.  */
  return 0;
}


/* Return true iff the previous slot was the last one.  */
bool
slots_iterate_last (slot_iterator_t *slot)
{
  unsigned int idx = SLOT_ID_TO_IDX (*slot);

  return idx >= HURD_TABLE_EXTENT (&slots);
}


/* Acquire the slot for the slot ID ID.  */
CK_RV
slots_lookup (CK_SLOT_ID id, slot_iterator_t *slot)
{
  unsigned int idx = SLOT_ID_TO_IDX (id);

  if (idx >= HURD_TABLE_EXTENT (&slots))
    return CKR_SLOT_ID_INVALID;
  if (!hurd_table_lookup (&slots, idx))
    return CKR_DEVICE_ERROR;

  *slot = SLOT_IDX_TO_ID (idx);

  return CKR_OK;
}



/* Return true iff a token is present in slot SLOT.  */
bool
slot_token_present (slot_iterator_t id)
{
  unsigned int idx = SLOT_ID_TO_IDX (id);
  struct slot *slot = hurd_table_lookup (&slots, idx);

  assert (slot);

  return slot->token_present;
}


/* Return the token label.  */
char *
slot_token_label (slot_iterator_t id)
{
  unsigned int idx = SLOT_ID_TO_IDX (id);
  struct slot *slot = hurd_table_lookup (&slots, idx);

  assert (slot);

  /* slots_update() makes sure this is valid.  */
  return slot->info.serialno;
}


/* Get the manufacturer of the token.  */
char *
slot_token_manufacturer (slot_iterator_t id)
{
  unsigned int idx = SLOT_ID_TO_IDX (id);
  struct slot *slot = hurd_table_lookup (&slots, idx);
  unsigned int uval;

  assert (slot);

  /* slots_update() makes sure this is valid.  */
  uval = xtoi_2 (slot->info.serialno + 16) * 256
    + xtoi_2 (slot->info.serialno + 18);

  /* Note:  Make sure that there is no colon or linefeed in the string. */
  switch (uval)
    {
    case 0:
    case 0xffff: return "test card";
    case 0x0001: return "PPC Card Systems";
    case 0x0002: return "Prism";
    case 0x0003: return "OpenFortress";
    default: return "unknown";
    }
}


/* Get the manufacturer of the token.  */
char *
slot_token_application (slot_iterator_t id)
{
  unsigned int idx = SLOT_ID_TO_IDX (id);
  struct slot *slot = hurd_table_lookup (&slots, idx);

  assert (slot);

  /* slots_update() makes sure this is correct.  */
  return "OpenPGP";
}


/* Get the serial number of the token.  Must not write more than 16
   bytes starting from DST.  */
int
slot_token_serial (slot_iterator_t id, char *dst)
{
  unsigned int idx = SLOT_ID_TO_IDX (id);
  struct slot *slot = hurd_table_lookup (&slots, idx);
  int i;

  assert (slot);

  /* slots_update() makes sure serialno is valid.  */
  for (i = 0; i < 8; i++)
    dst[i] = slot->info.serialno[20 + i];

  return 8;
}


/* Get the manufacturer of the token.  */
void
slot_token_version (slot_iterator_t id, CK_BYTE *hw_major, CK_BYTE *hw_minor,
		    CK_BYTE *fw_major, CK_BYTE *fw_minor)
{
  unsigned int idx = SLOT_ID_TO_IDX (id);
  struct slot *slot = hurd_table_lookup (&slots, idx);

  assert (slot);

  /* slots_update() makes sure serialno is valid.  */
  *hw_major = xtoi_2 (slot->info.serialno + 12);
  *hw_minor = xtoi_2 (slot->info.serialno + 14);
  *fw_major = 0;
  *fw_minor = 0;
}


/* Get the maximum and minimum pin length.  */
void
slot_token_maxpinlen (slot_iterator_t id, CK_ULONG *max, CK_ULONG *min)
{
  unsigned int idx = SLOT_ID_TO_IDX (id);
  struct slot *slot = hurd_table_lookup (&slots, idx);

  assert (slot);

  *max = MIN (slot->info.chvmaxlen[0], slot->info.chvmaxlen[1]);

  /* FIXME: This is true at least for the user pin (CHV1 and CHV2).  */
  *min = 6;
}


/* Get the maximum and the actual pin count.  */
void
slot_token_pincount (slot_iterator_t id, int *max, int *len)
{
  unsigned int idx = SLOT_ID_TO_IDX (id);
  struct slot *slot = hurd_table_lookup (&slots, idx);

  assert (slot);

  *max = 3;
  *len = MIN (slot->info.chvretry[0], slot->info.chvretry[1]);
}


/* Return the ID of slot SLOT.  */
CK_SLOT_ID
slot_get_id (slot_iterator_t id)
{
  unsigned int idx = SLOT_ID_TO_IDX (id);
  struct slot *slot = hurd_table_lookup (&slots, idx);

  assert (slot);

  return id;
}


/* Mechanism management.  */

/* Begin iterating over the list of mechanisms.  If succeeds, will be
   followed up by a slot_iterate_end.  */
CK_RV
mechanisms_iterate_begin (slot_iterator_t id,
			  mechanism_iterator_t *mechanism)
{
  unsigned int idx = SLOT_ID_TO_IDX (id);
  struct slot *slot = hurd_table_lookup (&slots, idx);
  unsigned int midx = 0;

  assert (slot);

  while (midx < HURD_TABLE_EXTENT (&slot->mechanisms)
	 && !hurd_table_lookup (&slot->mechanisms, midx))
    midx++;

  *mechanism = MECHANISM_IDX_TO_ID (midx);

  return CKR_OK;
}


/* Continue iterating over the list of mechanisms.  */
CK_RV
mechanisms_iterate_next (slot_iterator_t id, mechanism_iterator_t *mechanism)
{
  unsigned int idx = SLOT_ID_TO_IDX (id);
  struct slot *slot = hurd_table_lookup (&slots, idx);
  unsigned int midx = MECHANISM_ID_TO_IDX (*mechanism);

  assert (slot);

  do
    midx++;
  while (midx < HURD_TABLE_EXTENT (&slot->mechanisms)
	 && !hurd_table_lookup (&slot->mechanisms, midx));
  
  *mechanism = MECHANISM_IDX_TO_ID (midx);

  return CKR_OK;
}


/* Stop iterating over the list of mechanisms.  */
CK_RV
mechanisms_iterate_end (slot_iterator_t id, mechanism_iterator_t *mechanism)
{
  /* Nothing to do.  */

  return 0;
}


/* Return true iff the previous slot was the last one.  */
bool
mechanisms_iterate_last (slot_iterator_t id, mechanism_iterator_t *mechanism)
{
  unsigned int idx = SLOT_ID_TO_IDX (id);
  struct slot *slot = hurd_table_lookup (&slots, idx);
  unsigned int midx = MECHANISM_ID_TO_IDX (*mechanism);

  assert (slot);

  return midx >= HURD_TABLE_EXTENT (&slot->mechanisms);
}


/* Acquire the mechanism TYPE for the slot id ID.  */
CK_RV
mechanisms_lookup (slot_iterator_t id,  mechanism_iterator_t *mid,
		   CK_MECHANISM_TYPE type)
{
  unsigned int idx = SLOT_ID_TO_IDX (id);
  struct slot *slot = hurd_table_lookup (&slots, idx);

  assert (slot);

  HURD_TABLE_ITERATE (&slot->mechanisms, midx)
    {
      struct mechanism *mechanism;

      mechanism = (struct mechanism *)
	HURD_TABLE_LOOKUP (&slot->mechanisms, midx);
      if (mechanism->type == type)
	{
	  *mid = MECHANISM_IDX_TO_ID (midx);
	  return CKR_OK;
	}
    }

  return CKR_MECHANISM_INVALID;
}


/* Return the type of mechanism MID in slot ID.  */
CK_MECHANISM_TYPE
mechanism_get_type (slot_iterator_t id, mechanism_iterator_t mid)
{
  unsigned int idx = SLOT_ID_TO_IDX (id);
  struct slot *slot = hurd_table_lookup (&slots, idx);
  unsigned int midx = MECHANISM_ID_TO_IDX (mid);
  struct mechanism *mechanism;

  assert (slot);
  mechanism = hurd_table_lookup (&slot->mechanisms, midx);
  assert (mechanism);

  return mechanism->type;
}


/* Return the info of mechanism MID.  */
CK_MECHANISM_INFO_PTR
mechanism_get_info (slot_iterator_t id, mechanism_iterator_t mid)
{
  unsigned int idx = SLOT_ID_TO_IDX (id);
  struct slot *slot = hurd_table_lookup (&slots, idx);
  unsigned int midx = MECHANISM_ID_TO_IDX (mid);
  struct mechanism *mechanism;

  assert (slot);
  mechanism = hurd_table_lookup (&slot->mechanisms, midx);
  assert (mechanism);

  return &mechanism->info;
}


/* Session management.  */

/* Create a new session.  */
CK_RV
slot_create_session (slot_iterator_t id, session_iterator_t *session,
		     bool rw)
{
  error_t err;
  unsigned int idx = SLOT_ID_TO_IDX (id);
  struct slot *slot = hurd_table_lookup (&slots, idx);
  unsigned int tsid;
  struct session session_obj;

  assert (slot);

  if (HURD_TABLE_USED (&slot->sessions) == SESSION_MAX)
    return CKR_SESSION_COUNT;

  if (slot->login == SLOT_LOGIN_SO && !rw)
    return CKR_SESSION_READ_WRITE_SO_EXISTS;

  session_obj.dummy = DUMMY_PTR;
  session_obj.rw = rw;
  session_obj.search_result = NULL;
  session_obj.search_result_len = 0;

  err = hurd_table_enter (&slot->sessions, &session_obj, &tsid);
  if (err)
    return scute_sys_to_ck (err);

  *session = SESSION_BUILD_ID (id, tsid);

  return CKR_OK;
}

/* Look up session.  */
CK_RV
slots_lookup_session (session_iterator_t sid, slot_iterator_t *id)
{
  CK_RV err;
  unsigned int idx = SLOT_ID_TO_IDX (SESSION_SLOT (sid));
  unsigned session_idx = SESSION_ID (sid);
  struct slot *slot;

  /* Verify the slot.  */
  err = slots_lookup (SESSION_SLOT (sid), id);
  if (err)
    return err;

  /* Verify the session.  */
  slot = hurd_table_lookup (&slots, idx);
  if (session_idx >= HURD_TABLE_EXTENT (&slot->sessions)
      || !hurd_table_lookup (&slot->sessions, session_idx))
    return CKR_SESSION_HANDLE_INVALID;

  return 0;
}

/* Close the session.  */
CK_RV
slot_close_session (slot_iterator_t id, session_iterator_t sid)
{
  unsigned int idx = SLOT_ID_TO_IDX (id);
  struct slot *slot = hurd_table_lookup (&slots, idx);
  unsigned session_idx = SESSION_ID (sid);
  struct session *session;

  assert (slot);

  session = hurd_table_lookup (&slot->sessions, session_idx);
  assert (session);

  if (session->search_result)
    free (session->search_result);

  hurd_table_remove (&slot->sessions, session_idx);

  /* At last session closed, return to public sessions.  */
  if (! HURD_TABLE_USED (&slot->sessions))
    slot->login = SLOT_LOGIN_PUBLIC;

  return CKR_OK;
}


/* Close all sessions.  */
CK_RV
slot_close_all_sessions (slot_iterator_t id)
{
  unsigned int idx = SLOT_ID_TO_IDX (id);
  struct slot *slot = hurd_table_lookup (&slots, idx);

  assert (slot);

  HURD_TABLE_ITERATE (&slot->sessions, sid)
    slot_close_session (id, sid);

  assert (HURD_TABLE_USED (&slot->sessions) == 0);

  return CKR_OK;
}



/* Get the RW flag from the session SID in slot ID.  */
bool
session_get_rw (slot_iterator_t id, session_iterator_t sid)
{
  unsigned int idx = SLOT_ID_TO_IDX (id);
  struct slot *slot = hurd_table_lookup (&slots, idx);
  unsigned session_idx = SESSION_ID (sid);
  struct session *session;

  assert (slot);

  session = hurd_table_lookup (&slot->sessions, session_idx);
  assert (session);

  return session->rw;
}


/* Get the login state from the slot ID.  */
slot_login_t
slot_get_status (slot_iterator_t id)
{
  unsigned int idx = SLOT_ID_TO_IDX (id);
  struct slot *slot = hurd_table_lookup (&slots, idx);

  assert (slot);

  return slot->status;
}


/* Object management.  */

/* Begin iterating over the list of objects.  If succeeds, will be
   followed up by a slot_iterate_end.  */
CK_RV
objects_iterate_begin (slot_iterator_t id,
			  object_iterator_t *object)
{
  unsigned int idx = SLOT_ID_TO_IDX (id);
  struct slot *slot = hurd_table_lookup (&slots, idx);
  unsigned int oidx = 0;

  assert (slot);

  while (oidx < HURD_TABLE_EXTENT (&slot->objects)
	 && !hurd_table_lookup (&slot->objects, oidx))
    oidx++;

  *object = OBJECT_IDX_TO_ID (oidx);

  return CKR_OK;
}


/* Continue iterating over the list of objects.  */
CK_RV
objects_iterate_next (slot_iterator_t id, object_iterator_t *object)
{
  unsigned int idx = SLOT_ID_TO_IDX (id);
  struct slot *slot = hurd_table_lookup (&slots, idx);
  unsigned int oidx = OBJECT_ID_TO_IDX (*object);

  assert (slot);

  do
    oidx++;
  while (oidx < HURD_TABLE_EXTENT (&slot->objects)
	 && !hurd_table_lookup (&slot->objects, oidx));
  
  *object = OBJECT_IDX_TO_ID (oidx);

  return CKR_OK;
}


/* Stop iterating over the list of objects.  */
CK_RV
objects_iterate_end (slot_iterator_t id, object_iterator_t *object)
{
  /* Nothing to do.  */

  return 0;
}


/* Return true iff the previous slot was the last one.  */
bool
objects_iterate_last (slot_iterator_t id, object_iterator_t *object)
{
  unsigned int idx = SLOT_ID_TO_IDX (id);
  struct slot *slot = hurd_table_lookup (&slots, idx);
  unsigned int oidx = OBJECT_ID_TO_IDX (*object);

  assert (slot);

  return oidx >= HURD_TABLE_EXTENT (&slot->objects);
}


/* Return the max. number of objects in the slot.  May overcount
   somewhat.  */
CK_RV
slot_get_object_count (slot_iterator_t id, int *nr)
{
  unsigned int idx = SLOT_ID_TO_IDX (id);
  struct slot *slot = hurd_table_lookup (&slots, idx);

  assert (slot);

  *nr = HURD_TABLE_EXTENT (&slot->objects);

  return CKR_OK;
}

/* Get the object information for object OBJECT_ID in slot ID.  */
CK_RV
slot_get_object (slot_iterator_t id, object_iterator_t oid,
		 CK_ATTRIBUTE_PTR *obj, CK_ULONG *obj_count)
{
  unsigned int idx = SLOT_ID_TO_IDX (id);
  struct slot *slot = hurd_table_lookup (&slots, idx);
  unsigned int object_idx = OBJECT_ID_TO_IDX (oid);
  struct object *object;

  assert (slot);

  object = hurd_table_lookup (&slot->objects, object_idx);
  if (!object)
    return CKR_OBJECT_HANDLE_INVALID;

  assert (obj);
  assert (obj_count);

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
  unsigned int idx = SLOT_ID_TO_IDX (id);
  struct slot *slot = hurd_table_lookup (&slots, idx);
  unsigned session_idx = SESSION_ID (sid);
  struct session *session;

  assert (slot);

  session = hurd_table_lookup (&slot->sessions, session_idx);
  assert (session);

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
  unsigned int idx = SLOT_ID_TO_IDX (id);
  struct slot *slot = hurd_table_lookup (&slots, idx);
  unsigned session_idx = SESSION_ID (sid);
  struct session *session;

  assert (slot);

  session = hurd_table_lookup (&slot->sessions, session_idx);
  assert (session);

  assert (search_result);
  assert (search_result_len);

  *search_result = session->search_result;
  *search_result_len = session->search_result_len;

  return 0;
}


/* Set the signing key for session SID in slot ID to KEY.  */
CK_RV
session_set_signing_key (slot_iterator_t id, session_iterator_t sid,
			 object_iterator_t key)
{
  unsigned int idx = SLOT_ID_TO_IDX (id);
  struct slot *slot = hurd_table_lookup (&slots, idx);
  unsigned session_idx = SESSION_ID (sid);
  struct session *session;
  CK_RV err;
  CK_ATTRIBUTE_PTR attr;
  CK_ULONG attr_count;
  CK_OBJECT_CLASS key_class = CKO_PRIVATE_KEY;

  assert (slot);

  session = hurd_table_lookup (&slot->sessions, session_idx);
  assert (session);

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

  /* It's the private RSA key object.  */
  session->signing_key = key;

  return 0;
}


/* Set the signing key for session SID in slot ID to KEY.  */
CK_RV
session_sign (slot_iterator_t id, session_iterator_t sid,
	      CK_BYTE_PTR pData, CK_ULONG ulDataLen,
	      CK_BYTE_PTR pSignature, CK_ULONG_PTR pulSignatureLen)
{
  unsigned int idx = SLOT_ID_TO_IDX (id);
  struct slot *slot = hurd_table_lookup (&slots, idx);
  unsigned session_idx = SESSION_ID (sid);
  struct session *session;
  gpg_error_t err;
  unsigned int sig_len;

  assert (slot);

  session = hurd_table_lookup (&slot->sessions, session_idx);
  assert (session);

  /* FIXME: Who cares if they called sign init correctly.  */
  if (pSignature == NULL_PTR)
    {
      err = scute_agent_sign (NULL, NULL, 0, NULL, &sig_len);
      if (err)
	return scute_gpg_err_to_ck (err);
      *pulSignatureLen = sig_len;
      return 0;
    }

  sig_len = *pulSignatureLen;
  err = scute_agent_sign (slot->info.grip3, pData, ulDataLen,
			  pSignature, &sig_len);
  /* FIXME: Oh well.  */
  if (gpg_err_code (err) == GPG_ERR_INV_ARG)
    return CKR_BUFFER_TOO_SMALL;
  
  return scute_gpg_err_to_ck (err);
}
