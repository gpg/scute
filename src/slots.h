/* slots.h - Slot management interface.
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

#ifndef SLOTS_H
#define SLOTS_H	1

#include <stdbool.h>

#include "cryptoki.h"


/* The slot login status.  */
typedef enum
  {
    SLOT_LOGIN_PUBLIC = 0,
    SLOT_LOGIN_USER = 1,
    SLOT_LOGIN_SO = 2,
  } slot_login_t;

/* A slot pointer.  */
typedef CK_SLOT_ID slot_iterator_t;

/* A mechanism pointer.  */
typedef int mechanism_iterator_t;

/* An object pointer.  */
typedef CK_OBJECT_HANDLE object_iterator_t;

/* A session pointer.  */
typedef int session_iterator_t;


/* Initialize the slot list.  */
CK_RV scute_slots_initialize (void);

/* Finalize the slot list.  */
void scute_slots_finalize (void);

/* Update the slot list by finding new devices.  Please note that
   Mozilla NSS currently assumes that the slot list never shrinks (see
   TODO file for a discussion).  This is the only function allowed to
   manipulate the slot list.  */
CK_RV slots_update_all (void);

/* Update the slot SLOT.  */
CK_RV slots_update_slot (slot_iterator_t id);

/* Begin iterating over the list of slots.  If succeeds, will be
   followed up by a slot_iterate_end.  */
CK_RV slots_iterate_first (slot_iterator_t *slot);

/* Continue iterating over the list of slots.  */
CK_RV slots_iterate_next (slot_iterator_t *slot);

/* Return true iff the previous slot was the last one.  */
bool slots_iterate_last (slot_iterator_t *slot);


/* Acquire the slot for the slot id ID.  */
CK_RV slots_lookup (CK_SLOT_ID id, slot_iterator_t *slot);


/* Return true iff a token is present in slot SLOT.  */
bool slot_token_present (slot_iterator_t slot);

/* Return the token label.  */
const char *slot_token_label (slot_iterator_t id);

/* Get the manufacturer of the token.  */
const char *slot_token_manufacturer (slot_iterator_t id);

/* Get the application of the token.  */
const char *slot_token_application (slot_iterator_t id);

/* Get the serial number of the token.  */
const char *slot_token_serial (slot_iterator_t id);

/* Get the manufacturer of the token.  */
void slot_token_version (slot_iterator_t id,
			 CK_BYTE *hw_major, CK_BYTE *hw_minor,
			 CK_BYTE *fw_major, CK_BYTE *fw_minor);

/* Get the maximum and minimum pin length.  */
void slot_token_maxpinlen (slot_iterator_t id, CK_ULONG *max, CK_ULONG *min);

/* Get the maximum and the actual pin count.  */
void slot_token_pincount (slot_iterator_t id, int *max, int *len);

/* Return the ID of slot SLOT.  */
CK_SLOT_ID slot_get_id (slot_iterator_t slot);

/* Return true if the token supports the GET CHALLENGE operation. */
bool slot_token_has_rng (slot_iterator_t id);


/* Begin iterating over the list of mechanisms.  If succeeds, will be
   followed up by a slot_iterate_end.  */
CK_RV mechanisms_iterate_first (slot_iterator_t id,
				mechanism_iterator_t *mechanism);

/* Continue iterating over the list of mechanisms.  */
CK_RV mechanisms_iterate_next (slot_iterator_t id,
			       mechanism_iterator_t *mechanism);

/* Return true iff the previous slot was the last one.  */
bool mechanisms_iterate_last (slot_iterator_t id,
			      mechanism_iterator_t *mechanisms);


/* Acquire the mechanism TYPE for the slot id ID.  */
CK_RV mechanisms_lookup (CK_SLOT_ID id,  mechanism_iterator_t *mechanism,
			 CK_MECHANISM_TYPE type);


/* Return the type of mechanism MID in slot ID.  */
CK_MECHANISM_TYPE mechanism_get_type (slot_iterator_t id,
				      mechanism_iterator_t mid);

/* Return the info of mechanism MID.  */
CK_MECHANISM_INFO_PTR mechanism_get_info (slot_iterator_t id,
					  mechanism_iterator_t mid);


/* Create a new session.  */
CK_RV slot_create_session (slot_iterator_t id, session_iterator_t *session,
			   bool rw);

/* Look up session.  */
CK_RV slots_lookup_session (CK_SESSION_HANDLE sid, slot_iterator_t *id,
			    session_iterator_t *session_id);

/* Close the session.  */
CK_RV slot_close_session (slot_iterator_t id, session_iterator_t sid);

/* Close all sessions.  */
CK_RV slot_close_all_sessions (slot_iterator_t id);


/* Get the RW flag from the session SID in slot ID.  */
bool session_get_rw (slot_iterator_t id, session_iterator_t sid);

/* Get the login state from the slot ID.  */
slot_login_t slot_get_status (slot_iterator_t id);



/* Begin iterating over the list of objects.  If succeeds, will be
   followed up by a slot_iterate_end.  */
CK_RV objects_iterate_first (slot_iterator_t id, object_iterator_t *object);

/* Continue iterating over the list of objects.  */
CK_RV objects_iterate_next (slot_iterator_t id, object_iterator_t *object);

/* Return true iff the previous slot was the last one.  */
bool objects_iterate_last (slot_iterator_t id, object_iterator_t *object);

/* Return the max. number of objects in the slot.  May overcount
   somewhat.  */
CK_RV slot_get_object_count (slot_iterator_t id, int *nr);

/* Get the object information for object OBJECT_ID in slot ID.  */
CK_RV slot_get_object (slot_iterator_t id, object_iterator_t object_id,
		       CK_ATTRIBUTE_PTR *obj, CK_ULONG *obj_count);

/* Set the result of a search for session SID in slot ID to
   SEARCH_RESULT and SEARCH_RESULT_LEN.  */
CK_RV session_set_search_result (slot_iterator_t id, session_iterator_t sid,
				 object_iterator_t *search_result,
				 int search_result_len);

/* Get the stored search result for the session SID in slot ID.  */
CK_RV session_get_search_result (slot_iterator_t id, session_iterator_t sid,
				 object_iterator_t **search_result,
				 int *search_result_len);

/* The core of C_SignInit.  */
CK_RV session_set_signing_key (slot_iterator_t id, session_iterator_t sid,
			       object_iterator_t key);

/* The core of C_Sign.  */
CK_RV session_sign (slot_iterator_t id, session_iterator_t sid,
		    CK_BYTE_PTR pData, CK_ULONG ulDataLen,
		    CK_BYTE_PTR pSignature, CK_ULONG_PTR pulSignatureLen);

/* The core of C_DecryptInit.  */
CK_RV session_init_decrypt (slot_iterator_t slotid, session_iterator_t sid,
                            CK_MECHANISM *mechanism, object_iterator_t key);

/* The core of C_Decrypt.  */
CK_RV session_decrypt (slot_iterator_t slotid, session_iterator_t sid,
                       CK_BYTE *encdata, CK_ULONG encdatalen,
                       CK_BYTE *r_plaindata, CK_ULONG *r_plaindatalen);


#endif	/* !SLOTS_H */
