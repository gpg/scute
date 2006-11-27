/* t-gettokeninfo.c - Regression test.
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

#include <stdio.h>
#include <stdbool.h>

#include "t-support.h"

int
main (int argc, char *argv[])
{
  CK_RV err;
  CK_SLOT_ID_PTR slots;
  CK_ULONG slots_count;
  int i;

  init_cryptoki ();

  err = C_GetSlotList (true, NULL, &slots_count);
  fail_if_err (err);

  if (slots_count == 0)
    {
      printf ("Skipping test because no token is present.\n");
      return 0;
    }

  printf ("Number of slots with tokens: %lu\n", slots_count);
  slots = malloc (sizeof (CK_SLOT_ID) * slots_count);
  if (!slots)
    fail_if_err (CKR_HOST_MEMORY);

  err = C_GetSlotList (true, slots, &slots_count);
  fail_if_err (err);

  for (i = 0; i < slots_count; i++)
    {
      CK_TOKEN_INFO info;

      err = C_GetTokenInfo (slots[i], &info);

      printf ("%2i. Slot ID %lu\n", i, slots[i]);

      printf ("    Label: %.32s\n", info.label);
      printf ("    Manufacturer ID: %.32s\n", info.manufacturerID);
      printf ("    Model: %.16s\n", info.model);
      printf ("    Serial number: %.16s\n", info.serialNumber);
      printf ("    Flags: %#lx", info.flags);
      
      if (info.flags)
	{
	  bool any = false;
	  CK_FLAGS xflags;

	  xflags = info.flags
	    & ~(CKF_RNG | CKF_WRITE_PROTECTED | CKF_LOGIN_REQUIRED
		| CKF_USER_PIN_INITIALIZED | CKF_RESTORE_KEY_NOT_NEEDED
		| CKF_CLOCK_ON_TOKEN | CKF_PROTECTED_AUTHENTICATION_PATH
		| CKF_DUAL_CRYPTO_OPERATIONS | CKF_TOKEN_INITIALIZED
		| CKF_SECONDARY_AUTHENTICATION | CKF_USER_PIN_COUNT_LOW
		| CKF_USER_PIN_FINAL_TRY | CKF_USER_PIN_LOCKED
		| CKF_USER_PIN_TO_BE_CHANGED | CKF_SO_PIN_COUNT_LOW
		| CKF_SO_PIN_FINAL_TRY | CKF_SO_PIN_LOCKED
		| CKF_SO_PIN_TO_BE_CHANGED);

	  printf (" == ");
#define DO_FLAG(sym)					\
	  if (info.flags & sym)				\
	    {						\
	      printf ("%s" #sym, any ? " | " : "");	\
	      any = true;				\
	    }
	  DO_FLAG (CKF_RNG);
	  DO_FLAG (CKF_WRITE_PROTECTED);
	  DO_FLAG (CKF_LOGIN_REQUIRED);
	  DO_FLAG (CKF_USER_PIN_INITIALIZED);
	  DO_FLAG (CKF_RESTORE_KEY_NOT_NEEDED);
	  DO_FLAG (CKF_CLOCK_ON_TOKEN);
	  DO_FLAG (CKF_PROTECTED_AUTHENTICATION_PATH);
	  DO_FLAG (CKF_DUAL_CRYPTO_OPERATIONS);
	  DO_FLAG (CKF_TOKEN_INITIALIZED);
	  DO_FLAG (CKF_SECONDARY_AUTHENTICATION);
	  DO_FLAG (CKF_USER_PIN_COUNT_LOW);
	  DO_FLAG (CKF_USER_PIN_FINAL_TRY);
	  DO_FLAG (CKF_USER_PIN_LOCKED);
	  DO_FLAG (CKF_USER_PIN_TO_BE_CHANGED);
	  DO_FLAG (CKF_SO_PIN_COUNT_LOW);
	  DO_FLAG (CKF_SO_PIN_FINAL_TRY);
	  DO_FLAG (CKF_SO_PIN_LOCKED);
	  DO_FLAG (CKF_SO_PIN_TO_BE_CHANGED);

	  if (xflags)
	    printf ("%s%#lx", any ? " | " : "", xflags);
	}
      printf ("\n");

      printf ("    Max session count: %li\n", info.ulMaxSessionCount);
      printf ("    Session count: %li\n", info.ulSessionCount);
      printf ("    Max rw session count: %li\n", info.ulMaxRwSessionCount);
      printf ("    Rw session count: %li\n", info.ulRwSessionCount);
      printf ("    Max PIN length: %li\n", info.ulMaxPinLen);
      printf ("    Min PIN length: %li\n", info.ulMinPinLen);
      printf ("    Total public memory: %li\n", info.ulTotalPublicMemory);
      printf ("    Free public memory: %li\n", info.ulFreePublicMemory);
      printf ("    Total private memory: %li\n", info.ulTotalPrivateMemory);
      printf ("    Free private memory: %li\n", info.ulFreePrivateMemory);
      printf ("    Hardware version: %i.%i\n", info.hardwareVersion.major,
	      info.hardwareVersion.minor);
      printf ("    Firmware version: %i.%i\n", info.firmwareVersion.major,
	      info.firmwareVersion.minor);

      printf ("    UTC time: %.16s\n", info.utcTime);
    }

  return 0;
}
