/* t-support.h - Helper routines for regression tests.
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

#include <unistd.h>
#include <errno.h>
#include <stdlib.h>
#include <locale.h>

#include <cryptoki.h>

#define DIM(x) (sizeof (x) / sizeof (x[0]))


/* Check for compiler features.  */
#if __GNUC__
#define _GCC_VERSION (__GNUC__ * 10000 \
                      + __GNUC_MINOR__ * 100 \
                      + __GNUC_PATCHLEVEL__)

#if _GCC_VERSION > 30100
#define UNUSED	__attribute__ ((__unused__))
#endif
#endif

#ifndef UNUSED
#define UNUSED
#endif


const char *msg[] =
  {
    "OK", "Cancel", "Host memory", "Slot ID invalid", "Flags invalid",
    "General error", "Function failed", "Arguments bad", "No event",
    "Need to create threads", "Can't lock", "0x0000000b", "0x0000000c",
    "0x0000000d", "0x0000000e", "0x0000000f", "Attribute read only",
    "Attribute sensitive", "Attribute type invalid", "Attribute value invalid",
    "0x00000014", "0x00000015", "0x00000016", "0x00000017", "0x00000018",
    "0x00000019", "0x0000001a", "0x0000001b", "0x0000001c", "0x0000001d",
    "0x0000001e", "0x0000001f", "Data invalid", "Data length range",
    "0x00000022", "0x00000023", "0x00000024", "0x00000025", "0x00000026",
    "0x00000027", "0x00000028", "0x00000029", "0x0000002a", "0x0000002b",
    "0x0000002c", "0x0000002d", "0x0000002e", "0x0000002f", "Device error",
    "Device memory", "Devire removed", "0x00000033", "0x00000034",
    "0x00000035", "0x00000036", "0x00000037", "0x00000038", "0x00000039",
    "0x0000003a", "0x0000003b", "0x0000003c", "0x0000003d", "0x0000003e",
    "0x0000003f", "Encrypted data invalid", "Encrypted data length range",
    "0x00000042", "0x00000043", "0x00000044", "0x00000045", "0x00000046",
    "0x00000047", "0x00000048", "0x00000049", "0x0000004a", "0x0000004b",
    "0x0000004c", "0x0000004d", "0x0000004e", "0x0000004f",
    "Function canceled", "Function not parallel",
    "0x00000052", "0x00000053", "Function not supported", "0x00000055",
    "0x00000056", "0x00000057", "0x00000058", "0x00000059", "0x0000005a",
    "0x0000005b", "0x0000005c", "0x0000005d", "0x0000005e", "0x0000005f",
    "Key handle invalid", "Key sensitive", "Key size range",
    "Key type inconsistent", "Key not needed", "Key changed", "Key needed",
    "Key indigestible", "Key function not permitted", "Key not wrappable",
    "Key unextractable", "0x0000006b", "0x0000006c", "0x0000006d",
    "0x0000006e", "0x0000006f", "Mechanism invalid",
    "Mechanism parameter invalid",
    "0x00000072", "0x00000073", "0x00000074", "0x00000075", "0x00000076",
    "0x00000077", "0x00000078", "0x00000079", "0x0000007a", "0x0000007b",
    "0x0000007c", "0x0000007d", "0x0000007e", "0x0000007f",
    "Object class inconsistent", "Object class invalid",
    "Object handle invalid",
    "0x00000083", "0x00000084", "0x00000085", "0x00000086",
    "0x00000087", "0x00000088", "0x00000089", "0x0000008a", "0x0000008b",
    "0x0000008c", "0x0000008d", "0x0000008e", "0x0000008f",
    "Operation active", "Operation not initialized",
    "0x00000092", "0x00000093", "0x00000094", "0x00000095", "0x00000096",
    "0x00000097", "0x00000098", "0x00000099", "0x0000009a", "0x0000009b",
    "0x0000009c", "0x0000009d", "0x0000009e", "0x0000009f",
    "PIN incorrect", "PIN invalid", "PIN length range", "PIN expired",
    "PIN locked", "0x000000a5", "0x000000a6", "0x000000a7", "0x000000a8",
    "0x000000a9", "0x000000aa", "0x000000ab", "0x000000ac", "0x000000ad",
    "0x000000ae", "0x000000af",
    "Session closed", "Session count", "0x000000b2", "Session handle invalid",
    "Session parallel not supported", "Session read only", "Session exists",
    "Session read only exists", "Session read write SO exists",
    "0x000000b9", "0x000000ba", "0x000000bb", "0x000000bc", "0x000000bd",
    "0x000000be", "0x000000bf",
    "Signature invalid", "Signature length range",
    "0x000000c2", "0x000000c3", "0x000000c4", "0x000000c5", "0x000000c6",
    "0x000000c7", "0x000000c8", "0x000000c9", "0x000000ca", "0x000000cb",
    "0x000000cc", "0x000000cd", "0x000000ce", "0x000000cf",
    "Template incomplete", "Template inconsistent",
    "0x000000d2", "0x000000d3", "0x000000d4", "0x000000d5", "0x000000d6",
    "0x000000d7", "0x000000d8", "0x000000d9", "0x000000da", "0x000000db",
    "0x000000dc", "0x000000dd", "0x000000de", "0x000000df",
    "Token not present", "Token not recognized", "Token write protected",
    "0x000000e3", "0x000000e4", "0x000000e5", "0x000000e6", "0x000000e7",
    "0x000000e8", "0x000000e9", "0x000000ea", "0x000000eb", "0x000000ec",
    "0x000000ed", "0x000000ee", "0x000000ef",
    "Unwrapping key handle invalid", "Unwrapping key size range",
    "Unwrapping key type inconsistent",
    "0x000000f3", "0x000000f4", "0x000000f5", "0x000000f6", "0x000000f7",
    "0x000000f8", "0x000000f9", "0x000000fa", "0x000000fb", "0x000000fc",
    "0x000000fd", "0x000000fe", "0x000000ff",
    "User already logged in", "User not logged in", "User PIN not initialized",
    "User type invalid", "Another user already logged in",
    "User too many types",
    "0x00000106", "0x00000107", "0x00000108", "0x00000109", "0x0000010a",
    "0x0000010b", "0x0000010c", "0x0000010d", "0x0000010e", "0x0000010f",
    "Wrapped key invalid", "0x00000110", "Wrapped key length range",
    "Wrapping key handle invalid", "Wrapping key size range",
    "Wrapping key type inconsistent",
    "0x00000116", "0x00000117", "0x00000118", "0x00000119", "0x0000011a",
    "0x0000011b", "0x0000011c", "0x0000011d", "0x0000011e", "0x0000011f",
    "Random seed not supported", "No random number generator",
    "0x00000122", "0x00000123", "0x00000124", "0x00000125", "0x00000126",
    "0x00000127", "0x00000128", "0x00000129", "0x0000012a", "0x0000012b",
    "0x0000012c", "0x0000012d", "0x0000012e", "0x0000012f",
    "Domain parameters invalid",
    "0x00000131", "0x00000132", "0x00000133", "0x00000134", "0x00000135",
    "0x00000136", "0x00000137", "0x00000138", "0x00000139", "0x0000013a",
    "0x0000013b", "0x0000013c", "0x0000013d", "0x0000013e", "0x0000013f",
    "0x00000140", "0x00000141", "0x00000142", "0x00000143", "0x00000144",
    "0x00000145", "0x00000146", "0x00000147", "0x00000148", "0x00000149",
    "0x0000014a", "0x0000014b", "0x0000014c", "0x0000014d", "0x0000014e",
    "0x0000014f",
    "Buffer too small",
    "0x00000151", "0x00000152", "0x00000153", "0x00000154", "0x00000155",
    "0x00000156", "0x00000157", "0x00000158", "0x00000159", "0x0000015a",
    "0x0000015b", "0x0000015c", "0x0000015d", "0x0000015e", "0x0000015f",
    "Saved state invalid",
    "0x00000161", "0x00000162", "0x00000163", "0x00000164", "0x00000165",
    "0x00000166", "0x00000167", "0x00000168", "0x00000169", "0x0000016a",
    "0x0000016b", "0x0000016c", "0x0000016d", "0x0000016e", "0x0000016f",
    "Information sensitive",
    "0x00000171", "0x00000172", "0x00000173", "0x00000174", "0x00000175",
    "0x00000176", "0x00000177", "0x00000178", "0x00000179", "0x0000017a",
    "0x0000017b", "0x0000017c", "0x0000017d", "0x0000017e", "0x0000017f",
    "State unsaveable",
    "0x00000181", "0x00000182", "0x00000183", "0x00000184", "0x00000185",
    "0x00000186", "0x00000187", "0x00000188", "0x00000189", "0x0000018a",
    "0x0000018b", "0x0000018c", "0x0000018d", "0x0000018e", "0x0000018f",
    "Cryptoki not initialized", "Cryptoki already initialized",
    "0x00000192", "0x00000193", "0x00000194", "0x00000195", "0x00000196",
    "0x00000197", "0x00000198", "0x00000199", "0x0000019a", "0x0000019b",
    "0x0000019c", "0x0000019d", "0x0000019e", "0x0000019f",
    "Mutex bad", "Mutex not locked",
    "0x000001a2", "0x000001a3", "0x000001a4", "0x000001a5", "0x000001a6",
    "0x000001a7", "0x000001a8", "0x000001a9", "0x000001aa", "0x000001ab",
    "0x000001ac", "0x000001ad", "0x000001ae", "0x000001af",
    "0x000001b0", "0x000001b1", "0x000001b2", "0x000001b3", "0x000001b4",
    "0x000001b5", "0x000001b6", "0x000001b7", "0x000001b8", "0x000001b9",
    "0x000001ba", "0x000001bb", "0x000001bc", "0x000001bd", "0x000001be",
    "0x000001bf",
    "0x000001c0", "0x000001c1", "0x000001c2", "0x000001c3", "0x000001c4",
    "0x000001c5", "0x000001c6", "0x000001c7", "0x000001c8", "0x000001c9",
    "0x000001ca", "0x000001cb", "0x000001cc", "0x000001cd", "0x000001ce",
    "0x000001cf",
    "0x000001d0", "0x000001d1", "0x000001d2", "0x000001d3", "0x000001d4",
    "0x000001d5", "0x000001d6", "0x000001d7", "0x000001d8", "0x000001d9",
    "0x000001da", "0x000001db", "0x000001dc", "0x000001dd", "0x000001de",
    "0x000001df",
    "0x000001e0", "0x000001e1", "0x000001e2", "0x000001e3", "0x000001e4",
    "0x000001e5", "0x000001e6", "0x000001e7", "0x000001e8", "0x000001e9",
    "0x000001ea", "0x000001eb", "0x000001ec", "0x000001ed", "0x000001ee",
    "0x000001ef",
    "0x000001f0", "0x000001f1", "0x000001f2", "0x000001f3", "0x000001f4",
    "0x000001f5", "0x000001f6", "0x000001f7", "0x000001f8", "0x000001f9",
    "0x000001fa", "0x000001fb", "0x000001fc", "0x000001fd", "0x000001fe",
    "0x000001ff",
    "Function rejected" };

#define ERRMSG(nr) ((nr) == CKR_VENDOR_DEFINED ? "Vendor defined" :	\
		    (((nr) < 0 || (nr) > sizeof (msg) / sizeof (msg[0])) ? \
		     "(unknown error code)" : msg[(nr)]))


static const char *
mechanism_type_str (CK_MECHANISM_TYPE mechanism_type) UNUSED;

static const char *
mechanism_type_str (CK_MECHANISM_TYPE mechanism_type)
{
  switch (mechanism_type)
    {
#define CKM_ONE(mechanism)					\
    case mechanism:						\
      return #mechanism;

      CKM_ONE (CKM_RSA_PKCS_KEY_PAIR_GEN);
      CKM_ONE (CKM_RSA_PKCS);

    default:
      return NULL;
    }
}


static const char *session_state_str (CK_STATE state) UNUSED;

static const char *
session_state_str (CK_STATE state)
{
  switch (state)
    {
#define CKS_ONE(state)						\
    case state:							\
      return #state;

      CKS_ONE (CKS_RO_PUBLIC_SESSION);
      CKS_ONE (CKS_RO_USER_FUNCTIONS);
      CKS_ONE (CKS_RW_PUBLIC_SESSION);
      CKS_ONE (CKS_RW_USER_FUNCTIONS);
      CKS_ONE (CKS_RW_SO_FUNCTIONS);

    default:
      return NULL;
    }
}


#define fail_if_err(err)					\
  do								\
    {								\
      if (err)							\
        {							\
          fprintf (stderr, "%s:%d: %s\n",			\
                   __FILE__, __LINE__, ERRMSG(err));		\
          exit (1);						\
        }							\
    }								\
  while (0)

#define fail(errmsg)						\
  do								\
    {								\
      if (err)							\
        {							\
          fprintf (stderr, "%s:%d: %s\n",			\
                   __FILE__, __LINE__, errmsg);			\
          exit (1);						\
        }							\
    }								\
  while (0)

void
init_cryptoki (void)
{
  CK_RV err;

  err = C_Initialize (NULL);
  fail_if_err (err);
}
