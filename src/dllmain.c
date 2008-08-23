/* main.cc - DLL entry point
   Copyright (C) 2007 g10 Code GmbH

   This file is part of Scute.

   Scute is free software; you can redistribute it and/or
   modify it under the terms of the GNU Lesser General Public License
   as published by the Free Software Foundation; either version 2.1 
   of the License, or (at your option) any later version.
  
   Scute is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
   General Public License for more details.

   You should have received a copy of the GNU Lesser General Public License
   along with Scute; if not, write to the Free Software Foundation, 
   Inc., 59 Temple Place, Suite 330, Boston, MA 02111-1307 USA  */

#if HAVE_CONFIG_H
#include <config.h>
#endif

#include <stdarg.h>
#include <stdio.h>
#include <windows.h>
#include <shlobj.h>

#include <gpg-error.h>
#include <assuan.h>


/* Entry point called by DLL loader.  */
STDAPI
DllMain (HINSTANCE hinst, DWORD reason, LPVOID reserved)
{
  if (reason == DLL_PROCESS_ATTACH)
    {
      WSADATA wsadat;
	
      WSAStartup (0x202, &wsadat);
    }
  else if (reason == DLL_PROCESS_DETACH)
    {
      WSACleanup ();
    }
  
  return TRUE;
}
