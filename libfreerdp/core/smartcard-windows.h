/**
 * FreeRDP: A Remote Desktop Protocol Implementation
 *  smartcard-windows.h
 *
 *  Created by Marcian Lytwyn on 7/20/20.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#ifndef smartcard_windows_h
#define smartcard_windows_h

#include "smartcardlogon.h"
#include <wincrypt.h>
#include <WinCred.h>
#include <WinScard.h>
#include <winpr/crypto.h>

// Prototypes...
int getAtrCardName(char *readerName, scquery_result identityPtr);
int getCryptoCredentialForKeyName(LPWSTR keyname, LPWSTR *credential);
LPWSTR getMarshaledCredentials(char *keyname);
int validateSmartCardUsage(PCCERT_CONTEXT pcontext, scquery_result identityPtr);

#endif /* smartcard_windows_h */
