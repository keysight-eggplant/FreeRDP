/**
 * FreeRDP: A Remote Desktop Protocol Implementation
 * smartcard-windows.c
 *
 * Created by Marcian Lytwyn on 7/20/20.
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

#include <stdio.h>
#include "smartcard-windows.h"
#include "smartcardlogon.h"
#include <freerdp/log.h>


#if defined(WITH_SMARTCARD_LOGON) && defined(_WIN32)

extern LPTSTR stringX_from_cstring(const char* cstring);

#define TAG FREERDP_TAG("core.nla.smartcard")

#define NTE_NO_MORE_ITEMS                (0x8009002AL)

PCHAR reversePropertyValue(int cbData, void* pvData)
{
  UCHAR* ptr = (PUCHAR)pvData;
  UCHAR* dest = (PUCHAR)malloc(cbData);
  ptr += cbData - 1;
  for (int index = 0; index < cbData; ++index)
    dest[index] = *ptr--;
  return (PCHAR)dest;
}

void dumpPropertyValue(int cbData, void *pvData)
{
#if 0 // Enable for debugging...
  BYTE *ptr = (PBYTE) pvData;
  for (int index = 0; index < cbData; ++index)
    WLog_DBG(TAG, "%02X", ptr[index]);
  WLog_DBG(TAG, "\n");
#endif
}

int getCryptoCredentialForKeyName(LPWSTR keyname, LPWSTR *credential)
{
  NCRYPT_PROV_HANDLE phProvider;
  DWORD              certsize = 0;
  
  if (NULL == credential)
  {
    return 0;
  }
  *credential = NULL;
  
  SECURITY_STATUS    status = NCryptOpenStorageProvider(&phProvider, MS_SCARD_PROV, 0);
  
  if (ERROR_SUCCESS != status)
  {
    WLog_DBG(TAG, "NCryptOpenStorageProvider error: %d (0x%0X)\n", GetLastError(), GetLastError());
  }
  else
  {
    {
      WLog_DBG(TAG, "name: %S keySpec: %d (0x%X) flags: %d\n",
               keyname, AT_KEYEXCHANGE, AT_KEYEXCHANGE, 0);
      
      {
        NCRYPT_KEY_HANDLE  phKey;
        
        status = NCryptOpenKey(phProvider, &phKey, keyname, AT_KEYEXCHANGE, NCRYPT_SILENT_FLAG);
        
        if (ERROR_SUCCESS != status)
        {
          WLog_ERR(TAG, "NCryptOpenKey error: %d (0x%0X)\n", status, status);
        }
        else
        {
          // For some reason this one is not found when used...
          // NCRYPT_CERTIFICATE_PROPERTY,
          static const WCHAR *CProperties[] =
          {
            NCRYPT_CERTIFICATE_PROPERTY,
          };
          static const DWORD  NProperties = sizeof(CProperties) / sizeof(CProperties[0]);
          
          for (int index = 0; index < NProperties; ++index)
          {
            DWORD   cbOutput = 256;
            DWORD   dwFlags = 0;
            
            status = NCryptGetProperty(phKey, CProperties[index], NULL, 0, &cbOutput, dwFlags);
            PBYTE    pbOutput = (PBYTE)malloc(cbOutput);
            status = NCryptGetProperty(phKey, CProperties[index], pbOutput, cbOutput, &cbOutput, dwFlags);
            
            if (ERROR_SUCCESS != status)
            {
              WLog_ERR(TAG, "NCryptGetProperty (%S) error: %d (0x%0X)\n", CProperties[index], status, status);
            }
            else
            {
              if (0 == wcscmp(NCRYPT_CERTIFICATE_PROPERTY, CProperties[index]))
              {
                *credential = (LPWSTR)malloc(cbOutput);
                memcpy(*credential, pbOutput, cbOutput);
                certsize = cbOutput;
              }
              dumpPropertyValue(cbOutput, pbOutput);
            }
            free(pbOutput);
          }
          
          // Cleanup...
          NCryptFreeObject(phKey);
        }
      }
    }
    
    // Cleanup...
    NCryptFreeObject(phProvider);
  }
  
  return certsize;
}

LPWSTR getMarshaledCredentials(char *keyname)
{
  CERT_CREDENTIAL_INFO certInfo = { sizeof(CERT_CREDENTIAL_INFO), { 0 } };
  HCRYPTPROV hProv;
  HCRYPTHASH hHash;
  DWORD dwHashLen = CERT_HASH_LENGTH;
  PBYTE certdata = NULL;
  LPTSTR szMarshaledCred = NULL;
  LPWSTR credentials = NULL;
  
  if (NULL == keyname)
  {
    WLog_ERR(TAG, "getMarshaledCredentials - keyname is NULL");
  }
  else
  {
    DWORD keysize = strlen(keyname);
    if (0 == keysize)
    {
      WLog_ERR(TAG, "getMarshaledCredentials - keyname is empty");
    }
    else
    {
      LPWSTR wkeyname = stringX_from_cstring(keyname);
      DWORD certsize = getCryptoCredentialForKeyName(wkeyname, (LPWSTR*)&certdata);
      
      // Free the keyname memory first...
      free(wkeyname);
      
      // Check whether we got a certificate...
      if (0 == certsize)
      {
        WLog_ERR(TAG, "getMarshaledCredentials - could not get smart card certificate for keyname: %s", keyname);
        free(certdata);
      }
      else
      {
#if defined (WITH_DEBUG_NLA)
        WLog_DBG(TAG, "MarshalCredentials: using certificate size: %d ->", certsize);
        dumpPropertyValue(certsize, certdata);
#endif
        
        if (FALSE == CryptAcquireContext(&hProv, NULL, MS_DEF_PROV, PROV_RSA_FULL, CRYPT_VERIFYCONTEXT))
        {
          WLog_ERR(TAG, "getMarshaledCredentials - CryptAcquireContext failed for keyname: %s - error: %d (0x%0X)", keyname, GetLastError(), GetLastError());
          free(certdata);
        }
        else
        {
          if (FALSE == CryptCreateHash(hProv, CALG_SHA1, 0, 0, &hHash))
          {
            WLog_ERR(TAG, "getMarshaledCredentials - CryptCreateHash failed for keyname: %s - error: %d (0x%0X)", keyname, GetLastError(), GetLastError());
            free(certdata);
            CryptReleaseContext(hProv, 0);
          }
          else
          {
            if (FALSE == CryptHashData(hHash, certdata, certsize, 0))
            {
              WLog_ERR(TAG, "getMarshaledCredentials - CryptCreateHash failed for keyname: %s - error: %d (0x%0X)", keyname, GetLastError(), GetLastError());
              free(certdata);
              CryptDestroyHash(hHash);
              CryptReleaseContext(hProv, 0);
            }
            else
            {
              if (FALSE == CryptGetHashParam(hHash, HP_HASHVAL, certInfo.rgbHashOfCert, &dwHashLen, 0))
              {
                WLog_ERR(TAG, "getMarshaledCredentials - CryptGetHashParam failed for keyname: %s - error: %d (0x%0X)", keyname, GetLastError(), GetLastError());
                free(certdata);
                CryptDestroyHash(hHash);
                CryptReleaseContext(hProv, 0);
              }
              else
              {
                if (FALSE == CredMarshalCredential(CertCredential, &certInfo, &szMarshaledCred))
                {
                  WLog_ERR(TAG, "getMarshaledCredentials - CredMarshalCredential failed for keyname: %s - error: %d (0x%0X)", keyname, GetLastError(), GetLastError());
                  free(certdata);
                  CryptDestroyHash(hHash);
                  CryptReleaseContext(hProv, 0);
                }
                else
                {
#if defined (WITH_DEBUG_NLA)
                  {
                    WLog_DBG(TAG, "getMarshaledCredentials: %d -> %S\n", wcslen(szMarshaledCred), szMarshaledCred);
                    dumpPropertyValue(wcslen(szMarshaledCred), szMarshaledCred);
                  }
#endif
                  // Save a copy of the marshalled credentials
                  credentials = wcsdup(szMarshaledCred);
                  
                  // Cleanup...
                  free(certdata);
                  CryptDestroyHash(hHash);
                  CryptReleaseContext(hProv, 0);
                  CredFree(szMarshaledCred);
                }
              }
            }
          }
        }
      }
    }
  }
  
  return credentials;
}

int getAtrCardName(char *readerName, scquery_result identityPtr)
{
  LONG         status = 0;
  SCARDCONTEXT scContext = 0;
  
  status = SCardEstablishContext(SCARD_SCOPE_USER, NULL, NULL, &scContext);
  
  if (0 == scContext)
  {
    WLog_ERR(TAG, "SCardEstablishContext error: %ld (0x%0X)\n", status, (unsigned int)status);
    printf("SCardEstablishContext error: %ld (0x%0X)\n", status, (unsigned int)status);
    SCardReleaseContext(scContext);
    return -1;
  }
  else
  {
    DWORD           dwShareMode = SCARD_SHARE_SHARED;
    DWORD           dwPreferredProtocols = SCARD_PROTOCOL_T0 | SCARD_PROTOCOL_T1;
    SCARDHANDLE     hCardHandle;
    DWORD           dwActiveProtocol = 0;
    status = SCardConnect(scContext, readerName, dwShareMode, dwPreferredProtocols, &hCardHandle, &dwActiveProtocol);
    
    // Translate the ATR to a card name...
    if (ERROR_SUCCESS != status)
    {
      WLog_ERR(TAG, "SCardConnect error: %ld (0x%0X)\n", status, (unsigned int)status);
      printf("SCardConnect error: %ld (0x%0X)\n", status, (unsigned int)status);
      SCardReleaseContext(scContext);
      return -1;
    }
    
    BYTE  atrstring[256] = { 0 };
    DWORD cbLength = 256;
    
    // ATR...
    cbLength = 256;
    status = SCardGetAttrib(hCardHandle, SCARD_ATTR_ATR_STRING, atrstring, &cbLength);
    
    // Check whether we got a ATR string...
    if (ERROR_SUCCESS != status)
    {
      WLog_ERR(TAG, "SCardGetAttrib error: %ld (0x%0X)\n", status, (unsigned int)status);
      printf("SCardGetAttrib error: %ld (0x%0X)\n", status, (unsigned int)status);
      SCardDisconnect(scContext, SCARD_LEAVE_CARD);
      SCardReleaseContext(scContext);
      return -1;
    }
    
    wchar_t atrname[256] = { 0 };
    cbLength = 256;
    
    // This gets the card name for the ATR string...
    status = SCardListCards(scContext, atrstring, NULL, 0, atrname, &cbLength);
    if (ERROR_SUCCESS != status)
    {
      WLog_ERR(TAG, "SCardListCards error: %ld (0x%0X)\n", status, (unsigned int)status);
      printf("SCardListCards error: %ld (0x%0X)\n", status, (unsigned int)status);
      SCardDisconnect(scContext, SCARD_LEAVE_CARD);
      SCardReleaseContext(scContext);
    }
    else
    {
      printf("ATR name: %ld -> %S\n", cbLength, atrname);
      if (0 != wcsncmp(atrname, L"Identity Device", wcslen(L"Identity Device")))
      {
        // Allocate and azero out the memory for the card name...
        identityPtr->certificate->token_label = (char*)malloc(cbLength+1);
        memset(identityPtr->certificate->token_label, 0, cbLength+1);
        
        // Convert to char string...
        wcstombs(identityPtr->certificate->token_label, atrname, cbLength);
        WLog_DBG(TAG, "Card name: %ld -> %s\n", cbLength, identityPtr->certificate->token_label);
        printf("Card name: %ld -> %s\n", cbLength, identityPtr->certificate->token_label);
      }
      else
      {
        wchar_t* pos1 = wcschr(atrname, '(');
        wchar_t* pos2 = wcschr(atrname, ')');
        if ((NULL == pos1) || (NULL == pos2))
        {
          WLog_ERR(TAG, "card name error: %ld (0x%0X)\n", GetLastError(), (unsigned int)GetLastError());
          printf("card name error: %ld (0x%0X)\n", GetLastError(), (unsigned int)GetLastError());
          SCardDisconnect(scContext, SCARD_LEAVE_CARD);
          SCardReleaseContext(scContext);
        }
        else
        {
          const int size = pos2 - pos1;
          
          // Allocate and azero out the memory for the card name...
          identityPtr->certificate->token_label = (char*)calloc(size + 1, sizeof(char));
          memset(identityPtr->certificate->token_label, 0, (size + 1) * sizeof(char));
          
          // Null terminate at ')' position...
          *pos2 = '\0';
          
          // Convert to char string...
          wcstombs(identityPtr->certificate->token_label, pos1 + 1, size-1);
          WLog_DBG(TAG, "Card name: %d -> %s\n", size, identityPtr->certificate->token_label);
          printf("Card name: %d -> %s\n", size, identityPtr->certificate->token_label);
        }
      }
    }
    
    // Cleanup...
    SCardDisconnect(scContext, SCARD_LEAVE_CARD);
    SCardReleaseContext(scContext);
  }
  
  return 0;
}

int validateSmartCardUsage(PCCERT_CONTEXT pcontext, scquery_result identityPtr)
{
  DWORD flags = CERT_FIND_EXT_ONLY_ENHKEY_USAGE_FLAG; // CERT_FIND_EXT_ONLY_ENHKEY_USAGE_FLAG | CERT_FIND_PROP_ONLY_ENHKEY_USAGE_FLAG
  DWORD dusage = 0;
  
  // Request data buffer size needed...
  CertGetEnhancedKeyUsage(pcontext, flags, NULL, &dusage);
  WLog_INFO(TAG, "Certificate enhanced key usage - allocating size: %d\n", dusage);
  
  if (0 == dusage)
  {
    WLog_INFO(TAG, "CertGetEnhancedKeyUsage enhanced key usage size zero - assuming ALL ACCESS");
  }
  else
  {
    // TODO: Need more error checking here!!!
    PCERT_ENHKEY_USAGE pusage = (PCERT_ENHKEY_USAGE)malloc(dusage);
    
    // ANY erroros will skip this certificate...
    if (NULL == pusage)
    {
      WLog_ERR(TAG, "CertGetEnhancedKeyUsage error allocating memory enhanced key usage data: %d (0x%0X)\n", GetLastError(), GetLastError());
      identityPtr = NULL;
    }
    else
    {
      BOOL status = CertGetEnhancedKeyUsage(pcontext, flags, pusage, &dusage);
      DWORD errorcode = GetLastError();
      
      if ((FALSE == status) && (CRYPT_E_NOT_FOUND != errorcode))
      {
        WLog_ERR(TAG, "CertGetEnhancedKeyUsage error getting enhanced key usage data: %d (0x%0X)\n", GetLastError(), GetLastError());
        identityPtr = NULL;
        free(pusage);
      }
      else if ((0 == pusage->cUsageIdentifier) && (CRYPT_E_NOT_FOUND != errorcode))
      {
        WLog_ERR(TAG, "CertGetEnhancedKeyUsage(pusage->cUsageIdentifier == 0) error: %d (0x%0X)\n", GetLastError(), GetLastError());
        identityPtr = NULL;
        free(pusage);
      }
      else if (0 == pusage->cUsageIdentifier) // AND (CRYPT_E_NOT_FOUND != errorcode) is aassumed from above...
      {
        WLog_INFO(TAG, "Certificate enhanced key usage: ALL ALLOWED\n");
      }
      else
      {
        LPSTR *string = pusage->rgpszUsageIdentifier;
        int    foundCount = 0; // Need this to be 2 - SMART_CARD_LOGON_OID && CLIENT_AUTHENTICATION_OID - otherwise fail...
        for (int index = 0; index < pusage->cUsageIdentifier; ++index)
        {
          static const char *SMART_CARD_LOGON_OID        = "1.3.6.1.4.1.311.20.2.2";
#define SMART_CARD_LOGON_OID_LENGTH strlen(SMART_CARD_LOGON_OID)
          static const char *CLIENT_AUTHENTICATION_OID   = "1.3.6.1.5.5.7.3.2";
#define CLIENT_AUTHENTICATION_OID_LENGTH strlen(CLIENT_AUTHENTICATION_OID)
          static const char *SECURE_EMAIL_OID            = "1.3.6.1.5.5.7.3.4";
#define SECURE_EMAIL_OID_LENGTH strlen(SECURE_EMAIL_OID)
          
          int length = strlen(string[index]);
          
          if ((SMART_CARD_LOGON_OID_LENGTH == length) && (0 == strncmp(SMART_CARD_LOGON_OID, string[index], SMART_CARD_LOGON_OID_LENGTH)))
          {
            WLog_INFO(TAG, "SMART_CARD_LOGON_OID enhanced key usage: %d -> %s\n", length, string[index]);
            foundCount++;
          }
          else if ((CLIENT_AUTHENTICATION_OID_LENGTH == length) && (0 == strncmp(CLIENT_AUTHENTICATION_OID, string[index], CLIENT_AUTHENTICATION_OID_LENGTH)))
          {
            WLog_INFO(TAG, "CLIENT_AUTHENTICATION_OID enhanced key usage: %d -> %s\n", length, string[index]);
            foundCount++;
          }
          else if ((SECURE_EMAIL_OID_LENGTH == length) && (0 == strncmp(SECURE_EMAIL_OID, string[index], SECURE_EMAIL_OID_LENGTH)))
          {
            WLog_INFO(TAG, "SECURE_EMAIL_OID enhanced key usage: %d -> %s\n", length, string[index]);
          }
          else
          {
            WLog_ERR(TAG, "UNKNOWN enhanced key usage: %d -> %s\n", length, string[index]);
          }
        }
        
        // We need at least the client authentication and smart card logon OID for the ceritificate...
        if (2 != foundCount)
        {
          WLog_ERR(TAG, "CertGetEnhancedKeyUsage(Authentication/Smart Card Logon certificate not found)\n");
          identityPtr = NULL;
          free(pusage);
        }
      }
    }
    
    // Cleanup...
    free(pusage);
  }
  
  return ((NULL == identityPtr) ? -1 : 0);
}
#endif

