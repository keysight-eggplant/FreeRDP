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


#if defined(WITH_SMARTCARD_LOGON) && defined(_WIN32)

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
#endif

