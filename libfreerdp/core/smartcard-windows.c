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

static const char *SMART_CARD_LOGON_OID        = "1.3.6.1.4.1.311.20.2.2";
#define SMART_CARD_LOGON_OID_LENGTH           strlen(SMART_CARD_LOGON_OID)
static const char *CLIENT_AUTHENTICATION_OID   = "1.3.6.1.5.5.7.3.2";
#define CLIENT_AUTHENTICATION_OID_LENGTH      strlen(CLIENT_AUTHENTICATION_OID)
static const char *SECURE_EMAIL_OID            = "1.3.6.1.5.5.7.3.4";
#define SECURE_EMAIL_OID_LENGTH               strlen(SECURE_EMAIL_OID)


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

// MARK: Static functions...
static int getCertificateUPN(PCCERT_CONTEXT pcontext, scquery_result identityPtr)
{
  WCHAR namestring[256] = { 0 };
  
  if (false == CertGetNameString(pcontext, CERT_NAME_UPN_TYPE, 0, NULL, namestring, 256))
  {
    WLog_ERR(TAG, "NCryptOpenKey error getting upn: %d (0x%0X)\n", GetLastError(), GetLastError());
    identityPtr = NULL;
  }
  else if (0 == wcslen(namestring))
  {
    WLog_ERR(TAG, "NCryptOpenKey upn unavailable");
    identityPtr = NULL;
  }
  else
  {
    identityPtr->upn = malloc(wcslen(namestring)+1);
    memset(identityPtr->upn, 0, wcslen(namestring)+1);
    wcstombs(identityPtr->upn, namestring, wcslen(namestring));
    printf("UPN: %s\n", identityPtr->upn);
  }
  
  return ((NULL == identityPtr) ? -1 : 0);
}

static int validateSmartCardUsername(scquery_result identityPtr, rdpSettings *settings)
{
  if ((NULL != settings->Username) && (0 != strlen(settings->Username)))
  {
    char *upn      = _strdup(identityPtr->upn);
    char *username = _strdup(settings->Username);
    
    // Convert to lower case...
    _strlwr(upn);
    _strlwr(username);
    
    // Check username for at least a partial patch...
    char *resultptr = strstr(upn, username);
    
    // Free memory before continuing...
    free(upn);
    free(username);
    
    if (NULL == resultptr)
    {
      WLog_ERR(TAG, "username mismatch: %s vs. %s\n", settings->Username, identityPtr->upn);
      // No occurrance of requested partial username....
      return -1;
    }
    
    // We can use this certificate...
    WLog_INFO(TAG, "username match: %s vs. %s\n", settings->Username, identityPtr->upn);
  }
  
  return 0;
}

static int validateSmartCardUsage(PCCERT_CONTEXT pcontext, scquery_result identityPtr)
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
    // THe Enhanced Key Usage field contains the OID's that are valid
    // for a particular certificate...
    PCERT_ENHKEY_USAGE pusage = (PCERT_ENHKEY_USAGE)malloc(dusage);
    
    // ANY erroros will skip this certificate...
    if (NULL == pusage)
    {
      WLog_ERR(TAG, "CertGetEnhancedKeyUsage error allocating memory enhanced key usage data: %d (0x%0X)\n", GetLastError(), GetLastError());
      identityPtr = NULL;
    }
    else
    {
      BOOL  status = CertGetEnhancedKeyUsage(pcontext, flags, pusage, &dusage);
      DWORD errorcode = GetLastError(); // Could this in the if but wanted to ensure validity
      
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
        int    foundCount = 0;
        
        // At a minimu we're currently looking for 2:
        // SMART_CARD_LOGON_OID
        // CLIENT_AUTHENTICATION_OID
        // - otherwise fail...
        for (int index = 0; index < pusage->cUsageIdentifier; ++index)
        {
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

static int getAtrCardName(LPWSTR readerName, scquery_result identityPtr)
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
      
      // Some readers/cards seem to have the following embedded text: '(Identity Device)':
      // This creates a problem when passing the reader name via the RDP protocol so
      // the remote system knows which reader to use...
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
        // Need to remove the embedded text: '(Identity Device)':
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
          
          // Allocate and zero out the memory for the card name...
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

static int getCryptoCredentialForKeyName(LPWSTR keyname, LPWSTR *credential)
{
  NCRYPT_PROV_HANDLE phProvider;
  DWORD              certsize = 0;
  
  if (NULL == credential)
  {
    return 0;
  }
  *credential = NULL;
  
  // We're using the Cryptography API: Next Generation (CNG) family of functions
  // from Microsoft.  The previous generation of functions have been deprecated,
  // and according to MSDN documentation, the older generation could be removed
  // at the whim of Microsoft...
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

static DWORD getSmartCardReaders(LPWSTR *pReaderNames[])
{
  HRESULT           hr = S_OK;
  LPTSTR            szReaders = NULL;
  LPTSTR            szRdr = NULL;
  DWORD             cchReaders = SCARD_AUTOALLOCATE;
  DWORD             dwI = 0;
  DWORD             dwRdrCount = 0;
  SCARD_READERSTATE rgscState[MAXIMUM_SMARTCARD_READERS] = { 0 };
  SCARDCONTEXT      hSC = 0;
  LONG              lReturn;
  
  // Return a list of cmart cards reader(s) available...
  // We need a pointer passed in for the return array...
  if (NULL == pReaderNames)
  {
    WLog_ERR(TAG, "getSmartCardReaders: NULL input pointer\n");
  }
  else
  {
    // Establish a context.
    lReturn = SCardEstablishContext(SCARD_SCOPE_USER, NULL, NULL, &hSC);
    if (SCARD_S_SUCCESS != lReturn)
    {
      WLog_ERR(TAG, "getSmartCardReaders: Failed SCardEstablishContext\n");
    }
    else
    {
      // Determine which readers are available.
      lReturn = SCardListReaders(hSC, NULL, (LPTSTR)&szReaders, &cchReaders);
      if (SCARD_S_SUCCESS != lReturn)
      {
        WLog_ERR(TAG, "getSmartCardReaders: Failed SCardListReaders\n");
      }
      else
      {
        // Place the readers into the state array...
        // This is straight code from micrsoft - pretty crappy layout...
        // It seems the result is a contiguous array of characters that
        // include multiple reader names.  We have to break them up this way...
        szRdr = szReaders;
        for (dwI = 0; dwI < MAXIMUM_SMARTCARD_READERS; dwI++)
        {
          if (0 == *szRdr)
            break;
          rgscState[dwI].szReader = szRdr;
          rgscState[dwI].dwCurrentState = SCARD_STATE_UNAWARE;
          szRdr += lstrlen(szRdr) + 1;
        }
        dwRdrCount = dwI;
        
        // If any readers are available, proceed.
        if (0 != dwRdrCount)
        {
          *pReaderNames = malloc(sizeof(LPWSTR) * dwRdrCount);
          for (dwI = 0; dwI < dwRdrCount; ++dwI)
            (*pReaderNames)[dwI] = _wcsdup(rgscState[dwI].szReader);
        }
        else
        {
          WLog_ERR(TAG, "getSmartCardReaders: No readers available\n");
        }
        
        // Cleanup reader memory...
        SCardFreeMemory(hSC, szReaders);
        
        // Release the context.
        lReturn = SCardReleaseContext(hSC);
        if (SCARD_S_SUCCESS != lReturn)
        {
          WLog_ERR(TAG, "getSmartCardReaders: Failed SCardReleaseContext\n");
        }
      }
    }
  }
  
  return dwRdrCount;
}

// MARK: Global function definitions...
LPWSTR getMarshaledCredentials(char *keyname)
{
  CERT_CREDENTIAL_INFO certInfo = { sizeof(CERT_CREDENTIAL_INFO), { 0 } };
  HCRYPTPROV hProv;
  HCRYPTHASH hHash;
  DWORD dwHashLen = CERT_HASH_LENGTH;
  PBYTE certdata = NULL;
  LPTSTR szMarshaledCred = NULL;
  LPWSTR credentials = NULL;
  
  // TODO: This function uses the OLDER Crypto API from Microsoft.  These functions
  // have been deprecated by Microsoft, and this should be rewritten against the
  // newer one, Cryptography API: Next Generation (CNG)...
  // See the dicussion at this link for an explanation of a CNG equivalent solution:
  // https://docs.microsoft.com/en-us/windows/win32/seccng/creating-a-hash-with-cng
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

scquery_result getUserIdentityFromSmartcard(rdpSettings *settings)
{
  scquery_result  identityPtr = NULL;
  LPWSTR         *pReaderNames = NULL;
  DWORD           readerCount = 0;
  SECURITY_STATUS localstatus = ERROR_SUCCESS;
  
  // Obtain the FIRST reader name...
  readerCount = getSmartCardReaders(&pReaderNames);
  
  if (0 == readerCount)
  {
    WLog_ERR(TAG, "No smart card reader(s) available\n");
  }
  else
  {
    NCRYPT_PROV_HANDLE phProvider = 0;
    LPWSTR             cspname = NULL;
    
    // Generate the CSP name in wide character string...
    ConvertToUnicode(CP_UTF8, 0, settings->CspName, -1, &cspname, 0);
    
    SECURITY_STATUS status = NCryptOpenStorageProvider(&phProvider, cspname, 0);
    if (ERROR_SUCCESS != status)
    {
      WLog_ERR(TAG, "error opening provider: %s - error: %ld (0x%0X)\n", settings->CspName, status, status);
    }
    else
    {
      for (int index = 0; ((index < readerCount) && (NULL == identityPtr)); ++index)
      {
        WCHAR              szScope[256];
        NCryptKeyName     *ppKeyName = NULL;
        PVOID              ppEnumState = NULL;
        DWORD              idxcount = 0;
        scquery_result_t   localIdentity;
        LPWSTR             readerName = pReaderNames[index];
        
        // Create the windows reader name string to scope the results...
        {
          int length = swprintf_s(szScope, 256, L"\\\\.\\");
          wcscpy_s(&szScope[length], 256-length, readerName);
          length = wcslen(szScope);
          szScope[length] = '\\';
          szScope[length + 1] = '\0';
        }
        
        // DEBUG...
        //if (WLog_IsLevelActive(WLog_Get(TAG), WLOG_DEBUG))
        {
          int length = wcslen(szScope);
          char *tmpReaderName = malloc(length+1);
          wcstombs(tmpReaderName, szScope, length);
          tmpReaderName[length] = '\0';
          WLog_DBG(TAG, "enumerating provider: %s @reader: %d -> %s\n", settings->CspName, length, tmpReaderName);
          printf("enumerating provider: %s @reader: %d -> %s\n", settings->CspName, length, tmpReaderName);
          free(tmpReaderName);
        }
        
        while (ERROR_SUCCESS == NCryptEnumKeys(phProvider, szScope, &ppKeyName, &ppEnumState, 0))
        {
          printf("name: %S algorithm: %S keySpec: %ld (0x%X) flags: %ld\n",
                 ppKeyName->pszName, ppKeyName->pszAlgid, ppKeyName->dwLegacyKeySpec, (unsigned int)ppKeyName->dwLegacyKeySpec, ppKeyName->dwFlags);
          
          NCRYPT_KEY_HANDLE  phKey;
          DWORD              dwFlags = 0;
          
          status = NCryptOpenKey(phProvider, &phKey, ppKeyName->pszName, ppKeyName->dwLegacyKeySpec, dwFlags);
          
          if (ERROR_SUCCESS != status)
          {
            WLog_ERR(TAG, "NCryptOpenKey error: %ld (0x%0X)\n", status, (unsigned int)status);
            scquery_result_free(identityPtr);
            identityPtr = NULL;
            continue;
          }
          else
          {
            identityPtr = malloc(sizeof(scquery_result_t));
            memset(identityPtr, 0, sizeof(scquery_result_t));
            
            identityPtr->certificate = malloc(sizeof(smartcard_certificate_t));
            memset(identityPtr->certificate, 0, sizeof(smartcard_certificate_t));
            
            // Container name...
            identityPtr->certificate->id = malloc(wcslen(ppKeyName->pszName)+1);
            memset(identityPtr->certificate->id, 0, wcslen(ppKeyName->pszName)+1);
            wcstombs(identityPtr->certificate->id, ppKeyName->pszName, wcslen(ppKeyName->pszName));
            
            // Slot ID...
            identityPtr->certificate->slot_id = idxcount;
            identityPtr->certificate->type = CKC_X_509;
            
            // Reader name...
            identityPtr->certificate->slot_description = calloc(wcslen(readerName)+1, sizeof(char));
            memset(identityPtr->certificate->slot_description, 0, wcslen(readerName)+1);
            wcstombs(identityPtr->certificate->slot_description, readerName, wcslen(readerName));
            
            {
              DWORD   cbOutput = 256;
              DWORD   dwFlags = 0;
              
              status = NCryptGetProperty(phKey, NCRYPT_CERTIFICATE_PROPERTY, NULL, 0, &cbOutput, dwFlags);
              PBYTE    pbOutput = (PBYTE)malloc(cbOutput);
              status = NCryptGetProperty(phKey, NCRYPT_CERTIFICATE_PROPERTY, pbOutput, cbOutput, &cbOutput, dwFlags);
              
              if (ERROR_SUCCESS != status)
              {
                WLog_ERR(TAG, "NCryptGetProperty (%S) error: %ld (0x%0X)\n", NCRYPT_CERTIFICATE_PROPERTY, status, (unsigned int)status);
              }
              else
              {
                {
                  // Get card name...
                  if (-1 == getAtrCardName(readerName, identityPtr))
                  {
                    scquery_result_free(identityPtr);
                    identityPtr = NULL;
                    continue;
                  }
                  
                  PCCERT_CONTEXT pcontext = CertCreateCertificateContext(PKCS_7_ASN_ENCODING | X509_ASN_ENCODING, pbOutput, cbOutput);
                  if (NULL == pcontext)
                  {
                    WLog_ERR(TAG, "CertCreateCertificateContext error: %ld (0x%0X)\n", GetLastError(), (unsigned int)GetLastError());
                    printf("CertCreateCertificateContext error: %ld (0x%0X)\n", GetLastError(), (unsigned int)GetLastError());
                    scquery_result_free(identityPtr);
                    identityPtr = NULL;
                    continue;
                  }
                  else
                  {
                    // Need to first ascertain whether this certificate is allowed for
                    // authentication/smart card logon...
                    if (-1 == validateSmartCardUsage(pcontext, identityPtr))
                    {
                      scquery_result_free(identityPtr);
                      identityPtr = NULL;
                      continue;
                    }
                    
                    // Check requested username agaisnt UPN...
                    // TODO: We should also consider implementing checking the username
                    // against the associated Container Name (CN) fields within the X509
                    // string...

                    // Get UPN (User Principal Name)...need the certificate for this...
                    if (-1 == getCertificateUPN(pcontext, identityPtr))
                    {
                      // Absent or invalid UPN as an error ONLY if we're requesting a particular
                      // username sequence...
                      if ((NULL == settings->Username) || (0 != strlen(settings->Username)))
                      {
                        scquery_result_free(identityPtr);
                        identityPtr = NULL;
                        continue;
                      }
                      
                      // Otherwise...
                      WLog_INFO(TAG, "continuing withot UPN\n");
                    }
                    else
                    {
                      if (-1 == validateSmartCardUsername(identityPtr, settings))
                      {
                        WLog_ERR(TAG, "username mismatch: %s vs. %s\n", settings->Username, identityPtr->upn);
                        // No occurrance of requested partial username....
                        scquery_result_free(identityPtr);
                        identityPtr = NULL;
                        continue;
                      }
                      
                      // We can use this certificate...
                      WLog_INFO(TAG, "username match: %s vs. %s\n", settings->Username, identityPtr->upn);
                    }
                    
                    // X500 name string (X509 compatible???)...
                    // TODO: We should also consider implementing checking the username
                    // against the associated Container Name (CN) fields within the X509
                    // string...
                    // NOTE: A section of code from Pascal's original implementation against
                    // PKCS11 was also extracting this - but I don't see anywhere within
                    // his FreeRDP implementation that actually needed this.  If the X509
                    // string is never used at some point in the future then we could just
                    // remove this section, but since it's all working I am not going to
                    // fiddle with it...
                    {
                      WCHAR namestring[256] = { 0 };
                      CERT_NAME_BLOB nameblob = { pcontext->pCertInfo->Subject.cbData, pcontext->pCertInfo->Subject.pbData };
                      DWORD converted = CertNameToStr(X509_ASN_ENCODING, &nameblob, CERT_X500_NAME_STR | CERT_NAME_STR_REVERSE_FLAG, namestring, 256);
                      if (0 == converted)
                      {
                        WLog_ERR(TAG, "X500 name error (CERT_X500_NAME_STR): %d (0x%0X)\n", GetLastError(), GetLastError());
                        scquery_result_free(identityPtr);
                        identityPtr = NULL;
                        continue;
                      }
                      else
                      {
                        printf("X500 name: %ld string: %S\n", converted, namestring);
                        identityPtr->X509_user_identity = calloc(wcslen(namestring)+1, sizeof(char));
                        memset(identityPtr->X509_user_identity, 0, wcslen(namestring)+1);
                        wcstombs(identityPtr->X509_user_identity, namestring, wcslen(namestring));
                      }
                    }
                    
                    // Certificate serial...
                    identityPtr->certificate->token_serial = reversePropertyValue(pcontext->pCertInfo->SerialNumber.cbData, pcontext->pCertInfo->SerialNumber.pbData);
                    printf("cert info serial: %ld - ", pcontext->pCertInfo->SerialNumber.cbData);
                    dumpPropertyValue(pcontext->pCertInfo->SerialNumber.cbData, identityPtr->certificate->token_serial);
                  }
                }
              }
              
              // Free the buffer...
              free(pbOutput);
            }
            
            // Cleanup...
            NCryptFreeObject(phKey);
            
            // Cleanup...
            NCryptFreeBuffer(ppKeyName);
          }
          
          // Post index...
          ++idxcount;
          
          // Done..while loop for keys on card...
          if (NULL != (identityPtr))
            break;
        }
        
        // While key enum state cleanup...
        NCryptFreeBuffer(ppEnumState);
      }
    }
    
    // Cleanup
    NCryptFreeObject(phProvider);
    for (int index = 0; index < readerCount; ++index)
      free(pReaderNames[index]);
    free(pReaderNames);
    free(cspname);
  }
  
  return identityPtr;
}

#endif

