#include <freerdp/log.h>
#include <freerdp/settings.h>
#include <wincrypt.h>
#include <WinCred.h>
#include <WinScard.h>

//#include "../scquery/scquery.h"
//#include "../scquery/scquery_error.h"
//#include "certificate.h"
#include <pkcs11-helper-1.0/pkcs11.h>

typedef void* buffer;

typedef struct
{
  CK_SLOT_ID          slot_id;
  char*               slot_description; /* ReaderName */
  char*               token_label;      /* CardName */
  char*               token_serial;
  char*               id;
  char*               label;
  CK_CERTIFICATE_TYPE type;
  buffer              issuer;
  buffer              subject;
  buffer              value;
  CK_KEY_TYPE         key_type;
  int                 protected_authentication_path;
} smartcard_certificate_t, *smartcard_certificate;

typedef struct
{
  smartcard_certificate  certificate;
  char*  X509_user_identity; /* kinit -X X509_user_identity value */
  char*  upn;
} scquery_result_t, *scquery_result;

typedef struct
{
  CK_ULONG flags;
  CK_ULONG size;
  CK_BYTE* data;
} buffer_t;

enum
{
  buffer_flag_allocated = (1 << 0)
};

void buffer_free(buffer buf)
{
  buffer_t* buffer = buf;
  
  if (buffer == NULL)
  {
    return;
  }
  
  if (buffer->flags & buffer_flag_allocated)
  {
    memset(buffer->data, 0, buffer->size);
    free(buffer->data);
  }
  
  memset(buffer, 0, sizeof(*buffer));
  free(buffer);
}

void scquery_certificate_free(smartcard_certificate certificate)
{
  free(certificate);
}

void scquery_certificate_deepfree(smartcard_certificate certificate)
{
  if (certificate)
  {
    free(certificate->slot_description);
    free(certificate->token_label);
    free(certificate->token_serial);
    free(certificate->id);
    free(certificate->label);
    buffer_free(certificate->issuer);
    buffer_free(certificate->subject);
    buffer_free(certificate->value);
    scquery_certificate_free(certificate);
  }
}

void  scquery_result_free(scquery_result that)
{
  if (that)
  {
    scquery_certificate_deepfree(that->certificate);
    free(that->X509_user_identity);
    free(that->upn);
    free(that);
  }
}

/* out_of_memory
 handles the out of memory error (when malloc returns NULL).
 It may not return, or it should return a pointer returned
 untouched by the caller.
 */
typedef void* (*out_of_memory_handler)(size_t size);
out_of_memory_handler handle_out_of_memory;

void* check_memory(void* memory, size_t size)
{
  return memory
  ? memory
  : handle_out_of_memory(size);
}

#define TAG CLIENT_TAG("smartcardlogon")
#define ORNIL(x)  ((x)?(x):"(nil)")

#if defined(WITH_SMARTCARD_LOGON) && defined(_WIN32)
extern PCHAR reversePropertyValue(int cbData, void* pvData);
extern void dumpPropertyValue(int cbData, void *pvData);
#endif

static void copy_string(char** old_string, char* new_string)
{
	free(*old_string);
	(*old_string) = NULL;

	if (new_string != NULL)
	{
		(*old_string) = check_memory(strdup(new_string), strlen(new_string));
	}
}

#if defined(WITH_SMARTCARD_LOGON) && defined(_WIN32)
HRESULT __cdecl LocateReader(LPWSTR *pReaderName)
{
    HRESULT           hr = S_OK;
    LPTSTR            szReaders = NULL;
	LPTSTR            szRdr = NULL;
    DWORD             cchReaders = SCARD_AUTOALLOCATE;
    DWORD             dwI, dwRdrCount;
    SCARD_READERSTATE rgscState[MAXIMUM_SMARTCARD_READERS] = { 0 };
    SCARDCONTEXT      hSC = 0;
    LONG              lReturn;

	// We need a pointer...
	if (NULL == pReaderName)
	{
		WLog_ERR(TAG, "LocateReader: reader name return pointer is NULL\n");
        return(1);
	}
	*pReaderName = NULL;
	
    // Establish the card to watch for.
    // Multiple cards can be looked for, but
    // We look for only the first card reader. 

    // Establish a context.
    lReturn = SCardEstablishContext(SCARD_SCOPE_USER, NULL, NULL, &hSC);
    if (SCARD_S_SUCCESS != lReturn)
    {
		WLog_ERR(TAG, "LocateReader: Failed SCardEstablishContext\n");
        return(1);
    }

    // Determine which readers are available.
    lReturn = SCardListReaders(hSC, NULL, (LPTSTR)&szReaders, &cchReaders);
    if (SCARD_S_SUCCESS != lReturn)
    {
		WLog_ERR(TAG, "LocateReader: Failed SCardListReaders\n");
        return(1);
    }

    // Place the readers into the state array.
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
		*pReaderName = _wcsdup(rgscState[0].szReader);
    }
    else
    {
		WLog_ERR(TAG, "LocateReader: No readers available\n");
    }

	// Cleanup reader memory...
    SCardFreeMemory(hSC, szReaders);

    // Release the context.
    lReturn = SCardReleaseContext(hSC);
    if (SCARD_S_SUCCESS != lReturn)
    {
        printf("Failed SCardReleaseContext\n");
		WLog_ERR(TAG, "LocateReader: Failed SCardReleaseContext\n");
    }

    return hr;
}

static scquery_result getUserIdentityFromSmartcard(rdpSettings *settings)
{
	scquery_result identity = NULL;
	LPWSTR         readerName = NULL;

	// Obtain the FIRST reader name...
	LocateReader(&readerName);
	
	if (NULL == readerName)
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
			WCHAR              szScope[256];
			NCryptKeyName     *ppKeyName = NULL;
			PVOID              ppEnumState = NULL;
			DWORD              idxcount = 0;

			// Create the windows reader name string to scope the results...
			{
				int length = swprintf_s(szScope, 256, L"\\\\.\\");
				wcscpy_s(&szScope[length], 256-length, readerName);
				length = wcslen(szScope);
				szScope[length] = '\\';
				szScope[length + 1] = '\0';
			}

			// DEBUG...
			if (WLog_IsLevelActive(WLog_Get(TAG), WLOG_DEBUG))
			{
				int length = wcslen(szScope);
				char *tmpReaderName = malloc(length+1);
				wcstombs(tmpReaderName, szScope, length);
				tmpReaderName[length] = '\0';
				WLog_DBG(TAG, "enumerating provider: %s @reader: %d -> %s\n", settings->CspName, length, tmpReaderName);
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
					scquery_result_free(identity);
					identity = NULL;
					break;
				}
				else
				{
					identity = malloc(sizeof(scquery_result_t));
					memset(identity, 0, sizeof(scquery_result_t));

					identity->certificate = malloc(sizeof(smartcard_certificate_t));
					memset(identity->certificate, 0, sizeof(smartcard_certificate_t));

					// Container name...
					identity->certificate->id = malloc(wcslen(ppKeyName->pszName)+1);
					memset(identity->certificate->id, 0, wcslen(ppKeyName->pszName)+1);
					wcstombs(identity->certificate->id, ppKeyName->pszName, wcslen(ppKeyName->pszName));

					// Slot ID...
					identity->certificate->slot_id = idxcount;
					identity->certificate->type = CKC_X_509;
					
					// Reader name...
					identity->certificate->slot_description = calloc(wcslen(readerName)+1, sizeof(char));
					memset(identity->certificate->slot_description, 0, wcslen(readerName)+1);
					wcstombs(identity->certificate->slot_description, readerName, wcslen(readerName));
									
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
								{
									LONG         status = 0;
									SCARDCONTEXT scContext = 0;

									status = SCardEstablishContext(SCARD_SCOPE_USER, NULL, NULL, &scContext);

									if (0 == scContext)
									{
										WLog_ERR(TAG, "SCardEstablishContext error: %ld (0x%0X)\n", status, (unsigned int)status);
										printf("SCardEstablishContext error: %ld (0x%0X)\n", status, (unsigned int)status);
										scquery_result_free(identity);
										identity = NULL;
										SCardReleaseContext(scContext);
										break;
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
											scquery_result_free(identity);
											identity = NULL;
											SCardReleaseContext(scContext);
											break;
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
											scquery_result_free(identity);
											identity = NULL;
											SCardDisconnect(scContext, SCARD_LEAVE_CARD);
											SCardReleaseContext(scContext);
											break;
										}

										wchar_t atrname[256] = { 0 };
										cbLength = 256;
										
										// This gets the card name for the ATR string...
										status = SCardListCards(scContext, atrstring, NULL, 0, atrname, &cbLength);
										if (ERROR_SUCCESS != status)
										{
											WLog_ERR(TAG, "SCardListCards error: %ld (0x%0X)\n", status, (unsigned int)status);
											printf("SCardListCards error: %ld (0x%0X)\n", status, (unsigned int)status);
											scquery_result_free(identity);
											identity = NULL;
											SCardDisconnect(scContext, SCARD_LEAVE_CARD);
											SCardReleaseContext(scContext);
											break;
										}
										else
										{
											printf("ATR name: %ld -> %S\n", cbLength, atrname);
											if (0 != wcsncmp(atrname, L"Identity Device", wcslen(L"Identity Device")))
											{
												// Allocate and azero out the memory for the card name...
												identity->certificate->token_label = (char*)malloc(cbLength+1);
												memset(identity->certificate->token_label, 0, cbLength+1);
												
												// Convert to char string...
												wcstombs(identity->certificate->token_label, atrname, cbLength);
												WLog_DBG(TAG, "Card name: %ld -> %s\n", cbLength, identity->certificate->token_label);
												printf("Card name: %ld -> %s\n", cbLength, identity->certificate->token_label);
											}
											else
											{
												wchar_t* pos1 = wcschr(atrname, '(');
												wchar_t* pos2 = wcschr(atrname, ')');
												if ((NULL == pos1) || (NULL == pos2))
												{
													WLog_ERR(TAG, "card name error: %ld (0x%0X)\n", GetLastError(), (unsigned int)GetLastError());
													printf("card name error: %ld (0x%0X)\n", GetLastError(), (unsigned int)GetLastError());
													scquery_result_free(identity);
													identity = NULL;
													SCardDisconnect(scContext, SCARD_LEAVE_CARD);
													SCardReleaseContext(scContext);
                                                    break;
												}
												else
												{
													const int size = pos2 - pos1;
													
													// Allocate and azero out the memory for the card name...
													identity->certificate->token_label = (char*)calloc(size + 1, sizeof(char));
													memset(identity->certificate->token_label, 0, (size + 1) * sizeof(char));
													
													// Null terminate at ')' position...
													*pos2 = '\0';
													
													// Convert to char string...
													wcstombs(identity->certificate->token_label, pos1 + 1, size-1);
													WLog_DBG(TAG, "Card name: %d -> %s\n", size, identity->certificate->token_label);
													printf("Card name: %d -> %s\n", size, identity->certificate->token_label);
												}
											}
										}
									
										// Cleanup...
										SCardDisconnect(scContext, SCARD_LEAVE_CARD);
										SCardReleaseContext(scContext);
									}
								}

								PCCERT_CONTEXT pcontext = CertCreateCertificateContext(PKCS_7_ASN_ENCODING | X509_ASN_ENCODING, pbOutput, cbOutput);
								if (NULL == pcontext)
								{
									WLog_ERR(TAG, "CertCreateCertificateContext error: %ld (0x%0X)\n", GetLastError(), (unsigned int)GetLastError());
									printf("CertCreateCertificateContext error: %ld (0x%0X)\n", GetLastError(), (unsigned int)GetLastError());
									scquery_result_free(identity);
									identity = NULL;
									break;
								}
								else
								{
									// Need to first ascertain whether this certificate is allowed for authentication/smart card logon...
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
												scquery_result_free(identity);
												identity = NULL;
												break;
											}
											else
											{
												BOOL status = CertGetEnhancedKeyUsage(pcontext, flags, pusage, &dusage);
												DWORD errorcode = GetLastError();
												
												if ((FALSE == status) && (CRYPT_E_NOT_FOUND != errorcode))
												{
													WLog_ERR(TAG, "CertGetEnhancedKeyUsage error getting enhanced key usage data: %d (0x%0X)\n", GetLastError(), GetLastError());
													scquery_result_free(identity);
													identity = NULL;
													free(pusage);
													break;
												}
												else if ((0 == pusage->cUsageIdentifier) && (CRYPT_E_NOT_FOUND != errorcode))
												{
													WLog_ERR(TAG, "CertGetEnhancedKeyUsage(pusage->cUsageIdentifier == 0) error: %d (0x%0X)\n", GetLastError(), GetLastError());
													scquery_result_free(identity);
													identity = NULL;
													free(pusage);
													break;
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
													
													if (2 != foundCount)
													{
														WLog_ERR(TAG, "CertGetEnhancedKeyUsage(Authentication/Smart Card Logon certificate not found)\n");
														scquery_result_free(identity);
														identity = NULL;
														free(pusage);
														break;
													}
												}
											}
										
											// Cleanup...
											free(pusage);
										}
									}

									// Get UPN (User Principal Name)...need the certificate for this...
									WCHAR namestring[256] = { 0 };

									if (false == CertGetNameString(pcontext, CERT_NAME_UPN_TYPE, 0, NULL, namestring, 256))
									{
										WLog_ERR(TAG, "NCryptOpenKey error getting upn: %d (0x%0X)\n", GetLastError(), GetLastError());
#if 0
										scquery_result_free(identity);
										identity = NULL;
										break;
#endif
									}
									else if (0 == wcslen(namestring))
									{
										WLog_ERR(TAG, "NCryptOpenKey upn unavailable");
#if 0
										scquery_result_free(identity);
										identity = NULL;
										break;
#endif
									}
									else
									{
										identity->upn = malloc(wcslen(namestring)+1);
										memset(identity->upn, 0, wcslen(namestring)+1);
										wcstombs(identity->upn, namestring, wcslen(namestring));
										printf("UPN: %s\n", identity->upn);
									}

									// X500 name string (X509 compatible???)...
									{
                                        CERT_NAME_BLOB nameblob = { pcontext->pCertInfo->Subject.cbData, pcontext->pCertInfo->Subject.pbData };
										DWORD converted = CertNameToStr(X509_ASN_ENCODING, &nameblob, CERT_X500_NAME_STR | CERT_NAME_STR_REVERSE_FLAG, namestring, 256);
										if (0 == converted)
										{
											WLog_ERR(TAG, "X500 name error (CERT_X500_NAME_STR): %d (0x%0X)\n", GetLastError(), GetLastError());
											scquery_result_free(identity);
											identity = NULL;
											break;
										}
										else
										{
											printf("X500 name: %ld string: %S\n", converted, namestring);
											identity->X509_user_identity = calloc(wcslen(namestring)+1, sizeof(char));
											memset(identity->X509_user_identity, 0, wcslen(namestring)+1);
											wcstombs(identity->X509_user_identity, namestring, wcslen(namestring));
										}
									}

									// Certificate serial...
									identity->certificate->token_serial = reversePropertyValue(pcontext->pCertInfo->SerialNumber.cbData, pcontext->pCertInfo->SerialNumber.pbData);
									printf("cert info serial: %ld - ", pcontext->pCertInfo->SerialNumber.cbData);
									dumpPropertyValue(pcontext->pCertInfo->SerialNumber.cbData, identity->certificate->token_serial);
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
					
				// Done..
				if (NULL != identity)
					break;
			}
			
			NCryptFreeBuffer(ppEnumState);
		}
		
		// Cleanup
		NCryptFreeObject(phProvider);
		free(readerName);
		free(cspname);
	}

	return identity;
}
#endif

int get_info_smartcard(rdpSettings* settings)
{
	scquery_result identity = NULL;

#if defined(WITH_PKCS11H) && defined(WITH_GSSAPI)
    if (settings->Pkcs11Module == NULL)
    {
        WLog_ERR(TAG, "Missing /pkcs11module");
        return -1;
    }
    
    settings->Krb5Trace = true;
	identity = scquery_X509_user_identities(settings->Pkcs11Module,
		settings->ReaderName,
		settings->CardName,
		settings->Krb5Trace);
#elif defined(WITH_SMARTCARD_LOGON) && defined(_WIN32)
    // Default the Cryptographic Service Provider if none specified...
    if (NULL == settings->CspName)
    {
        settings->CspName = strdup(MS_SCARD_PROV_A);
    }

    // Attempt to read an identity from the smart card...
    identity = getUserIdentityFromSmartcard(settings);
#endif

	if (identity == NULL)
	{
		WLog_ERR(TAG, "Could not get an identity from the smartcard %s (reader %s)",
			ORNIL(settings->CardName),
			ORNIL(settings->ReaderName));
		return -1;
	}

	copy_string(&settings->CardName,          identity->certificate->token_label);
	copy_string(&settings->ReaderName,        identity->certificate->slot_description);
	copy_string(&settings->UserPrincipalName, identity->upn);
	copy_string(&settings->PkinitIdentity, 	  identity->X509_user_identity);
	copy_string(&settings->TokenLabel,    	  identity->certificate->token_label);
	copy_string(&settings->IdCertificate, 	  identity->certificate->id);
	settings->IdCertificateLength = strlen(settings->IdCertificate);
	settings->SlotID = identity->certificate->slot_id;
	settings->PinPadIsPresent = identity->certificate->protected_authentication_path;

	WLog_INFO(TAG, "Got identity from the smartcard %s (reader %s): %s (UPN = %s) Length: %d Slot: %ld CertID: %s",
		ORNIL(settings->CardName),
		ORNIL(settings->ReaderName),
		identity->X509_user_identity,
		identity->upn, settings->IdCertificateLength, settings->SlotID, settings->IdCertificate);
	scquery_result_free(identity);
	return 0;
}
