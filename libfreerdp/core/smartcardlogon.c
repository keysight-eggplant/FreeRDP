#include "smartcardlogon.h"
#include <freerdp/log.h>
#include <freerdp/settings.h>

//#include "../scquery/scquery.h"
//#include "../scquery/scquery_error.h"
//#include "certificate.h"
#include <pkcs11-helper-1.0/pkcs11.h>

#if defined(WITH_SMARTCARD_LOGON) && defined(_WIN32)
#include "smartcard-windows.h"
#endif

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

void  scquery_result_free_parts(scquery_result that)
{
	if (that)
	{
		scquery_certificate_deepfree(that->certificate);
		free(that->X509_user_identity);
		free(that->upn);
	}
}

void  scquery_result_free(scquery_result that)
{
  if (that)
  {
    scquery_result_free_parts(that);
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

int get_info_smartcard(rdpSettings* settings)
{
	scquery_result identityPtr = NULL;

#if defined(WITH_PKCS11H) && defined(WITH_GSSAPI)
    if (settings->Pkcs11Module == NULL)
    {
        WLog_ERR(TAG, "Missing /pkcs11module");
        return -1;
    }
    
	settings->Krb5Trace = true;
	identityPtr = scquery_X509_user_identities(settings->Pkcs11Module,
		settings->ReaderName,
		settings->CardName,
		settings->Krb5Trace);
#elif defined(WITH_SMARTCARD_LOGON) && defined(_WIN32)
	// Default the Cryptographic Service Provider if none specified...
	if (NULL == settings->CspName)
	{
		settings->CspName = strdup(MS_SCARD_PROV_A);
	}

	// Attempt to read an (identityPtr) from the smart card...
	identityPtr = getUserIdentityFromSmartcard(settings);
#endif

	if (identityPtr == NULL)
	{
		WLog_ERR(TAG, "Could not get an identity from the smartcard %s (reader %s)",
			ORNIL(settings->CardName),
			ORNIL(settings->ReaderName));
		return -1;
	}

	copy_string(&settings->CardName,          identityPtr->certificate->token_label);
	copy_string(&settings->ReaderName,        identityPtr->certificate->slot_description);
	copy_string(&settings->UserPrincipalName, identityPtr->upn);
	copy_string(&settings->PkinitIdentity, 	  identityPtr->X509_user_identity);
	copy_string(&settings->TokenLabel,    	  identityPtr->certificate->token_label);
	copy_string(&settings->IdCertificate, 	  identityPtr->certificate->id);
	settings->IdCertificateLength = strlen(settings->IdCertificate);
	settings->SlotID = identityPtr->certificate->slot_id;
	settings->PinPadIsPresent = identityPtr->certificate->protected_authentication_path;

	WLog_INFO(TAG, "Got identity from the smartcard %s (reader %s): %s (UPN = %s) Length: %d Slot: %ld CertID: %s",
		ORNIL(settings->CardName),
		ORNIL(settings->ReaderName),
		identityPtr->X509_user_identity,
		identityPtr->upn, settings->IdCertificateLength, settings->SlotID, settings->IdCertificate);
	
	// Cleanup identity memory allocated...
	scquery_result_free(identityPtr);
	
	return 0;
}
