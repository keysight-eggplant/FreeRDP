#ifndef LIBFREERDP_CORE_SMARTCARDLOGON_H
#define LIBFREERDP_CORE_SMARTCARDLOGON_H
#include <freerdp/settings.h>
//#include "../scquery/scquery.h"
//#include "../scquery/scquery_error.h"
//#include "certificate.h"
#include <pkcs11-helper-1.0/pkcs11.h>

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

int get_info_smartcard(rdpSettings* settings);

#endif
