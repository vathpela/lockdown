#ifndef _LOCKDOWN_PKCS7_H
#define _LOCKDOWN_PKCS7_H

#include <seccomon.h>

extern void
build_timestamp(const char *timestr, EFI_TIME *timestamp);

extern void
build_authenticated_attributes(SECItem *output, SECItem *data,
			       EFI_TIME *timestamp);

extern void
build_pkcs7(SECItem *output, SECItem *cert, SECItem *signature,
	    SECItem *authattr);

#endif /* _LOCKDOWN_PKCS7_H */
