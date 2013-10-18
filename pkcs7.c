
#define _XOPEN_SOURCE

#include <efi.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <time.h>
#include <unistd.h>

#include "pkcs7.h"

#include <prerror.h>
#include <nss.h>
#include <cert.h>
#include <pk11pub.h>
#include <secasn1t.h>
#include <secasn1.h>
#include <secerr.h>
#include <secoidt.h>
#include <secoid.h>

static int
__attribute__ ((unused))
content_is_empty(uint8_t *data, ssize_t len)
{
	if (len < 1)
		return 1;

	for (int i = 0; i < len; i++)
		if (data[i] != 0)
			return 0;
	return 1;
}

typedef struct {
	SECItem one;
	SECItem two;
} tuple;

static SEC_ASN1Template TupleTemplate[] = {
	{.kind = SEC_ASN1_SEQUENCE,
	 .offset = 0,
	 .sub = NULL,
	 .size = 0,
	},
	{.kind = SEC_ASN1_ANY,
	 .offset = offsetof(tuple, one),
	 .sub = &SEC_AnyTemplate,
	 .size = sizeof (SECItem),
	},
	{.kind = SEC_ASN1_ANY,
	 .offset = offsetof(tuple, two),
	 .sub = &SEC_AnyTemplate,
	 .size = sizeof (SECItem),
	},
	{ 0 }
};

static void
generate_tuple(SECItem *output, SECItem *one, SECItem *two)
{
	tuple t;

	memcpy(&t.one, one, sizeof(t.one));
	memcpy(&t.two, two, sizeof(t.two));

	void *ret;
	ret = SEC_ASN1EncodeItem(NULL, output, &t, TupleTemplate);
	if (ret == NULL) {
		fprintf(stderr, "assemble: could not encode data\n");
		exit(1);
	}

}

static SEC_ASN1Template SetTemplate = {
	.kind = SEC_ASN1_SET_OF,
	.offset = 0,
	.sub = &SEC_AnyTemplate,
	.size = sizeof (SECItem **)
	};

static void
wrap_in_set(SECItem *der, SECItem **items)
{
	void *ret;

	ret = SEC_ASN1EncodeItem(NULL, der, &items, &SetTemplate);
	if (ret == NULL) {
		fprintf(stderr, "assemble: could not encode data\n");
		exit(1);
	}
}

static SEC_ASN1Template SeqTemplateTemplate = {
	.kind = SEC_ASN1_ANY,
	.offset = 0,
	.sub = &SEC_AnyTemplate,
	.size = sizeof (SECItem),
	};

static SEC_ASN1Template SeqTemplateHeader = {
	.kind = SEC_ASN1_SEQUENCE,
	.offset = 0,
	.sub = NULL,
	.size = sizeof (SECItem)
	};

static void __attribute__((unused))
wrap_in_seq(SECItem *der, SECItem *items, int num_items)
{
	void *ret;

	SEC_ASN1Template tmpl[num_items+2];

	memcpy(&tmpl[0], &SeqTemplateHeader, sizeof(*tmpl));
	tmpl[0].size = sizeof (SECItem) * num_items;

	for (int i = 0; i < num_items; i++) {
		memcpy(&tmpl[i+1], &SeqTemplateTemplate, sizeof(SEC_ASN1Template));
		tmpl[i+1].offset = (i) * sizeof (SECItem);
	}
	memset(&tmpl[num_items + 1], '\0', sizeof(SEC_ASN1Template));

	ret = SEC_ASN1EncodeItem(NULL, der, items, tmpl);
	if (ret == NULL) {
		fprintf(stderr, "assemble: could not encode data\n");
		exit(1);
	}
}

void
build_timestamp(const char *timestr, EFI_TIME *timestamp)
{
	struct tm tm;
	char *leftover;

	if (timestr == NULL) {
		time_t t;
		struct tm *tmp;
		time(&t);
		tmp = gmtime(&t);
		memcpy(&tm, tmp, sizeof (tm));
	} else {
		leftover = strptime(timestr, "%c", &tm);
		if (leftover == NULL) {
			fprintf(stderr, "buildvar: could not parse timestamp: "
					"%m\n");
			exit(1);
		}
	}

	timestamp->Year = tm.tm_year + 1900;
	timestamp->Month = tm.tm_mon;
	timestamp->Day = tm.tm_mday;
	timestamp->Hour = tm.tm_hour;
	timestamp->Minute = tm.tm_min;
	timestamp->Second = tm.tm_sec;
}

static void
generate_octet_string(SECItem *encoded, SECItem *original)
{
	if (content_is_empty(original->data, original->len)) {
		fprintf(stderr, "data is empty, not encoding\n");
		exit(1);
	}
	if (SEC_ASN1EncodeItem(NULL, encoded, original,
			SEC_OctetStringTemplate) == NULL) {
		fprintf(stderr, "could not encode octet string\n");
		exit(1);
	}
}

static void __attribute__((unused))
generate_object_id(SECItem *der, SECOidTag tag)
{
	SECOidData *oid;

	oid = SECOID_FindOIDByTag(tag);
	if (!oid) {
		fprintf(stderr, "assemble: could not find OID\n");
		exit(1);
	}

	void *ret;
	ret = SEC_ASN1EncodeItem(NULL, der, &oid->oid,
						SEC_ObjectIDTemplate);
	if (ret == NULL) {
		fprintf(stderr, "assemble: could not encode OID\n");
		exit(1);
	}
}

static SEC_ASN1Template IntegerTemplate[] = {
	{.kind = SEC_ASN1_INTEGER,
	 .offset = 0,
	 .sub = NULL,
	 .size = sizeof(long),
	},
	{ 0 },
};

static void
generate_integer(SECItem *der, unsigned long integer, int bytes)
{
	void *ret;

	uint32_t u32;

	SECItem input = {
		.data = (void *)&integer,
		.len = sizeof(integer),
		.type = siUnsignedInteger,
	};

	if (integer < 0x100000000) {
		u32 = integer & 0xffffffffUL;
		input.data = (void *)&u32;
		input.len = sizeof(u32);
	}
	if (bytes < input.len)
		input.len = bytes;

	ret = SEC_ASN1EncodeItem(NULL, der, &input, IntegerTemplate);
	if (ret == NULL) {
		fprintf(stderr, "assemble: could not encode data\n");
		exit(1);
	}
}

static SEC_ASN1Template ContextSpecificSequence[] = {
	{
	.kind = SEC_ASN1_CONTEXT_SPECIFIC | SEC_ASN1_EXPLICIT,
	.offset = 0,
	.sub = &SEC_AnyTemplate,
	.size = sizeof (SECItem),
	},
	{ 0 }
};

static void
make_context_specific(int ctxt, SECItem *encoded, SECItem *original)
{
	void *rv;
	ContextSpecificSequence[0].kind = SEC_ASN1_EXPLICIT |
					  SEC_ASN1_CONTEXT_SPECIFIC | ctxt;

	rv = SEC_ASN1EncodeItem(NULL, encoded, original,
				ContextSpecificSequence);
	if (rv == NULL) {
		fprintf(stderr, "assemble: could not encode context specific "
			"data\n");
		exit(1);
	}
}

int
generate_algorithm_id(SECAlgorithmID *idp, SECOidTag tag)
{
	SECAlgorithmID id;

	if (!idp)
		return -1;

	SECOidData *oiddata;
	oiddata = SECOID_FindOIDByTag(tag);
	if (!oiddata) {
		PORT_SetError(SEC_ERROR_INVALID_ALGORITHM);
		return -1;
	}
	if (SECITEM_CopyItem(NULL, &id.algorithm, &oiddata->oid))
		return -1;

	SECITEM_AllocItem(NULL, &id.parameters, 2);
	if (id.parameters.data == NULL)
		goto err;
	id.parameters.data[0] = SEC_ASN1_NULL;
	id.parameters.data[1] = 0;
	id.parameters.type = siBuffer;

	memcpy(idp, &id, sizeof (id));
	return 0;

err:
	SECITEM_FreeItem(&id.algorithm, PR_FALSE);
	return -1;
}

int
encode_algorithm_id(SECItem *der, SECOidTag tag)
{
	SECAlgorithmID id;

	int rc = generate_algorithm_id(&id, tag);
	if (rc < 0)
		return rc;

	void *ret;
	ret = SEC_ASN1EncodeItem(NULL, der, &id, SECOID_AlgorithmIDTemplate);
	if (ret == NULL) {
		fprintf(stderr, "could not encode algorithm ID\n");
		exit(1);
	}

	return 0;
}

static void
generate_digest_algorithms(SECItem *output, SECOidTag tag)
{
	SECItem algorithm;

	encode_algorithm_id(&algorithm, tag);

	SECItem *items[2] = {&algorithm, NULL};
	wrap_in_set(output, items);
}

static void
generate_content_info(SECItem *output, SECOidTag tag)
{
	SECItem oid;
	generate_object_id(&oid, tag);

	wrap_in_seq(output, &oid, 1);
}

extern CERTCertificate *
__CERT_DecodeDERCertificate(SECItem *derSignedCert, PRBool copyDER, char *nickname);

typedef struct {
	SECItem issuer;
	SECItem serial;
} issuer_and_serial_number;

static SEC_ASN1Template IssuerAndSerialNumberTemplate[] = {
	{.kind = SEC_ASN1_SEQUENCE,
	 .offset = 0,
	 .sub = NULL,
	 .size = 0,
	},
	{.kind = SEC_ASN1_ANY,
	 .offset = offsetof(issuer_and_serial_number, issuer),
	 .sub = &SEC_AnyTemplate,
	 .size = sizeof (SECItem),
	},
	{.kind = SEC_ASN1_INTEGER,
	 .offset = offsetof(issuer_and_serial_number, serial),
	 .sub = NULL,
	 .size = sizeof(long),
	},
	{ 0 }
};

static void
generate_issuer_and_serial(SECItem *output, SECItem *cert_der)
{
	issuer_and_serial_number iasn;

	CERTCertificate *cert;

	cert = __CERT_DecodeDERCertificate(cert_der, PR_FALSE, "fuckit");
	if (!cert)
		goto err;
#if 0
	CERTCertDBHandle *dbh = CERT_GetDefaultCertDB();
	if (!dbh)
		goto err;
	CERTCertificate *cert = CERT_FindCertByDERCert(dbh, cert_der);
	if (!cert)
		goto err;
#endif

	memcpy(&iasn.issuer, &cert->derIssuer, sizeof(iasn.issuer));
	memcpy(&iasn.serial, &cert->serialNumber, sizeof(iasn.serial));

	void *ret;
	ret = SEC_ASN1EncodeItem(NULL, output, &iasn,
				 IssuerAndSerialNumberTemplate);
	if (ret == NULL)
		goto err;

	return;
err:
	fprintf(stderr, "Could not generate issuer: %s\n",
		PORT_ErrorToString(PORT_GetError()));
	exit(1);
}

typedef struct {
	SECItem version;
	SECItem issuer_and_serial;
	SECItem digest_algorithm;
	SECItem authenticated_attributes;
	SECItem digest_encoding_algorithm;
	SECItem encoded_digest;
} signer_info;

static SEC_ASN1Template SignerInfoTemplate[] = {
	{.kind = SEC_ASN1_SEQUENCE,
	 .offset = 0,
	 .sub = NULL,
	 .size = 0,
	},
	{.kind = SEC_ASN1_ANY,
	 .offset = offsetof(signer_info, version),
	 .sub = &SEC_AnyTemplate,
	 .size = sizeof (SECItem),
	},
	{.kind = SEC_ASN1_ANY,
	 .offset = offsetof(signer_info, issuer_and_serial),
	 .sub = &SEC_AnyTemplate,
	 .size = sizeof (SECItem),
	},
	{.kind = SEC_ASN1_ANY,
	 .offset = offsetof(signer_info, digest_algorithm),
	 .sub = &SEC_AnyTemplate,
	 .size = sizeof (SECItem),
	},
	{.kind = SEC_ASN1_ANY,
	 .offset = offsetof(signer_info, authenticated_attributes),
	 .sub = &SEC_AnyTemplate,
	 .size = sizeof (SECItem),
	},
	{.kind = SEC_ASN1_ANY,
	 .offset = offsetof(signer_info, digest_encoding_algorithm),
	 .sub = &SEC_AnyTemplate,
	 .size = sizeof (SECItem),
	},
	{.kind = SEC_ASN1_ANY,
	 .offset = offsetof(signer_info, encoded_digest),
	 .sub = &SEC_AnyTemplate,
	 .size = sizeof (SECItem),
	},
	{ 0 }
};

static void
build_signer_infos(SECItem *output, SECItem *cert, SECItem *authattr,
		   SECItem *signature)
{
	signer_info si;

	generate_integer(&si.version, 1, 1);
	generate_issuer_and_serial(&si.issuer_and_serial, cert);
	encode_algorithm_id(&si.digest_algorithm, SEC_OID_SHA256);
	memcpy(&si.authenticated_attributes, authattr, sizeof (*authattr));
	encode_algorithm_id(&si.digest_encoding_algorithm,
			    SEC_OID_PKCS1_RSA_ENCRYPTION);
	generate_octet_string(&si.encoded_digest, signature);

	SECItem si_der;
	void *ret;
	ret = SEC_ASN1EncodeItem(NULL, &si_der, &si, SignerInfoTemplate);
	if (ret == NULL) {
		fprintf(stderr, "assemble: could not encode data\n");
		exit(1);
	}
	SECItem *list[2] = {&si_der, NULL};
	wrap_in_set(output, list);
}

typedef struct {
	SECItem oid;
	SECItem data;
} whole_thing;

static SEC_ASN1Template WholeThingTemplate[] = {
	{.kind = SEC_ASN1_SEQUENCE,
	 .offset = 0,
	 .sub = NULL,
	 .size = 0,
	},
	{.kind = SEC_ASN1_OBJECT_ID,
	 .offset = offsetof(whole_thing, oid),
	 .sub = &SEC_ObjectIDTemplate,
	 .size = sizeof (SECItem),
	},
	{.kind = SEC_ASN1_ANY,
	 .offset = offsetof(whole_thing, data),
	 .sub = &SEC_AnyTemplate,
	 .size = sizeof (SECItem),
	},
	{ 0 }
};

static void build_whole_thing(SECItem *data, SECItem *output)
{
	whole_thing wt;

	SECOidData *oid = SECOID_FindOIDByTag(SEC_OID_PKCS7_SIGNED_DATA);
	if (!oid) {
		fprintf(stderr, "Could not find OID for signature\n");
		exit(1);
	}
	memcpy(&wt.oid, &oid->oid, sizeof (wt.oid));
	memcpy(&wt.data, data, sizeof(wt.data));

	void *ret;
	ret = SEC_ASN1EncodeItem(NULL, output, &wt, WholeThingTemplate);
	if (ret == NULL) {
		fprintf(stderr, "assemble: could not encode data\n");
		exit(1);
	}
}

typedef struct {
	SECItem version;
	SECItem digest_algorithms;
	SECItem content_info;
	SECItem certificates;
	SECItem signer_infos;
} signed_data;

static SEC_ASN1Template SignedDataTemplate[] = {
	{.kind = SEC_ASN1_SEQUENCE,
	 .offset = 0,
	 .sub = NULL,
	 .size = 0,
	},
	{.kind = SEC_ASN1_ANY,
	 .offset = offsetof(signed_data, version),
	 .sub = &SEC_AnyTemplate,
	 .size = sizeof (SECItem),
	},
	{.kind = SEC_ASN1_ANY,
	 .offset = offsetof(signed_data, digest_algorithms),
	 .sub = &SEC_AnyTemplate,
	 .size = sizeof (SECItem),
	},
	{.kind = SEC_ASN1_ANY,
	 .offset = offsetof(signed_data, content_info),
	 .sub = &SEC_AnyTemplate,
	 .size = sizeof (SECItem),
	},
	{.kind = SEC_ASN1_ANY,
	 .offset = offsetof(signed_data, certificates),
	 .sub = &SEC_AnyTemplate,
	 .size = sizeof (SECItem),
	},
	{.kind = SEC_ASN1_ANY,
	 .offset = offsetof(signed_data, signer_infos),
	 .sub = &SEC_AnyTemplate,
	 .size = sizeof (SECItem),
	},
	{ 0 }
};

static void
build_signed_data(SECItem *output, SECItem *cert, SECItem *authattr,
		  SECItem *signature)
{
	signed_data sd;
	SECItem sd_der;

	generate_integer(&sd.version, 1, 1);
	generate_digest_algorithms(&sd.digest_algorithms, SEC_OID_SHA256);
	generate_content_info(&sd.content_info, SEC_OID_PKCS7_DATA);

	make_context_specific(SEC_ASN1_CONSTRUCTED | 0, &sd.certificates, cert);
	build_signer_infos(&sd.signer_infos, cert, authattr, signature);

	void *ret;
	ret = SEC_ASN1EncodeItem(NULL, &sd_der, &sd, SignedDataTemplate);
	if (ret == NULL) {
		fprintf(stderr, "assemble: could not encode data\n");
		exit(1);
	}

	make_context_specific(SEC_ASN1_CONSTRUCTED | 0, output, &sd_der);
}

void
build_pkcs7(SECItem *output, SECItem *signing_cert, SECItem *signature,
	    SECItem *authattr)
{
	SECItem signed_data_der;
	build_signed_data(&signed_data_der, signing_cert, authattr, signature);
	build_whole_thing(&signed_data_der, output);
}

static void
generate_time(SECItem *encoded, EFI_TIME *when)
{
	static char timebuf[32];
	SECItem whenitem = {.type = SEC_ASN1_UTC_TIME,
			 .data = (unsigned char *)timebuf,
			 .len = 0
	};

	whenitem.len = snprintf(timebuf, 32, "%02d%02d%02d%02d%02d%02dZ",
		when->Year % 100, when->Month + 1, when->Day,
		when->Hour, when->Minute, when->Second);
	if (whenitem.len == 32) {
err:
		fprintf(stderr, "could not encode timestamp\n");
		exit(1);
	}

	if (SEC_ASN1EncodeItem(NULL, encoded, &whenitem,
			SEC_UTCTimeTemplate) == NULL)
		goto err;
}

static void
build_content_type(SECItem *output, SECOidTag tag)
{
	SECItem ctype;
	SECItem oid;
	SECItem *items[2] = {&oid, NULL};
	SECItem set;

	generate_object_id(&ctype, SEC_OID_PKCS9_CONTENT_TYPE);
	generate_object_id(&oid, SEC_OID_PKCS7_DATA);
	wrap_in_set(&set, items);
	generate_tuple(output, &ctype, &set);
}

static void
build_signing_time(SECItem *output, EFI_TIME *timestamp)
{
	SECItem stime;
	SECItem time;
	SECItem *items[2] = {&time, NULL};
	SECItem set;

	generate_object_id(&stime, SEC_OID_PKCS9_SIGNING_TIME);
	generate_time(&time, timestamp);

	wrap_in_set(&set, items);
	generate_tuple(output, &stime, &set);
}

static void
get_sha(SECItem *data, unsigned char *sha)
{
	PK11Context *pk11ctx = NULL;
	unsigned int outlen = -1;

	pk11ctx = PK11_CreateDigestContext(SEC_OID_SHA1);
	PK11_DigestBegin(pk11ctx);

	PK11_DigestOp(pk11ctx, data->data, data->len);
	PK11_DigestFinal(pk11ctx, sha, &outlen, 32);

	PK11_Finalize(pk11ctx);
	PK11_DestroyContext(pk11ctx, PR_TRUE);
}

static void
build_message_digest(SECItem *output, SECItem *data)
{
	SECItem oid;
	unsigned char sha_data[32];
	SECItem octets;

	generate_object_id(&oid, SEC_OID_PKCS9_MESSAGE_DIGEST);
	get_sha(data, sha_data);
	SECItem sha = {.type = siBuffer, .data = sha_data, .len = 32};
	generate_octet_string(&octets, &sha);

	SECItem *items[2] = {&octets, NULL};
	SECItem set;
	wrap_in_set(&set, items);
	generate_tuple(output, &oid, &set);
}

static void
build_smime_caps(SECItem *output)
{
	SECItem oid, set, seq;
	SECItem *items[2] = {&seq, NULL};

	generate_object_id(&oid, SEC_OID_PKCS9_SMIME_CAPABILITIES);
	wrap_in_seq(&seq, NULL, 0);
	wrap_in_set(&set, items);
	generate_tuple(output, &oid, &set);
}

typedef struct {
	SECItem content_type;
	SECItem signing_time;
	SECItem message_digest;
	SECItem smime_capabilities;
} authenticated_attributes;

static SEC_ASN1Template AuthenticatedAttributesTemplate[] = {
	{.kind = SEC_ASN1_SEQUENCE,
	 .offset = 0,
	 .sub = NULL,
	 .size = 0,
	},
	{.kind = SEC_ASN1_ANY,
	 .offset = offsetof(authenticated_attributes, content_type),
	 .sub = &SEC_AnyTemplate,
	 .size = sizeof (SECItem),
	},
	{.kind = SEC_ASN1_ANY,
	 .offset = offsetof(authenticated_attributes, signing_time),
	 .sub = &SEC_AnyTemplate,
	 .size = sizeof (SECItem),
	},
	{.kind = SEC_ASN1_ANY,
	 .offset = offsetof(authenticated_attributes, message_digest),
	 .sub = &SEC_AnyTemplate,
	 .size = sizeof (SECItem),
	},
	{.kind = SEC_ASN1_ANY,
	 .offset = offsetof(authenticated_attributes, smime_capabilities),
	 .sub = &SEC_AnyTemplate,
	 .size = sizeof (SECItem),
	},
	{ 0 }
};

void
build_authenticated_attributes(SECItem *output, SECItem *data,
			       EFI_TIME *timestamp)
{
	authenticated_attributes aa;

	build_content_type(&aa.content_type, SEC_OID_PKCS7_DATA);
	build_signing_time(&aa.signing_time, timestamp);
	build_message_digest(&aa.message_digest, data);
	build_smime_caps(&aa.smime_capabilities);

	void *ret;
	ret = SEC_ASN1EncodeItem(NULL, output, &aa,
				 AuthenticatedAttributesTemplate);
	if (ret == NULL) {
		fprintf(stderr, "buildvar: could not encode data\n");
		exit(1);
	}

	output->data[0] = SEC_ASN1_CONSTRUCTED | SEC_ASN1_CONTEXT_SPECIFIC;
}
