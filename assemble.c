
#include <efi/efi.h>
#include <efivar.h>
#include <fcntl.h>
#include <popt.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>

#include "wincert.h"
#include "pkcs7.h"

#include <prerror.h>
#include <nss.h>
#include <pk11pub.h>

static void
map_file(const char *filename, SECItem *item)
{
	int fd = -1;
	struct stat statbuf;
	int rc;
	
	fd = open(filename, O_RDONLY);
	if (fd < 0) {
err:
		fprintf(stderr, "assemble: could not read \"%s\": %m\n",
			filename);
		exit(1);
	}

	rc = fstat(fd, &statbuf);
	if (rc < 0)
		goto err;
	
	if (!statbuf.st_size)
		goto err;
	
	item->len = statbuf.st_size;
	item->data = mmap(NULL, statbuf.st_size, PROT_READ, MAP_PRIVATE, fd, 0);

	if (!item->data)
		goto err;
}

int
main(int argc, char *argv[])
{
	char *outfile = NULL;
	char *name = NULL;

	char *signed_data_file = NULL;
	SECItem signed_data = {.type = siBuffer,
			       .data = NULL,
			       .len = 0
			      };

	char *signature_file = NULL;
	SECItem signature = {.type = siBuffer,
			     .data = NULL,
			     .len = 0
			    };

	char *signing_cert_file = NULL;
	SECItem signing_cert = {.type = siBuffer,
				.data = NULL,
				.len = 0
			       };

	char *authattr_file = NULL;
	SECItem authattr = {.type = siBuffer,
			    .data = NULL,
			    .len = 0
			   };

	// efi_guid_t guid;
	// uint32_t attributes = 0;
	int force = 0;

	poptContext optCon;
	struct poptOption options[] = {
		{NULL, '\0', POPT_ARG_INTL_DOMAIN, "assemble" },
		{"signed-data", 's', POPT_ARG_STRING, &signed_data_file, 0,
			"file to read the signed data from",
			"<signed-data>" },
		{"signature", 'S', POPT_ARG_STRING, &signature_file, 0,
			"file to read signature from",
			"<signature>" },
		{"certificate", 'c', POPT_ARG_STRING, &signing_cert_file, 0,
			"file to read public signing certificate from",
			"<certificate>" },
		{"auth-attrs", 'a', POPT_ARG_STRING, &authattr_file, 0,
			"file to read authenticated attributes from",
			"<auth-attr>" },
		{"force", 'f', POPT_ARG_VAL, &force, 1,
			"force overwriting of output file", NULL },
		{"output" , 'o', POPT_ARG_STRING, &outfile, 0,
			"file to write signed output payload to", "<outfile>"},
		{"name", 'n', POPT_ARG_STRING, &name, 0,
			"specify variable name", "<name>"},
		POPT_AUTOALIAS
		POPT_AUTOHELP
		POPT_TABLEEND
	};

	optCon = poptGetContext("assemble", argc, (const char **)argv,
				options, 0);

	int rc = poptReadDefaultConfig(optCon, 0);
	if (rc < 0) {
		fprintf(stderr, "assemble: poptReadDefaultConfig failed: %s\n",
			poptStrerror(rc));
		exit(1);
	}

	while ((rc = poptGetNextOpt(optCon)) > 0)
		;
	
	if (rc < -1) {
		fprintf(stderr, "assemble: invalid argument: %s: %s\n",
			poptBadOption(optCon, 0), poptStrerror(rc));
		exit(1);
	}

	if (poptPeekArg(optCon)) {
		fprintf(stderr, "assemble: invalid argument: \"%s\"\n",
			poptPeekArg(optCon));
		exit(1);
	}

	poptFreeContext(optCon);

	if (!name || name[0] == '\0') {
		fprintf(stderr, "buildvar: no valid variable name specified\n");
		exit(1);
	}

	if (!signed_data_file || signed_data_file[0] == '\0') {
		fprintf(stderr, "assemble: no valid signed data file "
			"provided\n");
		exit(1);
	}

	if (!signature_file || signature_file[0] == '\0') {
		fprintf(stderr, "assemble: no valid signature file provided\n");
		exit(1);
	}

	if (!signing_cert_file || signing_cert_file[0] == '\0') {
		fprintf(stderr, "assemble: no valid certificate file "
				"provided\n");
		exit(1);
	}

	if (!authattr_file || authattr_file[0] == '\0') {
		fprintf(stderr, "assemble: no valid authenticated attributes "
				"file provided\n");
		exit(1);
	}

	if (!outfile || outfile[0] == '\0') {
		fprintf(stderr, "assemble: no valid output file provided\n");
		exit(1);
	}

	SECStatus status = NSS_Init("/etc/pki/pesign");
	if (status != SECSuccess) {
		fprintf(stderr, "Could not initialize nss: %s\n",
			PORT_ErrorToString(PORT_GetError()));
		exit(1);
	}
	
	map_file(signed_data_file, &signed_data);
	map_file(signature_file, &signature);
	map_file(signing_cert_file, &signing_cert);
	map_file(authattr_file, &authattr);

	size_t name_len = strlen(name);
	size_t left = signed_data.len - name_len; 
	unsigned char *p = signed_data.data + name_len;

	efi_guid_t guid;
	memcpy(&guid, p, sizeof(guid));
	p += sizeof(guid);
	left -= sizeof(guid);

	uint32_t attributes;
	memcpy(&attributes, p, sizeof(attributes));
	p += sizeof(attributes);
	left -= sizeof(attributes);

	EFI_TIME time = { 0 };
	uint64_t monotonic = 0;

	if (attributes & EFI_VARIABLE_TIME_BASED_AUTHENTICATED_WRITE_ACCESS) {
		memcpy(&time, p, sizeof (time));
		p += sizeof (time);
		left -= sizeof (time);
	} else {
		memcpy(&monotonic, p, sizeof (monotonic));
		p += sizeof (monotonic);
		left -= sizeof (monotonic);
	}

	SECItem finished;
	build_pkcs7(&finished, &signing_cert, &signature, &authattr);

	int fd = open(outfile, O_CREAT|O_RDWR|O_TRUNC, 0600);
	if (fd < 0) {
		fprintf(stderr, "assemble: could not open output: %m\n");
		exit(1);
	}

	off_t offset = 0;
	while (offset < finished.len) {
		off_t rc = write(fd, finished.data + offset,
					finished.len - offset);
		if (rc < 0) {
			fprintf(stderr, "assemble: could not write output: "
					"%m\n");
			unlink(outfile);
			exit(1);
		}
		offset += rc;
	}

	return 0;
}
