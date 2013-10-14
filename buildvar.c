#include <efi/efi.h>
#include <efivar.h>
#include <errno.h>
#include <fcntl.h>
#include <inttypes.h>
#include <popt.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>

#include "wincert.h"

#ifndef EFI_IMAGE_SECURITY_DATABASE_GUID
#define EFI_IMAGE_SECURITY_DATABASE_GUID \
  EFI_GUID(0xd719b2cb,0x3d3a,0x4596,0xa3bc,0xda,0xd0,0x0e,0x67,0x65,0x6f)
#endif

static void
get_input_data(char *infile, char **in_data, size_t *in_data_size)
{
	int fd = -1;
	struct stat statbuf;
	int rc;
	
	if (!infile || infile[0] == '\0') {
err_data:
		fprintf(stderr, "buildvar: no valid input data specified\n");
		exit(1);
	}

	fd = open(infile, O_RDONLY);
	if (fd < 0) {
err:
		fprintf(stderr, "buildvar: could not get input data: %m\n");
		exit(1);
	}
	
	rc = fstat(fd, &statbuf);
	if (rc < 0)
		goto err;
	
	if (!statbuf.st_size)
		goto err_data;
	
	*in_data_size = statbuf.st_size;
	*in_data = mmap(NULL, statbuf.st_size, PROT_READ, MAP_PRIVATE, fd, 0);

	if (!*in_data)
		goto err;
}

static void
char_to_wchar(uint16_t *d, const char *s)
{
	for (int i = 0; s[i] != '\0'; i++)
		d[i] = s[i];
}

static uint16_t *
wstrdup(const char *s)
{
	uint16_t *d = calloc(strlen(s) + 1, sizeof (uint16_t));
	if (!d)
		return NULL;

	char_to_wchar(d, s);
	return d;
}

static void
build_data(char **data, size_t *data_size,
		uint16_t *wname, size_t wname_len,
		uint32_t attributes, efi_guid_t *guid,
		char *auth_data, size_t auth_data_size,
		char *in_data, size_t in_data_size)
{
	size_t buf_len = wname_len +
			sizeof(efi_guid_t) +
			sizeof (uint32_t) +
			auth_data_size +
			in_data_size;
	
	char *p, *buf;
	p = buf = malloc(buf_len);
	if (!buf) {
		fprintf(stderr, "buildvar: could not build data for signing: %m\n");
		exit(1);
	}

	memcpy(p, wname, wname_len);
	p += wname_len;
	memcpy(p, guid, sizeof (*guid));
	p += sizeof (*guid);
	memcpy(p, &attributes, sizeof (attributes));
	p += sizeof (attributes);
	memcpy(p, auth_data, auth_data_size);
	p += auth_data_size;
	memcpy(p, in_data, in_data_size);

	*data = buf;
	*data_size = buf_len;
}

int
main(int argc, char *argv[])
{
	char *name = NULL;
	char *infile = NULL;
	char *outfile = NULL;
	char *guid_str = NULL;
	char *timestamp_str = NULL;
	char *monotonic_str = NULL;
	efi_guid_t guid;
	uint32_t attributes = 0;
	int force = 0;

	poptContext optCon;
	struct poptOption options[] = {
		{NULL, '\0', POPT_ARG_INTL_DOMAIN, "buildvar" },
		{"data", 'd', POPT_ARG_STRING, &infile, 0,
			"specify file name to read variable data from",
			"<datafile>"},
		{"force", 'f', POPT_ARG_VAL, &force, 1,
			"force overwriting of output file", NULL },
		{"guid", 'g', POPT_ARG_STRING, &guid_str, 0,
			"vendor guid", "<guid>"},
		{"monotonic", 'm', POPT_ARG_STRING, &monotonic_str, 0,
			"monotonic count to use for authenticated variable",
			"<count>" },
		{"name", 'n', POPT_ARG_STRING, &name, 0,
			"specify variable name", "<name>"},
		{"output" , 'o', POPT_ARG_STRING, &outfile, 0,
			"file to write signing payload to", "<outfile>"},
		{"timestamp", 't', POPT_ARG_STRING, &timestamp_str, 0,
			"timestamp to use for authenticated variable",
			"<timestamp>" },
		{"non-volatile", 'N', POPT_ARG_VAL|POPT_BIT_SET, &attributes,
			EFI_VARIABLE_NON_VOLATILE,
			"variable is non-volatile", NULL },
		{"boot", 'B', POPT_ARG_VAL|POPT_BIT_SET, &attributes,
			EFI_VARIABLE_BOOTSERVICE_ACCESS,
			"allow boot services access", NULL },
		{"runtime", 'R', POPT_ARG_VAL|POPT_BIT_SET, &attributes,
			EFI_VARIABLE_RUNTIME_ACCESS,
			"allow runtime services access", NULL },
		{"append", 'P', POPT_ARG_VAL|POPT_BIT_SET, &attributes,
			EFI_VARIABLE_APPEND_WRITE,
			"append to previously set values", NULL },
		POPT_AUTOALIAS
		POPT_AUTOHELP
		POPT_TABLEEND
	};

	optCon = poptGetContext("buildvar", argc, (const char **)argv,options,0);

	int rc = poptReadDefaultConfig(optCon, 0);
	if (rc < 0) {
		fprintf(stderr, "buildvar: poptReadDefaultConfig failed: %s\n",
			poptStrerror(rc));
		exit(1);
	}

	while ((rc = poptGetNextOpt(optCon)) > 0)
		;
	
	if (rc < -1) {
		fprintf(stderr, "buildvar: invalid argument: %s: %s\n",
			poptBadOption(optCon, 0), poptStrerror(rc));
		exit(1);
	}

	if (poptPeekArg(optCon)) {
		fprintf(stderr, "buildvar: invalid argument: \"%s\"\n",
			poptPeekArg(optCon));
		exit(1);
	}

	poptFreeContext(optCon);

	if (!name || name[0] == '\0') {
		fprintf(stderr, "buildvar: no valid variable name specified\n");
		exit(1);
	}

	if (!strcmp(name, "db") ||
			!strcmp(name, "dbx") || !strcmp(name, "dbt")) {
		guid = EFI_IMAGE_SECURITY_DATABASE_GUID;
	} else if (!strcmp(name, "PK") || !strcmp(name, "KEK")) {
		guid = EFI_GLOBAL_GUID;
	} else {
		if (!guid_str || guid_str[0] == '\0' ||
				efi_str_to_guid(guid_str, &guid) < 0) {
			fprintf(stderr, "buildvar: no valid guid specified\n");
			exit(1);
		}
	}

	if (!outfile || outfile[0] == '\0') {
		fprintf(stderr, "buildvar: no output file specified\n");
		exit(1);
	}

	if (attributes == 0) {
		fprintf(stderr, "buildvar: no attributes set\n");
		exit(1);
	}

	if (timestamp_str && timestamp_str[0] != '\0' &&
			monotonic_str && monotonic_str[0] != '\0') {
		fprintf(stderr, "buildvar: --time-based and --monotonic "
			"can not be used together\n");
		exit(1);
	}
	void *auth_data = NULL;
	size_t auth_data_size = 0;

	if (timestamp_str && timestamp_str[0] != '\0') {
		attributes |=EFI_VARIABLE_TIME_BASED_AUTHENTICATED_WRITE_ACCESS;
	} else if (monotonic_str && monotonic_str[0] != '\0') {
		attributes |= EFI_VARIABLE_AUTHENTICATED_WRITE_ACCESS;

		EFI_VARIABLE_AUTHENTICATION *auth;

		auth = calloc(1, sizeof (*auth));
		auth->MonotonicCount = strtol(monotonic_str, NULL, 0);
		auth_data = auth;
		auth_data_size = sizeof(auth->MonotonicCount);
	}

	if (!(timestamp_str && timestamp_str[0] != '\0') &&
			!(monotonic_str && monotonic_str[0] != '\0')) {
		fprintf(stderr, "buildvar: either --time-based or --monotonic "
				"must be specified\n");
		exit(1);
	}

	struct stat statbuf;
	memset(&statbuf, '\0', sizeof (statbuf));

	rc = stat(outfile, &statbuf);
	if (rc < 0) {
		if (errno != ENOENT) {
			fprintf(stderr, "buildvar: could not create output: "
					"%m\n");
			exit(1);
		}
	} else if (!force) {
		fprintf(stderr, "buildvar: output exists and --force was not "
				"used\n");
		exit(1);
	}
	char *in_data = NULL;
	size_t in_data_size = 0;

	get_input_data(infile, &in_data, &in_data_size);

	uint16_t *wname = wstrdup(name);
	uint32_t wname_len = strlen(name) * sizeof(wchar_t);

	char *data = NULL;
	size_t data_size = 0;

	build_data(&data, &data_size, wname, wname_len, attributes, &guid,
		auth_data, auth_data_size, in_data, in_data_size);

	int outfd = open(outfile, O_RDWR|O_CREAT|O_TRUNC, 0600);
	if (outfd < 0) {
		fprintf(stderr, "buildvar: could not write output: %m\n");
		exit(1);
	}

	off_t pos = 0;
	while (pos < data_size) {
		off_t n = write(outfd, data+pos, data_size - pos);
		if (n >= 0)
			pos += n;
		if (n < 0 && errno != EAGAIN) {
			fprintf(stderr, "buildvar: could not write output: "
					"%m\n");
			unlink(outfile);
			exit(1);
		}
	}
	return 0;
}
