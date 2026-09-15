#define _GNU_SOURCE

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "sha3_variant_file.h"

#define ABC_SHA256 \
	"ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
#define EMPTY_SHA256 \
	"e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"

static int failures;
static unsigned cases;

static void expect_true(const char *name, int condition)
{
	cases++;
	if (!condition) {
		fprintf(stderr, "%s failed (errno=%d)\n", name, errno);
		failures++;
	}
}

int main(void)
{
	char directory[] = "/tmp/sha3_variant_file_test.XXXXXX";
	char path[256];
	char missing[256];
	char linked[256];
	char symbolic[256];
	char actual[SHA3_VARIANT_FILE_SHA256_HEX_SIZE];
	FILE *file;

	expect_true("mkdtemp", mkdtemp(directory) != NULL);
	snprintf(path, sizeof(path), "%s/test.bit", directory);
	snprintf(missing, sizeof(missing), "%s/missing.bit", directory);
	snprintf(linked, sizeof(linked), "%s/linked.bit", directory);
	snprintf(symbolic, sizeof(symbolic), "%s/symbolic.bit", directory);
	file = fopen(path, "wb");
	expect_true("create", file != NULL);
	if (file) {
		expect_true("write", fwrite("abc", 1, 3, file) == 3);
		expect_true("close", fclose(file) == 0);
	}
	expect_true("exact-digest",
		sha3_variant_file_check(path, ABC_SHA256, actual) ==
			SHA3_VARIANT_FILE_OK && strcmp(actual, ABC_SHA256) == 0);
	expect_true("mismatch",
		sha3_variant_file_check(path, EMPTY_SHA256, actual) ==
			SHA3_VARIANT_FILE_DIGEST_MISMATCH &&
			strcmp(actual, ABC_SHA256) == 0);
	expect_true("missing",
		sha3_variant_file_check(missing, ABC_SHA256, actual) ==
			SHA3_VARIANT_FILE_MISSING && actual[0] == '\0');
	errno = 0;
	expect_true("reject-uppercase-digest",
		sha3_variant_file_check(path,
			"BA7816BF8F01CFEA414140DE5DAE2223B00361A396177A9CB410FF61F20015AD",
			actual) == SHA3_VARIANT_FILE_INVALID && errno == EINVAL);
	errno = 0;
	expect_true("reject-null-output",
		sha3_variant_file_check(path, ABC_SHA256, NULL) ==
			SHA3_VARIANT_FILE_INVALID && errno == EINVAL);

	expect_true("hardlink-create", link(path, linked) == 0);
	expect_true("reject-multiple-links",
		sha3_variant_file_check(path, ABC_SHA256, actual) ==
			SHA3_VARIANT_FILE_INVALID);
	unlink(linked);
	expect_true("symlink-create", symlink(path, symbolic) == 0);
	expect_true("reject-symlink",
		sha3_variant_file_check(symbolic, ABC_SHA256, actual) ==
			SHA3_VARIANT_FILE_INVALID);
	unlink(symbolic);

	file = fopen(path, "wb");
	expect_true("truncate", file != NULL);
	if (file)
		expect_true("close-empty", fclose(file) == 0);
	expect_true("reject-empty",
		sha3_variant_file_check(path, EMPTY_SHA256, actual) ==
			SHA3_VARIANT_FILE_INVALID);

	unlink(path);
	rmdir(directory);
	if (failures)
		return 1;
	printf("SHA3_VARIANT_FILE_TEST_PASS cases=%u\n", cases);
	return 0;
}
