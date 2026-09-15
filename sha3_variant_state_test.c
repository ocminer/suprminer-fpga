#define _GNU_SOURCE

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

#include "sha3_variant_state.h"

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

static int read_file(const char *path, char *buffer, size_t size)
{
	FILE *file = fopen(path, "r");
	size_t used;

	if (!file)
		return -1;
	used = fread(buffer, 1, size - 1, file);
	if (ferror(file) || !feof(file)) {
		fclose(file);
		return -1;
	}
	buffer[used] = '\0';
	return fclose(file);
}

int main(void)
{
	char directory[] = "/tmp/sha3_variant_state_test.XXXXXX";
	char path[256];
	char before[4096];
	char after[4096];
	char state_id[64];
	bool found = false;
	struct stat status;
	FILE *file;

	expect_true("mkdtemp", mkdtemp(directory) != NULL);
	snprintf(path, sizeof(path), "%s/state.conf", directory);

	expect_true("create",
		sha3_variant_state_save_atomic(path, "ZTEX A", 0,
			"example-family", "example-a"));
	expect_true("read-created", read_file(path, after, sizeof(after)) == 0);
	expect_true("created-content",
		strcmp(after, "ZTEX A:0=example-family/example-a\n") == 0);
	expect_true("created-mode", stat(path, &status) == 0 &&
		(status.st_mode & 0777) == 0600);

	expect_true("append",
		sha3_variant_state_save_atomic(path, "ZTEX B", 3,
			"example-family", "example-b"));
	expect_true("update",
		sha3_variant_state_save_atomic(path, "ZTEX A", 0,
			"example-family", "example-c"));
	expect_true("read-updated", read_file(path, after, sizeof(after)) == 0);
	expect_true("updated-content",
		strcmp(after, "ZTEX A:0=example-family/example-c\n"
			"ZTEX B:3=example-family/example-b\n") == 0);

	expect_true("lookup-current-family",
		sha3_variant_state_lookup(path, "ZTEX A", 0, "example-family",
			state_id, sizeof(state_id), &found) && found &&
			strcmp(state_id, "example-c") == 0);
	found = true;
	strcpy(state_id, "dirty");
	expect_true("lookup-stale-family-ignored",
		sha3_variant_state_lookup(path, "ZTEX A", 0, "bc3-next",
			state_id, sizeof(state_id), &found) && !found &&
			state_id[0] == '\0');
	found = true;
	expect_true("lookup-missing-file",
		sha3_variant_state_lookup("/tmp/sha3-variant-no-such-state",
			"ZTEX A", 0, "example-family", state_id, sizeof(state_id),
			&found) && !found);

	file = fopen(path, "w");
	expect_true("open-duplicate", file != NULL);
	if (file) {
		fputs("ZTEX A:0=example-family/example-a\n", file);
		fputs("ZTEX A:0=example-family/example-b\n", file);
		fclose(file);
	}
	expect_true("read-duplicate-before",
		read_file(path, before, sizeof(before)) == 0);
	errno = 0;
	expect_true("reject-duplicate-lookup",
		!sha3_variant_state_lookup(path, "ZTEX A", 0, "example-family",
			state_id, sizeof(state_id), &found) && errno == EINVAL);
	errno = 0;
	expect_true("reject-duplicate-save",
		!sha3_variant_state_save_atomic(path, "ZTEX A", 0,
			"example-family", "example") && errno == EINVAL);
	expect_true("read-duplicate-after",
		read_file(path, after, sizeof(after)) == 0);
	expect_true("duplicate-preserved", strcmp(before, after) == 0);

	file = fopen(path, "w");
	expect_true("restore-valid", file != NULL);
	if (file) {
		fputs("ZTEX A:0=example-family/example-c\n", file);
		fputs("ZTEX B:3=example-family/example-b\n", file);
		fclose(file);
	}
	expect_true("read-restored-valid",
		read_file(path, before, sizeof(before)) == 0);

	errno = 0;
	expect_true("reject-newline",
		!sha3_variant_state_save_atomic(path, "ZTEX\nBAD", 0,
			"example-family", "example") &&
		errno == EINVAL);
	expect_true("reject-unsafe-family",
		!sha3_variant_state_save_atomic(path, "ZTEX A", 0,
			"bc3/final", "example") && errno == EINVAL);
	expect_true("reject-unsafe-state",
		!sha3_variant_state_save_atomic(path, "ZTEX A", 0,
			"example-family", "../example") && errno == EINVAL);
	expect_true("read-after-reject", read_file(path, after, sizeof(after)) == 0);
	expect_true("reject-preserves-old", strcmp(before, after) == 0);

	file = fopen(path, "w");
	expect_true("open-overlong", file != NULL);
	if (file) {
		for (int i = 0; i < 255; ++i)
			fputc('X', file);
		fputc('\n', file);
		fclose(file);
	}
	expect_true("read-overlong-before", read_file(path, before, sizeof(before)) == 0);
	errno = 0;
	expect_true("reject-overlong-state",
		!sha3_variant_state_save_atomic(path, "ZTEX A", 0,
			"example-family", "example") &&
		errno == EOVERFLOW);
	expect_true("read-overlong-after", read_file(path, after, sizeof(after)) == 0);
	expect_true("overlong-preserved", strcmp(before, after) == 0);

	unlink(path);
	rmdir(directory);
	if (failures)
		return 1;
	printf("SHA3_VARIANT_STATE_TEST_PASS cases=%u\n", cases);
	return 0;
}
