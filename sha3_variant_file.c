#define _POSIX_C_SOURCE 200809L

#include "sha3_variant_file.h"

#include <errno.h>
#include <stdbool.h>
#include <stdio.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

#include "algo/sha2.h"
#include "sha3_variant_family.h"

enum sha3_variant_file_status sha3_variant_file_check(const char *path,
		const char *expected_sha256,
		char actual_sha256[SHA3_VARIANT_FILE_SHA256_HEX_SIZE])
{
	static const char hexadecimal[] = "0123456789abcdef";
	unsigned char buffer[64 * 1024];
	unsigned char digest[32];
	sha256_ctx context;
	FILE *file;
	struct stat path_status;
	struct stat before;
	struct stat after;
	size_t length;
	int saved_errno;

	if (actual_sha256)
		actual_sha256[0] = '\0';
	if (!path || !*path || !sha3_variant_digest_valid(expected_sha256) ||
	    !actual_sha256) {
		errno = EINVAL;
		return SHA3_VARIANT_FILE_INVALID;
	}
	if (lstat(path, &path_status) != 0)
		return errno == ENOENT ? SHA3_VARIANT_FILE_MISSING :
			SHA3_VARIANT_FILE_IO_ERROR;
	if (!S_ISREG(path_status.st_mode) || path_status.st_nlink != 1 ||
	    path_status.st_size <= 0 || path_status.st_size > 16 * 1024 * 1024) {
		errno = EINVAL;
		return SHA3_VARIANT_FILE_INVALID;
	}
	file = fopen(path, "rb");
	if (!file)
		return errno == ENOENT ? SHA3_VARIANT_FILE_MISSING :
			SHA3_VARIANT_FILE_IO_ERROR;
	if (fstat(fileno(file), &before) != 0 || !S_ISREG(before.st_mode) ||
	    before.st_nlink != 1 || before.st_dev != path_status.st_dev ||
	    before.st_ino != path_status.st_ino ||
	    before.st_size != path_status.st_size) {
		saved_errno = errno ? errno : EINVAL;
		fclose(file);
		errno = saved_errno;
		return SHA3_VARIANT_FILE_INVALID;
	}
	sha256_init(&context);
	while ((length = fread(buffer, 1, sizeof(buffer), file)) > 0)
		sha256_update(&context, buffer, (unsigned int)length);
	if (ferror(file)) {
		saved_errno = errno ? errno : EIO;
		fclose(file);
		errno = saved_errno;
		return SHA3_VARIANT_FILE_IO_ERROR;
	}
	if (fstat(fileno(file), &after) != 0 ||
	    after.st_dev != before.st_dev || after.st_ino != before.st_ino ||
	    after.st_size != before.st_size || after.st_mtime != before.st_mtime ||
	    after.st_ctime != before.st_ctime || after.st_nlink != before.st_nlink) {
		saved_errno = errno ? errno : EIO;
		fclose(file);
		errno = saved_errno;
		return SHA3_VARIANT_FILE_IO_ERROR;
	}
	if (fclose(file) != 0)
		return SHA3_VARIANT_FILE_IO_ERROR;
	sha256_final(&context, digest);
	for (size_t i = 0; i < sizeof(digest); ++i) {
		actual_sha256[2 * i] = hexadecimal[digest[i] >> 4];
		actual_sha256[2 * i + 1] = hexadecimal[digest[i] & 0x0f];
	}
	actual_sha256[64] = '\0';
	return strcmp(actual_sha256, expected_sha256) == 0 ?
		SHA3_VARIANT_FILE_OK : SHA3_VARIANT_FILE_DIGEST_MISMATCH;
}
