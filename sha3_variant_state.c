#define _GNU_SOURCE

#include "sha3_variant_state.h"

#include <errno.h>
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#define SHA3_VARIANT_STATE_MAX_LINES 512U
#define SHA3_VARIANT_STATE_LINE_BYTES 256U

static bool safe_component(const char *text, size_t maximum)
{
	size_t length;

	if (!text)
		return false;
	length = strlen(text);
	if (length == 0 || length > maximum)
		return false;
	for (size_t i = 0; i < length; ++i) {
		unsigned char c = (unsigned char)text[i];
		if (!((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') ||
		      (c >= '0' && c <= '9') || c == '-' || c == '_' || c == '.'))
			return false;
	}
	return true;
}

static bool valid_serial(const char *serial)
{
	return serial && *serial && !strchr(serial, '\n') &&
		!strchr(serial, '\r') && !strchr(serial, '=') &&
		!strchr(serial, ':') && !strchr(serial, '/');
}

static bool make_key(char *key, size_t size, const char *serial,
		unsigned fpga)
{
	int written;

	if (!key || !size || !valid_serial(serial)) {
		errno = EINVAL;
		return false;
	}
	written = snprintf(key, size, "%s:%u=", serial, fpga);
	if (written < 0 || (size_t)written >= size) {
		errno = ENAMETOOLONG;
		return false;
	}
	return true;
}

bool sha3_variant_state_lookup(const char *path, const char *serial,
		unsigned fpga, const char *family_id, char *state_id,
		size_t state_id_size, bool *found)
{
	char line[SHA3_VARIANT_STATE_LINE_BYTES];
	char key[96];
	FILE *input;
	size_t key_length;
	bool matched = false;

	if (!path || !*path || !safe_component(family_id, 63) ||
	    !state_id || state_id_size < 2 || !found ||
	    !make_key(key, sizeof(key), serial, fpga)) {
		errno = EINVAL;
		return false;
	}
	state_id[0] = '\0';
	*found = false;
	input = fopen(path, "r");
	if (!input)
		return errno == ENOENT;
	key_length = strlen(key);
	while (fgets(line, sizeof(line), input)) {
		char *newline;
		char *slash;
		char *value;
		size_t value_length;

		newline = strchr(line, '\n');
		if (!newline) {
			errno = EOVERFLOW;
			goto fail;
		}
		*newline = '\0';
		if (strncmp(line, key, key_length) != 0)
			continue;
		if (matched) {
			errno = EINVAL;
			goto fail;
		}
		matched = true;
		value = line + key_length;
		slash = strchr(value, '/');
		if (!slash || strchr(slash + 1, '/')) {
			errno = EINVAL;
			goto fail;
		}
		*slash = '\0';
		if (!safe_component(value, 63) || !safe_component(slash + 1, 63)) {
			errno = EINVAL;
			goto fail;
		}
		if (strcmp(value, family_id) != 0)
			continue;
		value_length = strlen(slash + 1);
		if (value_length >= state_id_size) {
			errno = ENAMETOOLONG;
			goto fail;
		}
		memcpy(state_id, slash + 1, value_length + 1);
		*found = true;
	}
	if (ferror(input)) {
		errno = errno ? errno : EIO;
		goto fail;
	}
	if (fclose(input) != 0)
		return false;
	return true;

fail:
	{
		int saved_errno = errno ? errno : EIO;
		fclose(input);
		state_id[0] = '\0';
		*found = false;
		errno = saved_errno;
		return false;
	}
}

bool sha3_variant_state_save_atomic(const char *path, const char *serial,
		unsigned fpga, const char *family_id, const char *state_id)
{
	char lines[SHA3_VARIANT_STATE_MAX_LINES][SHA3_VARIANT_STATE_LINE_BYTES];
	char key[64];
	char temporary[PATH_MAX];
	size_t count = 0;
	bool found = false;
	FILE *input = NULL;
	FILE *output = NULL;
	int fd = -1;
	int saved_errno = 0;
	int written;

	if (!path || !*path || !safe_component(family_id, 63) ||
	    !safe_component(state_id, 63) ||
	    !make_key(key, sizeof(key), serial, fpga)) {
		errno = EINVAL;
		return false;
	}
	written = snprintf(temporary, sizeof(temporary), "%s.tmp.XXXXXX", path);
	if (written < 0 || (size_t)written >= sizeof(temporary)) {
		errno = ENAMETOOLONG;
		return false;
	}

	input = fopen(path, "r");
	if (input) {
		while (count < SHA3_VARIANT_STATE_MAX_LINES &&
		       fgets(lines[count], sizeof(lines[count]), input)) {
			/* Reject truncated or unterminated records instead of copying an
			 * ambiguous key into the replacement file. */
			if (!strchr(lines[count], '\n')) {
				saved_errno = EOVERFLOW;
				goto fail;
			}
			if (strncmp(lines[count], key, strlen(key)) == 0) {
				if (found) {
					saved_errno = EINVAL;
					goto fail;
				}
				written = snprintf(lines[count], sizeof(lines[count]),
					"%s%s/%s\n", key, family_id, state_id);
				if (written < 0 ||
				    (size_t)written >= sizeof(lines[count])) {
					saved_errno = EOVERFLOW;
					goto fail;
				}
				found = true;
			}
			count++;
		}
		if (ferror(input)) {
			saved_errno = errno ? errno : EIO;
			goto fail;
		}
		if (!feof(input)) {
			saved_errno = E2BIG;
			goto fail;
		}
		if (fclose(input) != 0) {
			input = NULL;
			saved_errno = errno ? errno : EIO;
			goto fail;
		}
		input = NULL;
	} else if (errno != ENOENT) {
		return false;
	}

	if (!found && count == SHA3_VARIANT_STATE_MAX_LINES) {
		errno = E2BIG;
		return false;
	}

	fd = mkstemp(temporary);
	if (fd < 0)
		return false;
	output = fdopen(fd, "w");
	if (!output) {
		saved_errno = errno;
		goto fail;
	}
	fd = -1; /* output owns it */

	for (size_t i = 0; i < count; ++i) {
		if (fputs(lines[i], output) == EOF) {
			saved_errno = errno ? errno : EIO;
			goto fail;
		}
	}
	if (!found && fprintf(output, "%s%s/%s\n", key, family_id,
			state_id) < 0) {
		saved_errno = errno ? errno : EIO;
		goto fail;
	}
	if (fflush(output) != 0 || fsync(fileno(output)) != 0) {
		saved_errno = errno ? errno : EIO;
		goto fail;
	}
	if (fclose(output) != 0) {
		output = NULL;
		saved_errno = errno ? errno : EIO;
		goto fail;
	}
	output = NULL;
	if (rename(temporary, path) != 0) {
		saved_errno = errno;
		goto fail;
	}
	return true;

fail:
	if (input)
		fclose(input);
	if (output)
		fclose(output);
	else if (fd >= 0)
		close(fd);
	unlink(temporary);
	errno = saved_errno ? saved_errno : EIO;
	return false;
}
