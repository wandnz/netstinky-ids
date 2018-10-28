#include <stdlib.h>
#include <stdint.h>
#include <assert.h>
#include "byte_array.h"

uint16_t
byte_array_get_uint16(uint8_t *array)
{
	assert(NULL != array);

	uint16_t result = ((array[0] & 0xFF) << 8)
			| ((array[1] & 0xFF) << 0);

	return (result);
}

void
byte_array_put_uint16(uint8_t *out_ptr, uint16_t value)
{
	assert(NULL != out_ptr);

	out_ptr[0] = (value >> 8) & (0xFF);
	out_ptr[1] = value & (0xFF);
}

void
byte_array_put_uint32(uint8_t *out_ptr, uint32_t value)
{
	assert(NULL != out_ptr);

	out_ptr[0] = value & (0xFF << 24);
	out_ptr[1] = value & (0xFF << 16);
	out_ptr[2] = value & (0xFF << 8);
	out_ptr[3] = value & (0xFF);
}

int
byte_array_read_uint16(uint16_t *out, uint8_t **array_pos, size_t *remaining_len)
{
	assert(NULL != out);
	assert(NULL != array_pos);
	assert(NULL != remaining_len);

	if (sizeof(*out) < *remaining_len)
	{
		*out = byte_array_get_uint16(*array_pos);
		(*array_pos) += sizeof(*out);
		(*remaining_len) -= sizeof(*out);

		return (1);
	}

	return (0);
}

int
byte_array_write_uint16(uint8_t **pos_ptr, size_t *remaining_len, uint16_t value)
{
	assert(NULL != pos_ptr);
	assert(NULL != *pos_ptr);
	assert(NULL != remaining_len);

	if (*remaining_len >= sizeof(value))
	{
		byte_array_put_uint16(*pos_ptr, value);
		(*pos_ptr) += sizeof(value);
		(*remaining_len) -= sizeof(value);

		return (1);
	}

	return (0);
}

uint32_t
byte_array_get_uint32(uint8_t *array)
{
	assert(NULL != array);

	uint32_t result = ((array[0] & 0xFF) << 24)
			| ((array[1] & 0xFF) << 16)
			| ((array[2] & 0xFF) << 8)
			| ((array[3] & 0xFF) << 0);

	return (result);
}

int
byte_array_read_uint32(uint32_t *out, uint8_t **array_pos, size_t *remaining_len)
{
	assert(NULL != out);
	assert(NULL != array_pos);
	assert(NULL != remaining_len);

	if (sizeof(*out) < *remaining_len)
	{
		*out = byte_array_get_uint32(*array_pos);
		(*array_pos) += sizeof(*out);
		(*remaining_len) -= sizeof(*out);

		return (1);
	}

	return (0);
}

int
byte_array_write_uint32(uint8_t **pos_ptr, size_t *remaining_len, uint32_t value)
{
	assert(NULL != pos_ptr);
	assert(NULL != *pos_ptr);
	assert(NULL != remaining_len);

	if (*remaining_len < sizeof(value)) goto error;
	byte_array_put_uint32(*pos_ptr, value);
	(*pos_ptr) += sizeof(value);
	(*remaining_len) -= sizeof(value);

	return (1);

error:
	return (0);
}
