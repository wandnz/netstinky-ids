/**
 * Contains functions which operate on a byte array. This includes
 * functions which convert from a byte array into integers and
 * strings.
 */

#ifndef BYTE_ARRAY_H_
#define BYTE_ARRAY_H_

uint16_t
byte_array_get_uint16(uint8_t *array);

uint32_t
byte_array_get_uint32(uint8_t *array);

void
byte_array_put_uint32(uint8_t *out_ptr, uint32_t value);

/*
 * Reads a uint16 from a byte array and updates the position pointer
 * into the array, and the remaining length in the array.
 *
 * Returns 1 if successful, 0 if unsuccessful.
 */
int
byte_array_read_uint16(uint16_t *out, uint8_t **array_pos,
		size_t *remaining_len);

int
byte_array_read_uint32(uint32_t *out, uint8_t **array_pos,
		size_t *remaining_len);

int
byte_array_write_uint16(uint8_t **pos_ptr, size_t *remaining_len,
		uint16_t value);

int
byte_array_write_uint32(uint8_t **pos_ptr, size_t *remaining_len,
		uint32_t value);

#endif /* BYTE_ARRAY_H_ */
