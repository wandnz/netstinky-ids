/**
 * Contains functions which operate on a byte array. This includes
 * functions which convert from a byte array into integers and
 * strings.
 */

#ifndef BYTE_ARRAY_H_
#define BYTE_ARRAY_H_

/*
 * All byte_array_read_xxx functions have the same usage:
 *
 * Reads a value from a byte array.
 * @param out The location to write the result to.
 * @param pos The position to begin the reading from.
 * @param buffer_end The first invalid address after the byte array.
 * @return The address of the first byte after the value or NULL if the value
 * could not be read.
 */

uint8_t *
byte_array_read_uint16(uint16_t *out, const uint8_t *pos,
		const uint8_t *buffer_end);

uint8_t *
byte_array_read_uint32(uint32_t *out, const uint8_t *pos,
		const uint8_t *buffer_end);

/*
 * All byte_array_write_xxx functions have the same usage:
 *
 * Write a value to a byte array.
 * @param value The value to write to the byte array.
 * @param pos The position to start writing to.
 * @param buffer_end The first invalid address after the byte array.
 * @return The address of the first byte after the written value, or NULL if
 * the value could not be written.
 */

uint8_t *
byte_array_write_uint16(uint16_t value, uint8_t *pos,
		const uint8_t *buffer_end);

uint8_t *
byte_array_write_uint32(uint32_t value, uint8_t *pos,
		const uint8_t *buffer_end);

#endif /* BYTE_ARRAY_H_ */
