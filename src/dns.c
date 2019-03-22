/*
 * mdns_control.c
 *
 *  Created on: 17/10/2018
 *      Author: mfletche
 */

/* TODO: Make setting rdlength automatic */

#include <stdlib.h>
#include <stddef.h>
#include <stdio.h>
#include <stdint.h>
#include <errno.h>
#include <assert.h>
#include <string.h>
#include <strings.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#include "utils/common.h"

#include "dns.h"
#include "utils/byte_array.h"


static const size_t DNS_HEADER_LEN = 12;

static const size_t MAX_LABEL_LEN = 63;
static const size_t MAX_NAME_LEN = 255;

/* -- MACROS -- */

/* -- PRIVATE FUNCTION DECLARATIONS -- */

size_t
dns_domain_compressed_length(const dns_domain domain_start,
		const uint8_t *packet_end);

int dns_label_is_compressed(const dns_domain label);

struct dns_answer *
dns_parse_answer_section(uint16_t num_answers, uint8_t **buf_pos,
		const uint8_t *packet_start, const uint8_t *packet_end);

dns_domain_literal
dns_parse_domain(uint8_t **buffer_pos, const uint8_t *packet_start,
		const uint8_t *packet_end);

uint8_t *
dns_parse_header(struct dns_packet *out, const uint8_t *packet_start,
		const uint8_t *packet_end);

struct dns_question *
dns_parse_question_section(uint16_t qn_num, uint8_t **packet_pos,
		const uint8_t *packet_start, const uint8_t *packet_end);

uint8_t *
dns_parse_rdata(union rdata_u *rdata, enum dns_qtype type,
		const uint8_t *rdata_start, const uint8_t *packet_start,
		const uint8_t *rdata_end);

uint8_t *
dns_write_answer_section(const struct dns_answer *answer, uint8_t *buffer_pos,
		const uint8_t *buffer_end);

uint8_t *
dns_write_domain(dns_domain_literal domain, uint8_t *pos,
		const uint8_t *buffer_end);

uint8_t *
dns_write_header(const struct dns_packet *packet, uint8_t *buffer_pos,
		const uint8_t *buffer_end);

uint8_t *
dns_write_question_section(const struct dns_packet *packet,
		uint8_t *buffer_pos, const uint8_t *buffer_end);

uint8_t *
dns_write_rdata(const union rdata_u rdata, const enum dns_qtype rdata_type,
		uint8_t *rdata_start, const uint8_t *buffer_end);

/* -- STATIC CHECKING FUNCTIONS -- */

static inline int
domain_length_ok(size_t length)
{
	return (length <= MAX_NAME_LEN);
}

static inline int
label_length_ok(size_t length)
{
	return (length <= MAX_LABEL_LEN);
}

/* -- STATIC FUNCTIONS -- */

/*
 * Does not check bounds. Use carefully */
static inline unsigned int
domain_pointer_offset(uint8_t *pointer)
{
	unsigned int offset = (*pointer++ & ~0xC0) << 8;
	offset |= *pointer;

	return (offset);
}

/* -- PUBLIC FUNCTIONS -- */

struct dns_answer *
dns_answer_list_copy(struct dns_answer *a)
{
	struct dns_answer *copy_head = NULL, *copy_tail = NULL, *tmp = NULL;
	while (a)
	{
		if (!(tmp = dns_answer_copy(a))) goto error;

		if (!copy_head) copy_head = tmp;
		if (copy_tail) copy_tail->next = tmp;
		copy_tail = tmp;

		a = a->next;
	}

	return (copy_head);

error:
	free_dns_answer(copy_head);
	return (NULL);
}

int
dns_domain_compare(dns_domain_literal a, dns_domain_literal b)
{
	/* domain names must be compared case-insensitively */
	/* TODO: Determine if this is safe to use */
	int r = strcasecmp((char *)a, (char *)b);
	return (r);
}

struct dns_packet *
dns_parse(uint8_t *packet_start, uint8_t *packet_end)
{
	assert(packet_start);
	assert(packet_end);
	assert(packet_start < packet_end);

	uint8_t *pkt_pos = packet_start;
	struct dns_packet *pkt = NULL;
	int count;

	if (packet_start && packet_end && packet_start < packet_end)
	{
		MALLOC_ZERO(pkt);
		if (!pkt)
		{
			DPRINT("dns_parse(): malloc() failed\n");
			goto error;
		}

		if (!(pkt_pos = dns_parse_header(pkt, pkt_pos, packet_end)))
		{
			DPRINT("dns_parse(): dns_parse_header() failed\n");
			goto error;
		}

		if ((count = pkt->header.qdcount))
		{
			if (!(pkt->questions = dns_parse_question_section(count, &pkt_pos,
					packet_start, packet_end)))
			{
				DPRINT("dns_parse(): dns_parse_question_section() failed\n");
				goto error;
			}
		}

		if ((count = pkt->header.ancount))
		{
			if (!(pkt->answers = dns_parse_answer_section(count, &pkt_pos, packet_start,
					packet_end)))
			{
				DPRINT("dns_parse(): dns_parse_answer_section(ancount) failed\n");
				goto error;
			}
		}

		if ((count = pkt->header.nscount))
		{
			if (!(pkt->answers = dns_parse_answer_section(count, &pkt_pos,
					packet_start, packet_end)))
			{
				DPRINT("dns_parse(): dns_parse_answer_section(nscount) failed\n");
				goto error;
			}
		}

		if ((count = pkt->header.arcount))
		{
			if (!(pkt->answers = dns_parse_answer_section(count, &pkt_pos,
					packet_start, packet_end)))
			{
				DPRINT("dns_parse(): dns_parse_answer_section(arcount) failed\n");
				goto error;
			}
		}
	}

	return (pkt);

error:
	/* reverse any operations done so far, free all structures */
	free_dns_packet(&pkt);
	return (NULL);
}

void
dns_print(struct dns_packet *pkt, FILE *fp)
{
	assert(pkt);
	assert(fp);

	fprintf(fp, "\n");
	fprintf(fp, " -- MESSAGE HEADER -- \n");
	fprintf(fp, "ID: %d\n", pkt->header.id);
	fprintf(fp, "QR: %d\n", pkt->header.qr);
	fprintf(fp, "OPCODE: %d\n", pkt->header.opcode);
	fprintf(fp, "AA: %d\n", pkt->header.aa);
	fprintf(fp, "TC: %d\n", pkt->header.tc);
	fprintf(fp, "RD: %d\n", pkt->header.rd);
	fprintf(fp, "RA: %d\n", pkt->header.ra);
	fprintf(fp, "Z: %d\n", pkt->header.z);
	fprintf(fp, "QDCOUNT: %d\n", pkt->header.qdcount);
	fprintf(fp, "ANCOUNT: %d\n", pkt->header.ancount);
	fprintf(fp, "NSCOUNT: %d\n", pkt->header.nscount);
	fprintf(fp, "ARCOUNT: %d\n", pkt->header.arcount);
	fprintf(fp, " -- QUESTION SECTION -- \n");
	struct dns_question *q = pkt->questions;
	while (q)
	{
		fprintf(fp, "QNAME: %s\n", q->qname);
		fprintf(fp, "QTYPE: %d\n", q->qtype);
		fprintf(fp, "QCLASS: %d\n", q->qclass);
		q = q->next;
	}
	fprintf(fp, " -- ANSWER SECTION -- \n");
	struct dns_answer *a = pkt->answers;
	while (a)
	{
		dns_answer_print(a, fp);
		a = a->next;
	}
	fprintf(fp, " -- AUTHORITY SECTION -- \n");
	a = pkt->authority;
	while (a)
	{
		dns_answer_print(a, fp);
		a = a->next;
	}
	fprintf(fp, " -- ADDITIONAL SECTION -- \n");
	a = pkt->additional;
	while (a)
	{
		dns_answer_print(a, fp);
		a = a->next;
	}
	fprintf(fp, "\n\n");
}

size_t dns_write(struct dns_packet *packet, uint8_t *buffer_start,
		uint8_t *buffer_end)
{
	assert(packet);
	assert(buffer_start);
	assert(buffer_end);

	uint8_t *buffer_pos = buffer_start;
	if (packet && buffer_start && buffer_end && buffer_start < buffer_end)
	{
		if (!(buffer_pos = dns_write_header(packet, buffer_pos, buffer_end))) goto error;
		if (!(buffer_pos = dns_write_question_section(packet, buffer_pos, buffer_end))) goto error;
		if (!(buffer_pos = dns_write_answer_section(packet->answers, buffer_pos, buffer_end))) goto error;
		if (!(buffer_pos = dns_write_answer_section(packet->authority, buffer_pos, buffer_end))) goto error;
		if (!(buffer_pos = dns_write_answer_section(packet->additional, buffer_pos, buffer_end))) goto error;
	}
	ptrdiff_t packet_len = buffer_pos - buffer_start;
	return (packet_len);

error:
	return (0);
}

/* -- PRIVATE FUNCTIONS -- */

struct dns_answer *
dns_answer_copy(struct dns_answer *a)
{
	struct dns_answer *copy = NULL;
	if (a && (copy = malloc(sizeof(*copy))))
	{
		memcpy(copy, a, sizeof(*copy));

		/* Create a new name string */
		copy->name = strdup(copy->name);

		switch(copy->type)
		{
		case SOA:
			copy->rdata.soa.mname = strdup(copy->rdata.soa.mname);
			copy->rdata.soa.rname = strdup(copy->rdata.soa.rname);
			break;
		case PTR:
			copy->rdata.ptr.name = strdup(copy->rdata.ptr.name);
			break;
		case SRV:
			copy->rdata.srv.target = strdup(copy->rdata.srv.target);
			break;
		}

		copy->next = NULL;
	}

	return (copy);
}

uint16_t
dns_answer_number(const struct dns_answer *ans_list)
{
	uint16_t count = 0;
	struct dns_answer *ans_pos = (struct dns_answer *)ans_list;
	while (ans_pos)
	{
		count++;
		ans_pos = ans_pos->next;
	}
	return (count);
}

void
dns_answer_print(struct dns_answer *a, FILE *fp)
{
	assert(a);
	assert(fp);

	struct in_addr addr;

	fprintf(fp, "NAME: %s\n", a->name);
	fprintf(fp, "TYPE: %d\n", a->type);
	fprintf(fp, "CLASS: %d\n", a->class);
	fprintf(fp, "TTL: %d\n", a->ttl);
	fprintf(fp, "RLENGTH: %d\n", a->rdlength);
	switch(a->type)
	{
	case A:
		addr.s_addr = htonl(a->rdata.a.ip_address);
		fprintf(fp, "IP ADDRESS: %s\n", inet_ntoa(addr));
		break;
	case MX:
		fprintf(fp, "PREFERENCE: %d\n", a->rdata.mx.preference);
		fprintf(fp, "MAIL EXCHANGER: %s\n", a->rdata.mx.mail_exchanger);
		break;
	case PTR:
		fprintf(fp, "NAME: %s\n", a->rdata.ptr.name);
		break;
	case SOA:
		/* TODO: Find out order of mname, rname */
		fprintf(fp, "PRIMARY NS: %s\n", a->rdata.soa.rname);
		fprintf(fp, "ADMIN MB: %s\n", a->rdata.soa.mname);
		fprintf(fp, "SERIAL NUMBER: %d\n", a->rdata.soa.serial);
		fprintf(fp, "REFRESH INTERVAL: %d\n", a->rdata.soa.refresh);
		fprintf(fp, "RETRY INTERVAL: %d\n", a->rdata.soa.retry);
		fprintf(fp, "EXPIRATION LIMIT: %d\n", a->rdata.soa.expire);
		fprintf(fp, "MINIMUM TTL: %d\n", a->rdata.soa.minimum);
		break;
	case SRV:
		fprintf(fp, "PRIORITY: %d\n", a->rdata.srv.priority);
		fprintf(fp, "WEIGHT: %d\n", a->rdata.srv.weight);
		fprintf(fp, "PORT: %d\n", a->rdata.srv.port);
		fprintf(fp, "TARGET: %s\n", a->rdata.srv.target);
		break;
	default:
		fprintf(fp, "Unknown format: %d\n", a->type);
		break;
	}
}

/** Get the actual length that a compressed domain name takes up.
 *
 */
size_t
dns_domain_compressed_length(const dns_domain domain_start,
		const uint8_t *packet_end)
{
	assert(domain_start);
	assert(packet_end);

	unsigned int length_total = 0;
	unsigned int length_label = 0;
	uint8_t *pos = domain_start;
	if (domain_start && packet_end)
	{
		while (pos < packet_end)
		{
			if (dns_label_is_compressed(pos))
			{
				/* Pointer is two bytes long */
				length_total += 2;
				break;
			}

			/* This includes the length byte. */
			length_label = *pos + 1;
			if (!label_length_ok(length_label)) goto error;

			length_total += length_label;
			if (!domain_length_ok(length_total)) goto error;

			/* Complete if length byte is 0. */
			if (length_label <= 1) break;

			pos += length_label;
		}

	}

	return (length_total);

error:
	return (0);
}

/**
 * Gets the position of a label if it is compressed.
 */
dns_domain
dns_label_dereference_pointer(const dns_domain pointer, const uint8_t *packet_start, const uint8_t *packet_end)
{
	assert(packet_start);
	assert(packet_end);
	assert(packet_start <= pointer && pointer < packet_end);
	unsigned int offset;
	dns_domain dest = NULL;

	if (packet_start && packet_end)
	{
		/* Make sure that it is a pointer, not a length byte */
		assert((*pointer & 0xC0) == 0xC0);

		offset = domain_pointer_offset(pointer);
		dest = (dns_domain)(packet_start + offset);

		/* Destination must be before the pointer and within packet bounds */
		if (dest >= pointer || dest >= packet_end) return (NULL);
	}

	return (dest);
}

/**
 * Get the length of a domain name when uncompressed.
 * @param packet_start The start of the DNS packet.
 * @param packet_end The first byte after the DNS packet.
 * @param domain_start The start of the domain name.
 * @return The bytes required to contain the uncompressed domain name.
 */
size_t dns_domain_uncompressed_length( const dns_domain domain_start,
		const uint8_t *packet_start, const uint8_t *packet_end)
{
	assert(packet_start);
	assert(packet_end);
	assert(domain_start);

	unsigned int label_len = 0;
	unsigned int total_len = 0;
	dns_domain label_start = domain_start;

	while (packet_start <= label_start && label_start < packet_end)
	{
		/* Dereference DNS label pointer */
		if (dns_label_is_compressed(label_start))
			if (!(label_start = dns_label_dereference_pointer(label_start, packet_start, packet_end)))
				goto error;

		/* This includes the length byte. */
		label_len = *label_start + 1;
		if (!label_length_ok(label_len)) goto error;

		total_len += label_len;
		if (!domain_length_ok(total_len)) goto error;

		/* Complete if length byte is 0. */
		if (label_len == 1) break;

		label_start += label_len;

	}

	return ((size_t)total_len);

error:
	return (0);
}

/**
 * Determines if a label is compressed.
 *
 * @param label A pointer to what is either the length byte or the index to
 * the repeated DNS string.
 * @return 1 if the label is compressed, 0 if not, -1 if an error occurred.
 */
int dns_label_is_compressed(const dns_domain label)
{
	assert(label);

	int result = -1;

	if (label)
	{
		/* If most-significant two bits are set, label is compressed */
		if ((label[0] & 0xC0) == 0xC0) result = 1;
		else result = 0;
	}

	return (result);
}

struct dns_answer *
dns_parse_answer(uint8_t **buf_pos,
		const uint8_t *packet_start, const uint8_t *packet_end)
{
	assert(buf_pos);
	assert(packet_start);
	assert(packet_end);
	assert(packet_start <= *buf_pos && *buf_pos < packet_end);

	struct dns_answer *ans = NULL;

	if (!(ans = new_dns_answer())) goto error;
	if (!(ans->name = dns_parse_domain(buf_pos, packet_start, packet_end)))
			goto error;

	if (!(*buf_pos = byte_array_read_uint16(&(ans->type), *buf_pos, packet_end))) goto error;
	if (!(*buf_pos = byte_array_read_uint16(&(ans->class), *buf_pos, packet_end))) goto error;
	if (!(*buf_pos = byte_array_read_uint32(&(ans->ttl), *buf_pos, packet_end))) goto error;
	if (!(*buf_pos = byte_array_read_uint16(&(ans->rdlength), *buf_pos, packet_end))) goto error;

	if (!dns_parse_rdata(&(ans->rdata), ans->type, *buf_pos, packet_start,
			*buf_pos + ans->rdlength))
		goto error;

	return (ans);

error:
	free_dns_answer(ans);
	return (NULL);
}

uint16_t
dns_question_number(const struct dns_question *qn_list)
{
	uint16_t count = 0;
	while (qn_list)
	{
		count++;
		qn_list = qn_list->next;
	}
	return (count);
}

char *
dns_name_to_readable(uint8_t *name)
{
	assert(name);

	size_t name_len = strlen((char *)name), remaining = name_len;
	char *readable = NULL, *readable_pos = NULL;
	uint8_t *label_ptr = name;
	size_t label_len = 0;

	if (name_len > MAX_NAME_LEN) goto error;

	readable = malloc(name_len);
	if (!readable) goto error;
	readable_pos = readable;

	label_len = *label_ptr;
	if (label_len > MAX_LABEL_LEN) goto error;

	label_ptr++;

	while (label_len && label_len <= remaining)
	{
		/* Move to position after length byte */
		strncpy(readable_pos, (char *)label_ptr, label_len);

		/* Move to next length byte */
		readable_pos += label_len;
		label_ptr += label_len;
		remaining -= label_len + 1;

		/* Get length byte */
		label_len = *label_ptr;
		label_ptr++;

		/* Add '.' */
		if (label_len)
		{
			*readable_pos = '.';
			readable_pos++;
		}
	}

	*readable_pos = 0;

	return (readable);

error:
	if (readable) free(readable);
	return (NULL);
}

uint8_t *
dns_domain_to_name(char *domain)
{
	assert(domain);

	/* declare early so cleanup on error works */
	char *name = NULL, *cpy = NULL;

	/* don't continue if it's obviously too long */
	size_t name_len = strlen(domain) + 3;
	if (name_len > MAX_NAME_LEN) goto error;

	/* allow space for NULL terminator AND an initial length byte */
	name = malloc(name_len);
	if (!name) goto error;

	uint8_t *name_pos = (uint8_t *)name;
	cpy = strdup(domain);
	if (!cpy) goto error;

	char *token = NULL;
	for (token = strtok(cpy, "."); token; token = strtok(NULL, "."))
	{
		size_t token_len = strlen(token);
		if (token_len > MAX_LABEL_LEN) goto error;

		*name_pos = token_len;
        (void)(name_pos++), name_len--;
		int r = snprintf((char *)name_pos, name_len, "%s", token);
		if (r < 0) goto error;

		/* the NULL terminator should be written over with the next
		 * length */
		name_pos += r;
		name_len -= r;
	}

	free(cpy);
	return ((uint8_t *)name);

error:
	if (name) free(name);
	if (cpy) free(cpy);
	return (NULL);
}

struct dns_answer *
dns_parse_answer_section(uint16_t num_answers, uint8_t **buf_pos,
		const uint8_t *packet_start, const uint8_t *packet_end)
{
	assert(buf_pos);
	assert(*buf_pos);
	assert(packet_start);
	assert(packet_end);

	struct dns_answer *first_answer = NULL;
	struct dns_answer *last_answer = NULL;
	uint16_t i;

	for (i = 0; i < num_answers; i++)
	{
		struct dns_answer *new_answer = NULL;
		if (!(new_answer = dns_parse_answer(buf_pos, packet_start, packet_end)))
			goto error;

		if (NULL == last_answer)
			first_answer = last_answer = new_answer;
		else
		{
			last_answer->next = new_answer;
			last_answer = last_answer->next;
		}
	}

	return (first_answer);

error:
	free_dns_answer(first_answer);
	return (NULL);
}

dns_domain_literal
dns_parse_domain(uint8_t **buffer_pos, const uint8_t *packet_start,
		const uint8_t *packet_end)
{
	assert(buffer_pos);
	assert(*buffer_pos);
	assert(packet_start);
	assert(packet_end);

	dns_domain_literal domain_out = NULL;
	dns_domain_literal domain_out_pos = NULL;
	dns_domain domain_in_pos = NULL;
	size_t total_length, label_length;

	/* Find out length of domain literal */
	if (!(total_length
			= dns_domain_uncompressed_length(*buffer_pos, packet_start,
					packet_end)))
		goto error;

	if (!(domain_out = malloc(total_length))) goto error;
	domain_out_pos = domain_out;
	domain_in_pos = *buffer_pos;

	while (domain_in_pos < packet_end)
	{
		if (dns_label_is_compressed(domain_in_pos)
			&& !(domain_in_pos = dns_label_dereference_pointer(domain_in_pos, packet_start, packet_end)))
				goto error;

		/* Checks on label length have already been performed when getting the
		 * length so don't need to do those again. */
		label_length = *domain_in_pos + 1;

		/* Copy label. Won't be NULL terminated until after last label has been
		 * copied. */
		strncpy((char *)domain_out_pos, (char *)domain_in_pos, label_length);

		if (label_length <= 1) break;	/* Done */

		domain_in_pos += label_length;
		domain_out_pos += label_length;
	}

	*buffer_pos = *buffer_pos + dns_domain_compressed_length(*buffer_pos,
			packet_end);

	return (domain_out);

error:
	if (domain_out) free(domain_out);
	return (NULL);
}

uint8_t *
dns_parse_header(struct dns_packet *out, const uint8_t *packet_start,
		const uint8_t *packet_end)
{
	assert(out);
	assert(packet_start);
	assert(packet_end);

	uint8_t *packet_pos = (uint8_t *)packet_start;
	if (packet_end < packet_pos + DNS_HEADER_LEN) goto error;

	struct dns_header h = out->header;

	packet_pos = byte_array_read_uint16(&(h.id), packet_pos, packet_end);
	h.qr = (*packet_pos & 0x80) >> 7;
	h.opcode = (*packet_pos & 0x78) >> 3;
	h.aa = (*packet_pos & 0x04) >> 2;
	h.tc = (*packet_pos & 0x02) >> 1;
	h.rd = (*packet_pos & 0x01);
	packet_pos++;
	h.ra = (*packet_pos & 0x80) >> 7;
	h.z = (*packet_pos & 0x70) >> 4;
	h.rcode = (*packet_pos & 0x0F);
	packet_pos++;
	packet_pos = byte_array_read_uint16(&(h.qdcount), packet_pos, packet_end);
	packet_pos = byte_array_read_uint16(&(h.ancount), packet_pos, packet_end);
	packet_pos = byte_array_read_uint16(&(h.nscount), packet_pos, packet_end);
	packet_pos = byte_array_read_uint16(&(h.arcount), packet_pos, packet_end);

	out->header = h;

	return (packet_pos);

error:
	return (0);
}

struct dns_question *
dns_parse_question(uint8_t **out, const uint8_t *packet_start,
		const uint8_t *packet_end)
{
	assert(out);
	assert(*out);
	assert(packet_start);
	assert(packet_end);

	struct dns_question *qn = new_dns_question();
	if (!qn)
	{
		DPRINT("dns_parse_question(): new_dns_question() failed\n");
		goto error;
	}

	qn->qname = dns_parse_domain(out, packet_start, packet_end);
	if (!qn->qname)
	{
		DPRINT("dns_parse_question(): dns_parse_name() failed\n");
		goto error;
	}

	if (!(*out = byte_array_read_uint16(&(qn->qtype), *out, packet_end)))
	{
		DPRINT("dns_parse_question(): byte_array_read_uint16() failed\n");
		goto error;
	}

	if (!(*out = byte_array_read_uint16(&(qn->qclass), *out, packet_end)))
	{
		DPRINT("dns_parse_question(): byte_array_read_uint16() failed\n");
		goto error;
	}

	return (qn);

error:
	free_dns_question(qn);
	return (NULL);
}

struct dns_question *
dns_parse_question_section(uint16_t qn_num, uint8_t **packet_pos,
		const uint8_t *packet_start, const uint8_t *packet_end)
{
	assert(packet_pos);
	assert(*packet_pos);
	assert(packet_start);
	assert(packet_end);

	struct dns_question *q_list_head = NULL, *q_list_tail = NULL;
	int i;

	for (i = qn_num; i > 0; i--)
	{
		struct dns_question *new_qn = dns_parse_question(packet_pos,
				packet_start, packet_end);
		if (!new_qn)
		{
			DPRINT("dns_parse_question_section(): dns_parse_question() failed\n");
			goto error;
		}

		if (!q_list_tail)
			q_list_tail = q_list_head = new_qn;
		else
		{
			q_list_tail->next = new_qn;
			q_list_tail = q_list_tail->next;
		}
	}

	return (q_list_head);

error:
	free_dns_question(q_list_head);
	return (NULL);
}

uint8_t *
dns_parse_rdata(union rdata_u *rdata, enum dns_qtype type, const uint8_t *rdata_start,
		const uint8_t *packet_start, const uint8_t *rdata_end)
{
	assert(rdata);
	assert(rdata_start);
	assert(packet_start);
	assert(rdata_end);

	uint8_t *rdata_pos = (uint8_t *)rdata_start;

	switch(type)
	{
	case(A):
		if (!(rdata_pos = byte_array_read_uint32(&(rdata->a.ip_address),
				rdata_start, rdata_end)))
			return (0);
		break;
	case(NS):
		/* no break: NS and PTR have the same format */
	case(PTR):
		if (!(rdata->ptr.name = dns_parse_domain(&rdata_pos, packet_start,
				rdata_end)))
			goto error;
		break;
	case(MD):
		break;
	case(MF):
		break;
	case(CNAME):
		break;
	case(SOA):
		if (!(rdata->soa.mname = dns_parse_domain(&rdata_pos, packet_start,
				rdata_end)))
			goto soa_error;

		if (!(rdata->soa.rname = dns_parse_domain(&rdata_pos, packet_start,
				rdata_end)))
			goto soa_error;

		if (!(rdata_pos = byte_array_read_uint32(&(rdata->soa.serial),
				rdata_pos, rdata_end)))
			goto soa_error;
		if (!(rdata_pos = byte_array_read_uint32(&(rdata->soa.refresh),
				rdata_pos, rdata_end)))
			goto soa_error;
		if (!(rdata_pos = byte_array_read_uint32(&(rdata->soa.retry),
				rdata_pos, rdata_end)))
			goto soa_error;
		if (!(rdata_pos = byte_array_read_uint32(&(rdata->soa.expire),
				rdata_pos, rdata_end)))
			goto soa_error;
		if (!(rdata_pos = byte_array_read_uint32(&(rdata->soa.minimum),
				rdata_pos, rdata_end)))
			goto soa_error;
		break;
		/* SOA specific cleanup */
soa_error:
		if (rdata->soa.mname)
		{
			free(rdata->soa.mname);
			rdata->soa.mname = NULL;
		}
		if (rdata->soa.rname)
		{
			free(rdata->soa.rname);
			rdata->soa.rname = NULL;
		}
		goto error;
		break;
	case(MB):
		break;
	case(MG):
		break;
	case(MR):
		break;
	case(NULL_TYPE):
		break;
	case(WKS):
		break;
	case(HINFO):
		break;
	case(MINFO):
		break;
	case(MX):
		break;
	case(TXT):
		break;
	case(SRV):
		if (!(rdata_pos = byte_array_read_uint16(&(rdata->srv.priority), rdata_pos, rdata_end))) goto srv_error;
		if (!(rdata_pos = byte_array_read_uint16(&(rdata->srv.weight), rdata_pos, rdata_end))) goto srv_error;
		if (!(rdata_pos = byte_array_read_uint16(&(rdata->srv.port), rdata_pos, rdata_end))) goto srv_error;
		if (!(rdata->srv.target = dns_parse_domain(&rdata_pos, packet_start, rdata_end))) goto srv_error;
		break;
srv_error:
		if (rdata->srv.target)
		{
			free(rdata->srv.target);
			rdata->srv.target = NULL;
		}
		goto error;
		break;
	default:
		break;
	}

	return (rdata_pos);

error:
	return (NULL);
}

uint8_t *
dns_write_answer(const struct dns_answer *answer, uint8_t *answer_start,
		const uint8_t *buffer_end)
{
	assert(answer);
	assert(answer_start);
	assert(buffer_end);
	uint8_t *answer_pos = (uint8_t *)answer_start;

	if (!(answer_pos = dns_write_domain(answer->name, answer_pos, buffer_end)))
		goto error;
	if (!(answer_pos = byte_array_write_uint16(answer->type, answer_pos, buffer_end)))
		goto error;
	if (!(answer_pos = byte_array_write_uint16(answer->class, answer_pos, buffer_end)))
		goto error;
	if (!(answer_pos = byte_array_write_uint32(answer->ttl, answer_pos, buffer_end)))
		goto error;
	if (!(answer_pos = byte_array_write_uint16(answer->rdlength, answer_pos, buffer_end)))
		goto error;

	if (!(answer_pos = dns_write_rdata(answer->rdata, answer->type, answer_pos, buffer_end)))
		goto error;

	return (answer_pos);

error:
	return (NULL);
}

/* Unlike the write_question_section function, this function does not
 * take the packet as an argument. This is because there are three
 * different sections with the same answer format so more specifics
 * must be provided */
uint8_t *
dns_write_answer_section(const struct dns_answer *answer, uint8_t *buffer_pos,
		const uint8_t *buffer_end)
{
	assert(buffer_pos);
	assert(buffer_end);

	struct dns_answer *list_pos = (struct dns_answer *)answer;

	if (answer)
	{
		int i;
		for (i = dns_answer_number(answer); i > 0; i--)
		{
			assert(list_pos);
			if (!(buffer_pos = dns_write_answer(list_pos, buffer_pos, buffer_end)))
				return (0);
		}
	}

	return (buffer_pos);
}

uint8_t *
dns_write_header(const struct dns_packet *packet, uint8_t *buffer_pos,
		const uint8_t *buffer_end)
{
	assert(packet);
	assert(buffer_pos);
	assert(buffer_end);

	uint8_t *packet_pos = (uint8_t *)buffer_pos;
	struct dns_header h = packet->header;
	if (buffer_end - buffer_pos >= DNS_HEADER_LEN)
	{
		if (!(packet_pos = byte_array_write_uint16(h.id, packet_pos, buffer_end)))
			goto error;

		uint8_t bit_field = 0;
		bit_field |= h.qr << 7;
		bit_field |= h.opcode << 3;
		bit_field |= h.aa << 2;
		bit_field |= h.tc << 1;
		bit_field |= h.rd;

		*packet_pos = bit_field;
		packet_pos++;

		bit_field = 0;
		bit_field |= h.ra << 7;
		bit_field |= h.z << 4;
		bit_field |= h.rcode;

		*packet_pos = bit_field;
		packet_pos++;

		h.qdcount = dns_question_number(packet->questions);
		h.ancount = dns_answer_number(packet->answers);
		h.nscount = dns_answer_number(packet->authority);
		h.arcount = dns_answer_number(packet->additional);

		if (!(packet_pos = byte_array_write_uint16(h.qdcount, packet_pos, buffer_end))) goto error;
		if (!(packet_pos = byte_array_write_uint16(h.ancount, packet_pos, buffer_end))) goto error;
		if (!(packet_pos = byte_array_write_uint16(h.nscount, packet_pos, buffer_end))) goto error;
		if (!(packet_pos = byte_array_write_uint16(h.arcount, packet_pos, buffer_end))) goto error;
	}

	return (packet_pos);
error:
	return (NULL);
}

uint8_t *
dns_write_question(const struct dns_question *qn, uint8_t *buffer_pos,
		const uint8_t *buffer_end)
{
	assert(qn);
	assert(buffer_pos);
	assert(buffer_end);

	if (!(buffer_pos = dns_write_domain(qn->qname, buffer_pos, buffer_end)))
		goto error;
	if (!(buffer_pos = byte_array_write_uint16(qn->qtype, buffer_pos, buffer_end)))
		goto error;
	if (!(buffer_pos = byte_array_write_uint16(qn->qclass, buffer_pos, buffer_end)))
		goto error;

	return (buffer_pos);
error:
	return (NULL);
}

/* This requires the entire packet structure because I wanted to
 * check the qncount */
uint8_t *
dns_write_question_section(const struct dns_packet *packet,
		uint8_t *buffer_pos, const uint8_t *buffer_end)
{
	assert(packet);
	assert(buffer_pos);
	assert(buffer_end);

	struct dns_question *q = packet->questions;
	int q_len = dns_question_number(packet->questions);
	int i;
	uint8_t *q_section_end = buffer_pos;
	for (i = q_len; i > 0; i--)
	{
		assert(q);	/* Should never have a NULL pointer */
		if (!(q_section_end = dns_write_question(q, buffer_pos, buffer_end)))
			return (NULL);

		q = q->next;
	}

	return (q_section_end);
}

uint8_t *
dns_write_domain(dns_domain_literal domain, uint8_t *pos,
		const uint8_t *buffer_end)
{
	assert(domain);
	assert(pos);
	assert(buffer_end);

	size_t max_len = buffer_end - pos;
	int domain_len = snprintf((char *)pos, max_len, "%s", domain);
	if (domain_len < 0 || domain_len > max_len) return (NULL);

	/* Include space for NULL terminator */
	return (pos + domain_len + 1);
}

uint8_t *
dns_write_rdata(const union rdata_u rdata, const enum dns_qtype rdata_type,
		uint8_t *rdata_start, const uint8_t *buffer_end)
{
	assert(rdata_start);
	assert(buffer_end);

	uint8_t *rdata_pos = rdata_start;
	switch(rdata_type)
	{
	case(A):
		if (!(rdata_pos = byte_array_write_uint32(rdata.a.ip_address, rdata_pos, buffer_end)))
			goto error;
		break;
	case(NS):
		/* no break: NS and PTR have the same format */
	case(PTR):
		if (!(rdata_pos = dns_write_domain(rdata.ptr.name, rdata_pos, buffer_end)))
			goto error;
		break;
	case(MD):
		break;
	case(MF):
		break;
	case(CNAME):
		break;
	case(SOA):
		if (!(rdata_pos = dns_write_domain(rdata.soa.mname, rdata_pos, buffer_end)))
			goto error;
		if (!(rdata_pos = dns_write_domain(rdata.soa.rname, rdata_pos, buffer_end)))
			goto error;
		if (!(rdata_pos = byte_array_write_uint32(rdata.soa.serial, rdata_pos, buffer_end)))
			return (0);
		if (!(rdata_pos = byte_array_write_uint32(rdata.soa.refresh, rdata_pos, buffer_end)))
			return (0);
		if (!(rdata_pos = byte_array_write_uint32(rdata.soa.retry, rdata_pos, buffer_end)))
			return (0);
		if (!(rdata_pos = byte_array_write_uint32(rdata.soa.expire, rdata_pos, buffer_end)))
			return (0);
		if (!(rdata_pos = byte_array_write_uint32(rdata.soa.minimum, rdata_pos, buffer_end)))
			return (0);
		break;
	case(MB):
		break;
	case(MG):
		break;
	case(MR):
		break;
	case(NULL_TYPE):
		break;
	case(WKS):
		break;
	case(HINFO):
		break;
	case(MINFO):
		break;
	case(MX):
		break;
	case(TXT):
		break;
	case(SRV):
		if (!(rdata_pos = byte_array_write_uint16(rdata.srv.priority, rdata_pos, buffer_end)))
			goto error;
		if (!(rdata_pos = byte_array_write_uint16(rdata.srv.weight, rdata_pos, buffer_end)))
			goto error;
		if (!(rdata_pos = byte_array_write_uint16(rdata.srv.port, rdata_pos, buffer_end)))
			goto error;
		if (!(rdata_pos = dns_write_domain(rdata.srv.target, rdata_pos, buffer_end)))
			goto error;
		break;
	default:
		break;
	}

	return (rdata_pos);

error:
	return (NULL);
}

int
rr_collection_add_record(struct rr_collection **head, dns_domain_literal name,
		struct dns_answer *record)
{
	assert(head);
	assert(name);
	assert(record);

	struct rr_collection *collection_tail = NULL;
	struct rr_collection **new_record_ptr = NULL;
	struct rr_collection *c = rr_collection_search(*head, name);
	struct dns_answer *record_tail = NULL;

	if (!c)
	{
		/* No existing collection with that name so add to end of
		 * list */
		if (*head)
		{
			/* Find tail of list */
			collection_tail = *head;
			while (collection_tail->next) collection_tail = collection_tail->next;
			new_record_ptr = &(collection_tail->next);
		}
		else new_record_ptr = head;

		struct rr_collection *new_record = malloc(sizeof(*new_record));
		if (!new_record)
		{
			/* Adding failed so this function is responsible for
			 * cleanup */
			free(name);
			free_dns_answer(record);
			return (0);
		}

		/* IMPORTANT: Haven't duplicated name, so this function needs
		 * to be provided with its own copy. This could be as simple
		 * as calling dns_domain_to_name() on a constant. */
		new_record->name = name;
		new_record->records = record;
		new_record->next = NULL;

		/* Save to collection */
		*new_record_ptr = new_record;
	}
	else
	{
		/* There is already a collection with that name. */
		record_tail = c->records;
		while (record_tail->next) record_tail = record_tail->next;

		/* TODO: Are duplicate records a problem? If yes, then need
		 * to check prior to adding to the list. */
		record_tail->next = record;
	}

	return (1);
}

struct rr_collection *
rr_collection_search(struct rr_collection *head,
		const dns_domain_literal name)
{
	/* This function accepts a NULL collection as it could be empty */
	assert(name);

	while (head)
	{
		/* It is a mistake to have any records without a name */
		assert(head->name);
		if (dns_domain_compare(name, head->name) == 0) return (head);

		head = head->next;
	}

	return (NULL);
}

void free_dns_answer(struct dns_answer *ans)
{
	if (ans)
	{
		if (ans->name) free(ans->name);
		free_dns_rdata(ans);
		if (ans->next) free_dns_answer(ans->next);

		free(ans);
	}
}

void free_dns_packet(struct dns_packet **packet)
{
	assert(packet);
	if (*packet)
	{
		free_dns_question((*packet)->questions);
		free_dns_answer((*packet)->answers);
		free_dns_answer((*packet)->authority);
		free_dns_answer((*packet)->additional);

		free(*packet);
		*packet = NULL;
	}
}

void free_dns_question(struct dns_question *qn)
{
	if (qn)
	{
		if (qn->qname) free(qn->qname);
		if (qn->next) free_dns_question(qn->next);

		free(qn);
	}
}

void
free_dns_rdata(struct dns_answer *ans)
{
	assert(ans);

	switch(ans->type)
	{
	case A:
		break;
	case NS:
		/* no break: NS and PTR have same format */
	case PTR:
		if (NULL != ans->rdata.ptr.name) free(ans->rdata.ptr.name);
		break;
	case CNAME:
		break;
	case SOA:
		if (NULL != ans->rdata.soa.mname) free(ans->rdata.soa.mname);
		if (NULL != ans->rdata.soa.rname) free(ans->rdata.soa.rname);
		break;
	case(MB):
		break;
	case(MG):
		break;
	case(MR):
		break;
	case(NULL_TYPE):
		break;
	case(WKS):
		break;
	case(HINFO):
		break;
	case(MINFO):
		break;
	case(MX):
		break;
	case(TXT):
		break;
	case(SRV):
		if (NULL != ans->rdata.srv.target) free(ans->rdata.srv.target);
		break;
	default:
		break;
	}

	return;
}

void
free_rr_collection(struct rr_collection *c)
{
	struct rr_collection *next = NULL;
	if (c)
	{
		do
		{
			next = c->next;
			free(c->name);
			free_dns_answer(c->records);
			free(c);
			c = next;
		} while (next);
	}
}

struct dns_answer *
new_dns_answer()
{
	struct dns_answer *ans = malloc(sizeof(*ans));
	if (ans)
	{
		memset(ans, 0, sizeof(*ans));
	}

	return (ans);
}

struct dns_question *
new_dns_question()
{
	struct dns_question *qn = malloc(sizeof(*qn));
	if (qn)
	{
		memset(qn, 0, sizeof(*qn));
	}

	return (qn);
}
