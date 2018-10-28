/*
 * mdns_control.c
 *
 *  Created on: 17/10/2018
 *      Author: mfletche
 */

#include <stdlib.h>
#include <stddef.h>
#include <stdio.h>
#include <stdint.h>
#include <errno.h>
#include <assert.h>
#include <string.h>
#include <strings.h>
#include <sys/socket.h>
#include "dns.h"
#include "byte_array.h"

static const size_t MAX_PKT_SIZE = 65535;
static const size_t DNS_HEADER_LEN = 12;

static const size_t MAX_LABEL_LEN = 63;
static const size_t MAX_NAME_LEN = 255;
static const size_t MAX_UDP_MSG_LEN = 512;

uint16_t
count_answers(struct dns_answer *ans_list)
{
	uint16_t count = 0;
	while (ans_list)
	{
		count++;
		ans_list = ans_list->next;
	}
	return (count);
}

uint16_t
count_questions(struct dns_question *qn_list)
{
	uint16_t count = 0;
	while (qn_list)
	{
		count++;
		qn_list = qn_list->next;
	}
	return (count);
}

int
dns_compare_names(uint8_t *a, uint8_t *b)
{
	/* domain names must be compared case-insensitively */
	/* TODO: Determine if this is safe to use */
	int r = strcasecmp(a, b);
	return (r);;
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

	uint8_t *name_pos = name;
	cpy = strdup(domain);
	if (!cpy) goto error;

	char *token = NULL;
	for (token = strtok(cpy, "."); token; token = strtok(NULL, "."))
	{
		size_t token_len = strlen(token);
		if (token_len > MAX_LABEL_LEN) goto error;

		*name_pos = token_len;
		name_pos++, name_len--;
		int r = snprintf(name_pos, name_len, "%s", token);
		if (r < 0) goto error;

		/* the NULL terminator should be written over with the next
		 * length */
		name_pos += r;
		name_len -= r;
	}

	free(cpy);
	return (name);

error:
	if (name) free(name);
	if (cpy) free(cpy);
	return (NULL);
}

struct dns_packet *
dns_parse(uint8_t *pkt_buff, size_t pkt_len)
{
	assert(pkt_buff);

	uint8_t *pkt_pos = pkt_buff;
	size_t remaining_len = pkt_len;

	struct dns_packet *pkt_parsed = malloc(sizeof(*pkt_parsed));
	if (NULL == pkt_parsed) goto error;
	memset(pkt_parsed, 0, sizeof(*pkt_parsed));

	if (!dns_parse_header(pkt_parsed, &pkt_pos, &pkt_len)) goto error;

	pkt_parsed->questions = dns_parse_question_section(pkt_parsed->header.qdcount, &pkt_pos, &remaining_len);
	if (!pkt_parsed->questions) goto error;
	if (!dns_parse_answer_section_into(&pkt_parsed->answers, pkt_parsed->header.ancount, &pkt_pos, &remaining_len)) goto error;
	if (!dns_parse_answer_section_into(&pkt_parsed->authority, pkt_parsed->header.nscount, &pkt_pos, &remaining_len)) goto error;
	if (!dns_parse_answer_section_into(&pkt_parsed->additional, pkt_parsed->header.arcount, &pkt_pos, &remaining_len)) goto error;

	return (pkt_parsed);

error:
	/* reverse any operations done so far, free all structures */
	free_dns_packet(pkt_parsed);
	return (NULL);
}

int
dns_parse_answer(struct dns_answer **out, uint8_t **buf_pos,
		size_t *remaining_len)
{
	assert(out);

	/* this might be annoying but it will force proper initialization
	 * of variables so should make programs safer */
	assert(NULL == *out);

	assert(buf_pos);
	assert(*buf_pos);
	assert(remaining_len);

	struct dns_answer *ans = NULL;

	/* if the most significant 2 bits of the name field are 1 the
	 * field contains a pointer instead of a literal name */
	if (*remaining_len > 0)
	{
		ans = new_dns_answer();
		if (NULL == ans) goto error;

		if (*buf_pos[0] & 0xC0)
		{
			/* TODO: Handle PTR */
		}
		else
		{
			ans->name = dns_parse_name(buf_pos, remaining_len);
			if (NULL == ans->name) goto error;

			if (!byte_array_read_uint16(&(ans->type), buf_pos, remaining_len)) goto error;
			if (!byte_array_read_uint16(&(ans->class), buf_pos, remaining_len)) goto error;
			if (!byte_array_read_uint32(&(ans->ttl), buf_pos, remaining_len)) goto error;
			if (!byte_array_read_uint16(&(ans->rdlength), buf_pos, remaining_len)) goto error;

			if (ans->rdlength > *remaining_len) goto error;

			/* TODO: RDATA is one of the few places where a failure
			 * to parse could be ignored, as the length is known. */

			/* rdata has a separate length field so set up a smaller
			 * limit for it */
			uint8_t *rdata_pos = *buf_pos;
			size_t rdata_remaining_len = ans->rdlength;

			if (!dns_parse_rdata(&ans, ans->type, &rdata_pos, &rdata_remaining_len)) goto error;

			/* since everything worked out, now update the "master"
			 * pointer and remainder */
			(*buf_pos) += ans->rdlength;
			(*remaining_len) -= ans->rdlength;
		}
	}

	*out = ans;

	return (1);

error:
	free_dns_answer(ans);
	*out = NULL;
	return (0);
}

struct dns_answer *
dns_parse_answer_section(uint16_t num_answers, uint8_t **buf_pos,
		size_t *remaining_len)
{
	assert(buf_pos);
	assert(*buf_pos);
	assert(remaining_len);

	struct dns_answer *first_answer = NULL;
	struct dns_answer *last_answer = NULL;
	uint16_t i;

	for (i = 0; i < num_answers; i++)
	{
		struct dns_answer *new_answer = NULL;
		if (!dns_parse_answer(&new_answer, buf_pos, remaining_len)) goto error;

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

int
dns_parse_answer_section_into(struct dns_answer **out,
		uint16_t num_answers, uint8_t **buf_pos, size_t *remaining_len)
{
	assert(out);
	assert(buf_pos);
	assert(*buf_pos);
	assert(remaining_len);

	if (num_answers > 0)
	{
		*out = dns_parse_answer_section(num_answers, buf_pos, remaining_len);
		if (NULL == *out) goto error;
	}

	return (1);

error:
	return (0);
}

uint8_t *
dns_parse_label(uint8_t **buf_pos, size_t *remaining_len)
{
	assert(buf_pos);
	assert(*buf_pos);
	assert(remaining_len);

	uint8_t *out = NULL;
	if (*remaining_len > 0)
	{
		size_t label_len = (*buf_pos)[0];
		if (label_len > MAX_LABEL_LEN) return (NULL);
		if ( (label_len + 1) >= *remaining_len) return (NULL);

		/* add NULL byte and length byte */
		size_t label_bytes = label_len + 2;

		out = malloc(label_bytes);
		if (!out) return (NULL);

		strncpy((char *)out, (char *)*buf_pos, label_bytes);
		out[label_bytes] = 0; /* ensure NULL termination */

		/* don't skip over the next length byte */
		*buf_pos += label_len + 1;
		*remaining_len -= label_len;
	}

	return (out);
}

uint8_t *
dns_parse_name(uint8_t **buf_pos, size_t *remaining_len)
{
	assert(buf_pos);
	assert(*buf_pos);
	assert(remaining_len);

	uint8_t *out = NULL;

	size_t buf_index = 0;
	if (*remaining_len > 0)
	{
		size_t label_len = 0;
		do
		{
			/* Hop along string only checking the label lengths */
			label_len = (*buf_pos)[buf_index];
			if (label_len > MAX_LABEL_LEN) goto error;

			buf_index += label_len + 1;
			if (buf_index >= *remaining_len) goto error;
			if (buf_index >= MAX_NAME_LEN) goto error;
		} while (label_len != 0);
	}

	/* buf_index now contains the length (including \x0 byte) */
	out = malloc(buf_index);
	if (NULL == out) goto error;

	strncpy((char *)out, (char *)(*buf_pos), buf_index);

	*buf_pos += buf_index;
	*remaining_len -= buf_index;

	return (out);

error:
	if (out) free(out);
	return (0);
}

int dns_parse_header(struct dns_packet *out, uint8_t **buf_pos, size_t *remaining_len)
{
	assert(out);
	assert(buf_pos);
	assert(*buf_pos);
	assert(remaining_len);

	if (*remaining_len >= DNS_HEADER_LEN)
	{
		out->header.id = byte_array_get_uint16(*buf_pos);
		out->header.qr = ((*buf_pos)[2] & 0x80) >> 7;
		out->header.opcode = ((*buf_pos)[2] & 0x78) >> 3;
		out->header.aa = ((*buf_pos)[2] & 0x04) >> 2;
		out->header.tc = ((*buf_pos)[2] & 0x02) >> 1;
		out->header.rd = ((*buf_pos)[2] & 0x01);
		out->header.ra = ((*buf_pos)[3] & 0x80) >> 7;
		out->header.z = ((*buf_pos)[3] & 0x70) >> 4;
		out->header.rcode = ((*buf_pos)[3] & 0x0F);
		out->header.qdcount = byte_array_get_uint16(&((*buf_pos)[4]));
		out->header.ancount = byte_array_get_uint16(&((*buf_pos)[6]));
		out->header.nscount = byte_array_get_uint16(&((*buf_pos)[8]));
		out->header.arcount = byte_array_get_uint16(&((*buf_pos)[10]));

		(*buf_pos) += DNS_HEADER_LEN;
		(*remaining_len) -= DNS_HEADER_LEN;

		return (1);
	}

	return (0);
}

struct dns_question *
dns_parse_question(uint8_t **qn_start, size_t *max_len)
{
	assert(qn_start);
	assert(*qn_start);
	assert(max_len);

	struct dns_question *qn = new_dns_question();
	if (!qn) return (NULL);

	qn->qname = dns_parse_name(qn_start, max_len);
	if (!qn->qname) goto error;

	if (!byte_array_read_uint16(&(qn->qtype), qn_start, max_len)) goto error;
	if (!byte_array_read_uint16(&(qn->qclass), qn_start, max_len)) goto error;

	return (qn);

error:
	free_dns_question(qn);
	return (NULL);
}

struct dns_question *
dns_parse_question_section(uint16_t qn_num,
		uint8_t **buf_pos, size_t *remaining_len)
{
	assert(buf_pos);
	assert(*buf_pos);
	assert(remaining_len);

	struct dns_question *qn_list = NULL;
	struct dns_question *last_qn = NULL;
	int i;

	for (i = 0; i < qn_num; i++)
	{
		struct dns_question *new_qn = dns_parse_question(buf_pos, remaining_len);
		if (!new_qn) goto error;

		if (!qn_list)
		{
			qn_list = new_qn;
			last_qn = qn_list;
		}
		else
		{
			last_qn->next = new_qn;
			last_qn = last_qn->next;
		}
	}

	return (qn_list);

error:
	free_dns_question(qn_list);
	return (NULL);
}

int
dns_parse_rdata(struct dns_answer **out, enum dns_qtype type,
		uint8_t **pos_ptr, size_t *remaining_len)
{
	assert(pos_ptr);

	switch(type)
	{
	case(A):
		if (!byte_array_read_uint32(&(*out)->rdata.a.ip_address, pos_ptr, remaining_len)) return (0);
		break;
	case(NS):
		/* no break: NS and PTR have the same format */
	case(PTR):
		(*out)->rdata.ptr.name = dns_parse_name(pos_ptr, remaining_len);
		if (!(*out)->rdata.ptr.name) return (0);
		break;
	case(MD):
		break;
	case(MF):
		break;
	case(CNAME):
		break;
	case(SOA):
		(*out)->rdata.soa.mname = dns_parse_name(pos_ptr, remaining_len);
		if (!(*out)->rdata.soa.mname) return (0);
		size_t name_len = strlen((*out)->rdata.soa.mname);
		pos_ptr += name_len;
		remaining_len -= name_len;

		(*out)->rdata.soa.rname = dns_parse_name(pos_ptr, remaining_len);
		if (!(*out)->rdata.soa.rname) return (0);
		name_len = strlen((*out)->rdata.soa.rname);
		pos_ptr += name_len;
		remaining_len -= name_len;

		if (!byte_array_read_uint32(&(*out)->rdata.soa.serial, pos_ptr, remaining_len)) return (0);
		if (!byte_array_read_uint32(&(*out)->rdata.soa.refresh, pos_ptr, remaining_len)) return (0);
		if (!byte_array_read_uint32(&(*out)->rdata.soa.retry, pos_ptr, remaining_len)) return (0);
		if (!byte_array_read_uint32(&(*out)->rdata.soa.expire, pos_ptr, remaining_len)) return (0);
		if (!byte_array_read_uint32(&(*out)->rdata.soa.minimum, pos_ptr, remaining_len)) return (0);
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
		if (!((*out)->rdata.srv.service = dns_parse_label(pos_ptr, remaining_len))) return (0);
		if (!((*out)->rdata.srv.proto = dns_parse_label(pos_ptr, remaining_len))) goto srv_error;
		if (!((*out)->rdata.srv.name = dns_parse_name(pos_ptr, remaining_len))) goto srv_error;
		if (!byte_array_read_uint32(&(*out)->rdata.srv.ttl, pos_ptr, remaining_len)) goto srv_error;
		if (!byte_array_read_uint16(&(*out)->rdata.srv.class, pos_ptr, remaining_len)) goto srv_error;
		if (!byte_array_read_uint16(&(*out)->rdata.srv.priority, pos_ptr, remaining_len)) goto srv_error;
		if (!byte_array_read_uint16(&(*out)->rdata.srv.weight, pos_ptr, remaining_len)) goto srv_error;
		if (!byte_array_read_uint16(&(*out)->rdata.srv.port, pos_ptr, remaining_len)) goto srv_error;
		if (!((*out)->rdata.srv.target = dns_parse_name(pos_ptr, remaining_len))) goto srv_error;
		break;
srv_error:
		if ((*out)->rdata.srv.service) free((*out)->rdata.srv.service);
		if ((*out)->rdata.srv.proto) free((*out)->rdata.srv.proto);
		if ((*out)->rdata.srv.name) free((*out)->rdata.srv.name);
		if ((*out)->rdata.srv.target) free((*out)->rdata.srv.target);
		return (0);
	default:
		break;
	}

	return (1);
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
		print_answer(a, fp);
		a = a->next;
	}
	fprintf(fp, " -- AUTHORITY SECTION -- \n");
	a = pkt->authority;
	while (a)
	{
		print_answer(a, fp);
		a = a->next;
	}
	fprintf(fp, " -- ADDITIONAL SECTION -- \n");
	a = pkt->additional;
	while (a)
	{
		print_answer(a, fp);
		a = a->next;
	}
	fprintf(fp, "\n\n");
}

void
print_answer(struct dns_answer *a, FILE *fp)
{
	assert(a);
	assert(fp);

	fprintf(fp, "NAME: %s\n", a->name);
	fprintf(fp, "TYPE: %d\n", a->type);
	fprintf(fp, "CLASS: %d\n", a->class);
	fprintf(fp, "TTL: %d\n", a->ttl);
	fprintf(fp, "RLENGTH: %d\n", a->rdlength);
	switch(a->type)
	{
	case A:
		fprintf(fp, "IP ADDRESS: %d\n", a->rdata.a.ip_address);
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
		fprintf(fp, "SERVICE: %s\n", a->rdata.srv.service);
		fprintf(fp, "PROTO: %s\n", a->rdata.srv.proto);
		fprintf(fp, "NAME: %s\n", a->rdata.srv.name);
		fprintf(fp, "TTL: %d\n", a->rdata.srv.ttl);
		fprintf(fp, "CLASS: %d\n", a->rdata.srv.class);
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

size_t dns_write(uint8_t *buf_ptr, size_t buf_len,
		struct dns_packet *pkt)
{
	assert(buf_ptr);
	assert(pkt);

	uint8_t *buf_pos = buf_ptr;
	size_t remaining_len = buf_len;

	if (!dns_write_header(&buf_pos, &remaining_len, pkt)) return (0);

	dns_write_question_section(&buf_pos, &remaining_len, pkt);
	dns_write_answer_section(&buf_pos, &remaining_len, pkt->answers, pkt->header.ancount);
	dns_write_answer_section(&buf_pos, &remaining_len, pkt->authority, pkt->header.nscount);
	dns_write_answer_section(&buf_pos, &remaining_len, pkt->additional, pkt->header.arcount);
	ptrdiff_t packet_len = buf_pos - buf_ptr;
	return (packet_len);
}

int
dns_write_answer(uint8_t **pos_ptr, size_t *remaining_len, struct dns_answer *answer)
{
	assert(pos_ptr);
	assert(*pos_ptr);
	assert(remaining_len);
	assert(answer);

	if (!dns_write_name(pos_ptr, remaining_len, answer->name)) return (0);
	if (!byte_array_write_uint16(pos_ptr, remaining_len, answer->type)) return (0);
	if (!byte_array_write_uint16(pos_ptr, remaining_len, answer->class)) return (0);
	if (!byte_array_write_uint32(pos_ptr, remaining_len, answer->ttl)) return (0);
	if (!byte_array_write_uint16(pos_ptr, remaining_len, answer->rdlength)) return (0);

	/* todo: write rdata */

	return (1);
}

/* Unlike the write_question_section function, this function does not
 * take the packet as an argument. This is because there are three
 * different sections with the same answer format so more specifics
 * must be provided */
int
dns_write_answer_section(uint8_t **pos_ptr, size_t *remaining_len,
		struct dns_answer *ans_list, uint16_t ans_len)
{
	assert(pos_ptr);
	assert(*pos_ptr);
	assert(remaining_len);
	assert(ans_list);

	int i;

	for (i = 0; i < ans_len; i++, ans_list = ans_list->next)
	{
		/* check list is not too short */
		if (!ans_list) return (0);

		if (!dns_write_answer(pos_ptr, remaining_len, ans_list)) return (0);
	}

	return (1);
}

int
dns_write_header(uint8_t **pos_ptr, size_t *remaining_len,
		struct dns_packet *pkt)
{
	assert(pos_ptr);
	assert(*pos_ptr);
	assert(remaining_len);
	assert(pkt);

	if (*remaining_len < DNS_HEADER_LEN) return (0);

	if (!byte_array_write_uint16(pos_ptr, remaining_len, pkt->header.id)) return (0);
	uint8_t bit_field = 0;
	bit_field |= pkt->header.qr << 7;
	bit_field |= pkt->header.opcode << 3;
	bit_field |= pkt->header.aa << 2;
	bit_field |= pkt->header.tc << 1;
	bit_field |= pkt->header.rd;
	**pos_ptr = bit_field;
	(*pos_ptr)++, (*remaining_len)--;

	bit_field = 0;
	bit_field |= pkt->header.ra << 7;
	bit_field |= pkt->header.z << 4;
	bit_field |= pkt->header.rcode;
	**pos_ptr = bit_field;
	(*pos_ptr)++, (*remaining_len)--;

	/* calculate these values */
	if (!byte_array_write_uint16(pos_ptr, remaining_len, count_questions(pkt->questions))) return (0);
	if (!byte_array_write_uint16(pos_ptr, remaining_len, count_answers(pkt->answers))) return (0);
	if (!byte_array_write_uint16(pos_ptr, remaining_len, count_answers(pkt->authority))) return (0);
	if (!byte_array_write_uint16(pos_ptr, remaining_len, count_answers(pkt->authority))) return (0);
	return (1);
}

int
dns_write_question(uint8_t **pos_ptr, size_t *remaining_len,
		struct dns_question *qn)
{
	assert(pos_ptr);
	assert(*pos_ptr);
	assert(remaining_len);
	assert(qn);

	if (!dns_write_name(pos_ptr, remaining_len, qn->qname)) return (0);
	if (!byte_array_write_uint16(pos_ptr, remaining_len, qn->qtype)) return (0);
	if (!byte_array_write_uint16(pos_ptr, remaining_len, qn->qclass)) return (0);

	return (1);
}

/* This requires the entire packet structure because I wanted to
 * check the qncount */
int
dns_write_question_section(uint8_t **pos_ptr, size_t *remaining_len,
		struct dns_packet *pkt)
{
	assert(pos_ptr);
	assert(*pos_ptr);
	assert(remaining_len);
	assert(pkt);

	struct dns_question *qn = pkt->questions;
	int num_qns = count_questions(pkt->questions);
	int i;
	for (i = 0; i < num_qns; i++, qn = qn->next)
	{
		assert(qn);
		if (!dns_write_question(pos_ptr, remaining_len, qn)) return (0);
	}

	return (1);
}

int
dns_write_label(uint8_t **pos_ptr, size_t *remaining_len, uint8_t *label)
{
	assert(pos_ptr);
	assert(*pos_ptr);
	assert(remaining_len);
	assert(label);

	int result = snprintf((char *)(*pos_ptr), *remaining_len, "%s", label);
	if (result < 0) return (0);

	/* can write over NULL byte with next label or name */
	int bytes = result;
	if (bytes > *remaining_len) return (0);

	(*pos_ptr) += bytes;
	*remaining_len -= bytes;

	return (bytes);
}

int
dns_write_name(uint8_t **pos_ptr, size_t *remaining_len, uint8_t *name)
{
	assert(pos_ptr);
	assert(*pos_ptr);
	assert(remaining_len);
	assert(name);

	int result = snprintf((char *)(*pos_ptr), *remaining_len, "%s", name);
	if (result < 0) return (0);

	int bytes = result + 1;
	if (bytes > *remaining_len) return (0);

	(*pos_ptr) += bytes;
	(*remaining_len) -= bytes;

	return (bytes);
}

int
dns_write_rdata(uint8_t **pos_ptr, size_t *remaining_len, struct dns_answer *ans)
{
	assert(pos_ptr);
	assert(*pos_ptr);
	assert(remaining_len);
	assert(ans);

	switch(ans->type)
	{
	case(A):
		if (!byte_array_write_uint32(pos_ptr, remaining_len, ans->rdata.a.ip_address)) return (0);
		break;
	case(NS):
		/* no break: NS and PTR have the same format */
	case(PTR):
		if (!dns_write_name(pos_ptr, remaining_len, ans->rdata.ptr.name)) return (0);
		break;
	case(MD):
		break;
	case(MF):
		break;
	case(CNAME):
		break;
	case(SOA):
		if (!dns_write_name(pos_ptr, remaining_len, ans->rdata.soa.mname)) return (0);
		if (!dns_write_name(pos_ptr, remaining_len, ans->rdata.soa.rname)) return (0);

		if (!byte_array_write_uint32(pos_ptr, remaining_len, ans->rdata.soa.serial)) return (0);
		if (!byte_array_write_uint32(pos_ptr, remaining_len, ans->rdata.soa.refresh)) return (0);
		if (!byte_array_write_uint32(pos_ptr, remaining_len, ans->rdata.soa.retry)) return (0);
		if (!byte_array_write_uint32(pos_ptr, remaining_len, ans->rdata.soa.expire)) return (0);
		if (!byte_array_write_uint32(pos_ptr, remaining_len, ans->rdata.soa.minimum)) return (0);
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
		if (!dns_write_label(pos_ptr, remaining_len, ans->rdata.srv.service)) return (0);
		if (!dns_write_label(pos_ptr, remaining_len, ans->rdata.srv.proto)) return (0);
		if (!dns_write_name(pos_ptr, remaining_len, ans->rdata.srv.name)) return (0);
		if (!byte_array_write_uint32(pos_ptr, remaining_len, ans->rdata.srv.ttl)) return (0);
		if (!byte_array_write_uint16(pos_ptr, remaining_len, ans->rdata.srv.class)) return (0);
		if (!byte_array_write_uint16(pos_ptr, remaining_len, ans->rdata.srv.priority)) return (0);
		if (!byte_array_write_uint16(pos_ptr, remaining_len, ans->rdata.srv.weight)) return (0);
		if (!byte_array_write_uint16(pos_ptr, remaining_len, ans->rdata.srv.port)) return (0);
		if (!dns_write_name(pos_ptr, remaining_len, ans->rdata.srv.target)) return (0);
		break;
	default:
		break;
	}

	return (1);
}

int
rr_collection_add_record(struct rr_collection **head, uint8_t *name,
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
rr_collection_search(struct rr_collection *head, uint8_t *name)
{
	/* This function accepts a NULL collection as it could be empty */
	assert(name);

	while (head)
	{
		/* It is a mistake to have any records without a name */
		assert(head->name);
		if (dns_compare_names(name, head->name) == 0) return (head);

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

void free_dns_packet(struct dns_packet *packet)
{
	if (packet)
	{
		free_dns_question(packet->questions);
		free_dns_answer(packet->answers);
		free_dns_answer(packet->authority);
		free_dns_answer(packet->additional);

		free(packet);
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
		if (NULL != ans->rdata.srv.service) free(ans->rdata.srv.service);
		if (NULL != ans->rdata.srv.proto) free(ans->rdata.srv.proto);
		if (NULL != ans->rdata.srv.name) free(ans->rdata.srv.name);
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
