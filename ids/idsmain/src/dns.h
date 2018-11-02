/*
 * dns.h
 *
 *  Created on: 18/10/2018
 *      Author: mfletche
 */

#ifndef DNS_H_
#define DNS_H_

#include <stdint.h>
#include <stdio.h>

enum dns_header_opcode
{
	QUERY = 0,
	IQUERY = 1,
	STATUS = 2
};

enum dns_header_rcode
{
	NO_ERROR = 0,
	FORMAT_ERROR = 1,
	SERVER_FAILURE = 2,
	NAME_ERROR = 3,
	NOT_IMPLEMENTED = 4,
	REFUSED = 5
};

struct dns_header
{
	uint16_t id;
	uint16_t qr : 1;
	uint16_t opcode : 4;
	uint16_t aa : 1;
	uint16_t tc : 1;
	uint16_t rd : 1;
	uint16_t ra : 1;
	uint16_t z : 3;
	uint16_t rcode : 4;
	uint16_t qdcount;	/* question section */
	uint16_t ancount;	/* answer section */
	uint16_t nscount;	/* authority section */
	uint16_t arcount;	/* additional section */
};

enum dns_qtype
{
	A = 1,
	NS = 2,
	MD = 3,
	MF = 4,
	CNAME = 5,
	SOA = 6,
	MB = 7,
	MG = 8,
	MR = 9,
	NULL_TYPE = 10,
	WKS = 11,
	PTR = 12,
	HINFO = 13,
	MINFO = 14,
	MX = 15,
	TXT = 16,	/* TXT and above valid for both questions and
				 * answers */
	SRV = 33,
	/* below are only for questions */
	AXFR = 252,
	MAILB = 253,
	MAILA = 254,
	QTYPE_WILDCARD = 255	/* matches all RR types */
};

enum dns_class
{
	IN = 1,
	CS = 2,
	CH = 3,
	HS = 4,
	/* wildcard is just for questions, requests RRs for any
	 * class */
	CLASS_WILDCARD = 255
};

struct dns_question
{
	uint8_t *qname;
	uint16_t qtype;
	uint16_t qclass;
	struct dns_question *next;	/* probably multiple questions */
};

/* the rdata field of the answer has various formats */
struct rdata_soa
{
	uint8_t *mname;
	uint8_t *rname;
	uint32_t serial;
	uint32_t refresh;
	uint32_t retry;
	uint32_t expire;
	uint32_t minimum;
};

struct rdata_mx
{
	uint16_t preference;
	uint8_t *mail_exchanger;
};

struct rdata_a
{
	uint32_t ip_address;
};

struct rdata_aaaa
{
	uint8_t ip_address[16];
};

/* PTR and NS have the same format */
struct rdata_ptr
{
	uint8_t *name;
};

/* https://www.ietf.org/rfc/rfc2052.txt */
struct rdata_srv
{
	uint16_t priority;
	uint16_t weight;
	uint16_t port;
	uint8_t *target;
};

union rdata_u {
	struct rdata_soa soa;
	struct rdata_mx mx;
	struct rdata_a a;
	struct rdata_aaaa aaaa;
	struct rdata_ptr ptr;
	struct rdata_srv srv;
};

struct dns_answer
{
	uint8_t *name;
	uint16_t type;
	uint16_t class;
	uint32_t ttl;
	uint16_t rdlength;
	union rdata_u rdata;
	struct dns_answer *next;
};

struct dns_packet
{
	struct dns_header header;
	struct dns_question *questions;
	struct dns_answer *answers;
	struct dns_answer *authority;
	struct dns_answer *additional;
};

/* Represents a group of records with a given NAME. RECORDS is a
 * linked list of answer records of various types. This is intended
 * to be used for a small DNS database with a few names at most. */
struct rr_collection
{
	uint8_t *name;
	struct dns_answer *records;
	struct rr_collection *next;
};

/**
 * The parsing functions work by taking a uint8_t **buffer pointer
 * and a size_t *remaining pointer. This is so that the buffer
 * pointer and the amount of remaining bytes can be updated within
 * each function. Updating those values after every function call
 * would be easy to forget so I made that automatic.
 */

/**
 * Copy one or the entire linked list of DNS answers.
 *
 * @param a The answer to copy. If a single answer is to be copied
 * the NEXT pointer of the output will be NULL.
 * @return The copied answer or list of answers. NULL if the operation
 * failed.
 */
struct dns_answer *
dns_answer_copy(struct dns_answer *a);

struct dns_answer *
dns_answer_list_copy(struct dns_answer *a);

int
dns_compare_names(uint8_t *a, uint8_t *b);

uint8_t *
dns_domain_to_name(char *domain);

char *
dns_name_to_readable(uint8_t *name);

/**
 * Parses a DNS packet contained in PKT_BUFF into a dns_packet
 * structure.
 *
 * PKT_BUFF may not be NULL.
 *
 * Returns the parsed packet or NULL if the operation was
 * unsuccessful.
 */
struct dns_packet *
dns_parse(uint8_t *pkt_buff, size_t pkt_len);

/**
 * Parses the DNS answer starting at the address in *BUF_POS.
 * *BUF_POS and *REMAINING_LEN will be updated. Creates a new
 * dns_answer struct and updates the *OUT pointer to its address.
 *
 * Returns 1 if successful, 0 if unsuccessful.
 */
int
dns_parse_answer(struct dns_answer **out, uint8_t **buf_pos,
		size_t *remaining_len, uint8_t *buf_start);

/**
 * Parse NUM_ANSWERS dns answers from a buffer, beginning at
 * *BUF_POS. Updates the *BUF_POS and *REMAINING_LEN to point to the
 * next unparsed byte, and have the correct number of unparsed bytes.
 *
 * Returns a dns_answer list or NULL if the operation failed.
 */
struct dns_answer *
dns_parse_answer_section(uint16_t num_answers, uint8_t **buf_pos,
		size_t *remaining_len, uint8_t *buf_start);

/*
 * Puts the next answer section into *OUT and returns 1 if successful.
 */
int
dns_parse_answer_section_into(struct dns_answer **out,
		uint16_t num_answers, uint8_t **buf_pos, size_t *remaining_len,
		uint8_t *buf_start);

/**
 * Parses the header of a DNS packet into OUT. Updates *BUF_POS to
 * point to the next unparsed byte, and updates REMAINING_LEN by
 * reducing it by the length of the header.
 *
 * Returns 1 on success and 0 on failure. Failure is due to the
 * packet length being too short to contain a DNS header.
 */
int
dns_parse_header(struct dns_packet *out, uint8_t **buf_pos, size_t *remaining_len);

/**
 * Parses a name starting at *NAME_POS into a newly allocated
 * byte array. Updates *NAME_POS so that it points to the next byte
 * that has not been parsed. Updates *REMAINING_LEN to remove the
 * bytes that were used by the name string.
 *
 * Returns a pointer to the name string or NULL if the operation
 * failed.
 */
uint8_t *
dns_parse_name(uint8_t **name_pos, size_t *remaining_len);

/**
 * Parse a question from a buffer starting at position *QN_START.
 * Updates the position of the pointer in *QN_START and the remaining
 * bytes in *MAX_LEN.
 *
 * Returns a new dns_question structure or NULL if the operation
 * failed.
 */
struct dns_question *
dns_parse_question(uint8_t **qn_start, size_t *max_len);

/**
 * Parse a list of questions from the question section of a DNS
 * packet. Updates BUF_POS to point to the next unparsed byte and
 * updates REMAINING_LEN by decrementing it by the size of the
 * question section.
 */
struct dns_question *
dns_parse_question_section(uint16_t qn_num,
		uint8_t **buf_pos, size_t *remaining_len);

int
dns_parse_rdata(struct dns_answer **out, enum dns_qtype type,
		uint8_t **pos_ptr, size_t *remaining_len);

void
dns_print(struct dns_packet *pkt, FILE *fp);

void
print_answer(struct dns_answer *a, FILE *fp);

int
dns_write_answer_section(uint8_t **pos_ptr, size_t *remaining_len,
		struct dns_answer *ans_list, uint16_t ans_len);

int
dns_write_question_section(uint8_t **pos_ptr, size_t *remaining_len,
		struct dns_packet *pkt);

size_t dns_write(uint8_t *buf_ptr, size_t buf_len,
		struct dns_packet *pkt);

int
dns_write_header(uint8_t **pos_ptr, size_t *remaining_len,
		struct dns_packet *pkt);

int
dns_write_name(uint8_t **pos_ptr, size_t *remaining_len, uint8_t *name);

int
dns_write_question(uint8_t **pos_ptr, size_t *remaining_len,
		struct dns_question *qn);

/**
 * Add a record to a resource record collection.
 *
 * Once NAME and RECORD have been used by this function, the
 * rr_collection functions are responsible for their cleanup. Do not
 * alter or free them yourself, even if this function was
 * unsuccessful.
 *
 * Returns 1 if successful, 0 if unsuccessful.
 */
int
rr_collection_add_record(struct rr_collection **head, uint8_t *name,
		struct dns_answer *record);

struct rr_collection *
rr_collection_search(struct rr_collection *head, uint8_t *name);

void
free_dns_answer(struct dns_answer *ans);

void
free_dns_packet(struct dns_packet **packet);

/*
 * Destroys a dns question and all substructures appropriately.
 */
void
free_dns_question(struct dns_question *qn);

void
free_dns_rdata(struct dns_answer *ans);

void
free_rr_collection(struct rr_collection *c);

struct dns_answer *new_dns_answer();

/* Allocates and initializes a new dns_question structure */
struct
dns_question *new_dns_question();

#endif /* DNS_H_ */
