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

/**
 * The dns_domain_literal can be safely stored as a C string as it is always
 * NULL-terminated.
 *
 * The dns_domain may or may not use compression. If it uses compression it
 * will not be NULL terminated.
 */
typedef char *dns_domain_literal;
typedef uint8_t *dns_domain;

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
    dns_domain_literal qname;
    uint16_t qtype;
    uint16_t qclass;
    struct dns_question *next;	/* probably multiple questions */
};

/* the rdata field of the answer has various formats */
struct rdata_soa
{
    dns_domain_literal mname;
    dns_domain_literal rname;
    uint32_t serial;
    uint32_t refresh;
    uint32_t retry;
    uint32_t expire;
    uint32_t minimum;
};

struct rdata_mx
{
    uint16_t preference;
    dns_domain_literal mail_exchanger;
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
    dns_domain_literal name;
};

/* https://www.ietf.org/rfc/rfc2052.txt */
struct rdata_srv
{
    uint16_t priority;
    uint16_t weight;
    uint16_t port;
    dns_domain_literal target;
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
    dns_domain_literal name;
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
    dns_domain_literal name;
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
struct dns_answer *dns_answer_copy(struct dns_answer *a);

struct dns_answer *dns_answer_list_copy(struct dns_answer *a);

int dns_domain_compare(dns_domain_literal a, dns_domain_literal b);

uint8_t *dns_domain_to_name(char *domain);

char *dns_name_to_readable(uint8_t *name);

/**
 * Parses a DNS packet (in a buffer beginning at PACKET_START and ending at
 * PACKET_END) into a newly allocated dns_packet structure.
 * @param packet_start The address of the first byte of the packet.
 * @param packet_end The address of the first byte that is not a part of the
 * packet.
 * @return A parsed DNS packet or NULL if an error occurred.
 */
struct dns_packet *dns_parse(uint8_t *packet_start, uint8_t *packet_end);

void dns_print(struct dns_packet *pkt, FILE *fp);

void dns_answer_print(struct dns_answer *a, FILE *fp);

size_t dns_write(struct dns_packet *packet, uint8_t *buffer_start,
                 uint8_t *buffer_end);

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
int rr_collection_add_record(struct rr_collection **head,
                            dns_domain_literal name,
                            struct dns_answer *record);

struct rr_collection *rr_collection_search(struct rr_collection *head,
                                           const dns_domain_literal name);

void free_dns_answer(struct dns_answer *ans);

void free_dns_packet(struct dns_packet **packet);

/*
 * Destroys a dns question and all substructures appropriately.
 */
void free_dns_question(struct dns_question *qn);

void free_dns_rdata(struct dns_answer *ans);

void free_rr_collection(struct rr_collection *c);

struct dns_answer *new_dns_answer(void);

/* Allocates and initializes a new dns_question structure */
struct dns_question *new_dns_question(void);

#endif /* DNS_H_ */
