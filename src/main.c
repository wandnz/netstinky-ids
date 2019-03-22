#include <stdlib.h>
#include <stdio.h>
#include <signal.h>
#include <ctype.h>
#include <string.h>
#include <unistd.h>

#include <getopt.h>

#include <pcap.h>
#include <uv.h>

#include "utils/common.h"
#include "linked_list.h"
#include "ip_blacklist.h"
#include "domain_blacklist.h"
#include "firehol_ip_blacklist.h"
#include "ids_event_list.h"
#include "ids_pcap.h"

#define MAX_EVENTS 5
#define MAX_TS 5

// Forward declarations
void packet_handler(unsigned char *userData, const struct pcap_pkthdr* pkthdr,
                    const unsigned char *packet);
int configure_pcap(const char *filter, const char *dev, char *err);

// Global state
static pcap_t *pcap = NULL;
static int pcap_fd = -1;
static uv_loop_t *loop = NULL;
static uv_poll_t poll_handle;
static uv_pipe_t stdin_pipe;

const static char *getopt_args = "hp:i:";
const static struct option long_options[] = {
    {"ipbl", 1, 0, 0},
};
const static char *getopt_usage =
        "\nRun as: %s -p port -i dev1 [-i devn]\n";

struct linked_list *iface_list = NULL;
static int server_port = -1;
char *ip_bl_file = NULL;
ip_blacklist *ip_bl = NULL;
domain_blacklist *dn_bl = NULL;
struct ids_event_list *event_queue = NULL;

static void free_globals(void) {
    if (pcap) pcap_close(pcap);
    if (pcap_fd != -1) close(pcap_fd);
    if (iface_list) free_linked_list(&iface_list, NULL);
    if (event_queue) free_ids_event_list(&event_queue);
    if (ip_bl) free_ip_blacklist(&ip_bl);
    if (dn_bl) free_domain_blacklist(&dn_bl);
}

int parse_args(int argc, char **argv)
{
    char *program = NULL;
    int option_char;
    int iface_num = 0;
    int success = 1;
    int option_index = 0;

    if (argc < 1) return 0;

    program = argv[0];

    while(-1 != (option_char = getopt_long(argc, argv, getopt_args,
                 long_options, &option_index))) {
        switch (option_char) {
        case 0:
            // Is a long option

            // Only one long option: ipbl
            if (!optarg) {
                fprintf(stderr, "Did not receive an option for %s\n",
                        long_options[option_index].name);
                break;
            } else {
                fprintf(stderr, "Argument --ipbl (IP blacklist file): %s\n",
                        optarg);
                ip_bl_file = optarg;
                break;
            }
        case 'h':
            fprintf(stderr, getopt_usage, program);
            return 1;
        case 'i':
            // -i requires an argument
            if (!optarg) {
                fprintf(stderr, "-i requires an argument\n");
                success = 0;
            }

            iface_num++;
            linked_list_add_item(&iface_list, optarg);

            fprintf(stderr, "Argument -i (interface): %s\n", optarg);
            break;
        case 'p':
            // -p requires an argument
            if (!optarg) {
                fprintf(stderr, "-p requires an argument\n");
                success = 0;
            }

            // -p must be given a port number > 0
            server_port = atoi(optarg);
            if (server_port <= 0) {
                fprintf(stderr, "-p was given an invalid argument: %s\n",
                        optarg);
                success = 0;
            }

            fprintf(stderr, "Argument -p (port number): %d\n", server_port);
            break;
        case '?':
            // options which require an argument
            if (optopt == 'p' || optopt == 'i') {
                fprintf(stderr, "-%c requires an argument\n", optopt);
            }
            // Unknown options
            else if (isprint(optopt))
                fprintf(stderr, "Unknown option received: -%c\n", optopt);
            else
                fprintf(stderr, "Unknown option received: -0x%x\n", optopt);

            success = 0;
            break;
        }
    }

    if (iface_num <= 0) {
        fprintf(stderr, "Required argument -i not received\n");
        success = 0;
    }

    // Check every required option has been received
    if (server_port <= 0) {
        fprintf(stderr, "Required argument -p not received\n");
        success = 0;
    }

    return success;
}

int setup_blacklists()
{
    struct ip4_address_range *firehol_list = NULL;
    FILE *fp = NULL;

    dn_bl = new_domain_blacklist();
    if (!dn_bl) goto error;

    ip_bl = new_ip_blacklist();
    if (!ip_bl) goto error;

    if (ip_bl_file)
    {
        fp = fopen(ip_bl_file, "r");
        if (!fp) exit(EXIT_FAILURE);

        firehol_list = read_firehol_ip_blacklist(fp);
        fclose(fp);
        fp = NULL;

        struct ip4_address_range *ip4_iter = firehol_list;
        while (ip4_iter)
        {
            /* Don't add really large address ranges */
            if (ip4_iter->prefix_len >= 28)
            {
                uint32_t addr_iter;
                uint32_t max_addr = ip4_address_range_get_max_addr(ip4_iter);

                for (addr_iter = ip4_address_range_get_min_addr(ip4_iter); addr_iter < max_addr; addr_iter++)
                {
                    if (!ip_blacklist_add(ip_bl, addr_iter)) goto error;
                }

                if (!ip_blacklist_add(ip_bl, max_addr)) goto error;
            }

            ip4_iter = ip4_iter->next;
        }

        free_ip4_address_range(&firehol_list);
    }

    return (1);
error:
    if (fp) fclose(fp);
    free_ip4_address_range(&firehol_list);
    free_ip_blacklist(&ip_bl);
    free_domain_blacklist(&dn_bl);
    return (0);
}


static int set_filter(pcap_t *pcap, const char *filter, char *err)
{
    int rc = -1;
    struct bpf_program fp;

    if (pcap == NULL || filter == NULL) return 0;

    memset(&fp, 0, sizeof(fp));

    if ((rc = pcap_compile(pcap, &fp, filter, 0, PCAP_NETMASK_UNKNOWN)) != 0) {
        fprintf(stderr, "Error in filter expression: %s\n", err);
        goto done;
    }
    if ((rc = pcap_setfilter(pcap, &fp)) != 0) {
        fprintf(stderr, "Can't set filter expression: %s\n", err);
        goto done;
    }

    pcap_freecode(&fp);
    rc = 0;
done:
    return rc;
}

static void pcap_data_cb(uv_poll_t *handle, int status, int events)
{
    if (status < 0) {
        fprintf(stderr, "Error while polling fd: %s\n", uv_strerror(status));
        return;
    }

    if (events & UV_READABLE) {
        int pkt_num = 0;
        // If we are here, the fd is ready to read
        pkt_num = pcap_dispatch(pcap, 0, packet_handler, NULL);

        if (pkt_num == -1) {
            fprintf(stderr, "Error processing packet\n%s\n",
                    pcap_geterr(pcap));
        } else if (pkt_num == -2) {
            fprintf(stderr, "Pcap requested loop close.\n");
            uv_stop(loop);
        }
    }
}

static void walk_cb(uv_handle_t *handle, void *arg)
{
    // KLUDGE: Don't close UV_POLL instances as it will be assumed that
    // they will be closed manually. Prevents double-closing errors
    if (handle->type == UV_POLL)
        return;
    else
        uv_close(handle, arg);
}

static void alloc_buffer(uv_handle_t *handle, size_t suggested_size,
             uv_buf_t *buf)
{
    *buf = uv_buf_init((char *) malloc(suggested_size), (uint) suggested_size);
}

static void read_stdin(uv_stream_t *stream, ssize_t nread,
               const uv_buf_t *buf)
{
    if (nread < 0) {
        if (nread == UV_EOF) {
        uv_read_stop((uv_stream_t *) &stdin_pipe);
            uv_stop(loop);
        }
    } else {
        // Keep reading
        uv_read_start(stream, alloc_buffer, read_stdin);
    }

    if (buf->base)
        free(buf->base);
}

static void close_polling(uv_handle_t *handle)
{
    free_globals();
}

int main(int argc, char **argv)
{
    int retval = -1;
    const char *filter = "(udp dst port 53) or (tcp[tcpflags] & tcp-syn != 0\
 and tcp[tcpflags] & tcp-ack == 0)";
    const char *dev = "eth0";
    char err[PCAP_ERRBUF_SIZE];

    if (!parse_args(argc, argv)) {
        DPRINT("parse_args() failed\n");
        exit(EXIT_FAILURE);
    }

    if (!setup_blacklists()) {
        DPRINT("setupt_blacklists() failed\n");
        exit(EXIT_FAILURE);
    }

    // pcap_io_task_setup, configure and add the pcap task to the event
    // loop here.
    event_queue = new_ids_event_list(MAX_EVENTS, MAX_TS);


    if ((retval = configure_pcap(filter, dev, err) != 0)) goto done;

    memset(&poll_handle, 0, sizeof(poll_handle));
    loop = uv_default_loop();

    uv_pipe_init(loop, &stdin_pipe, 0);
    uv_pipe_open(&stdin_pipe, 0);
    uv_read_start((uv_stream_t *) &stdin_pipe, alloc_buffer, read_stdin);

    uv_poll_init(loop, &poll_handle, pcap_fd);
    uv_poll_start(&poll_handle, UV_READABLE, pcap_data_cb);

    uv_run(loop, UV_RUN_DEFAULT);

    uv_poll_stop(&poll_handle);

    // Close the polling loop with a callback, as it will need to close the
    // pcap fd when the polling fd is closed (must wait for polling fd to
    // close to prevent leaks)
    uv_close((uv_handle_t *) &poll_handle, close_polling);
    // Close the remaining handles on the running loop
    uv_walk(loop, walk_cb, NULL);

    printf("\n\nCapture finished.\n\n");

    retval = 0;

done:
    if (loop) {
        int close_result;
        while((close_result =  uv_loop_close(loop)) == UV_EBUSY) {
            uv_run(loop, UV_RUN_NOWAIT);
        }
    } else {
        // Loop hasn't started yet, but pcap may need cleaning up
        free_globals();
    }
    return retval;
}

int configure_pcap(const char *filter, const char *dev, char *err)
{
    int retval = -1;
    if ((pcap = pcap_create(dev, err)) == NULL) {
        fprintf(stderr, "Can't open %s: %s\n", dev, err);
        retval = -2;
        goto done;
    }
    if (pcap_set_promisc(pcap, 1) != 0) {
        fprintf(stderr, "pcap_set_promisc failed\n");
        retval = -4;
        goto done;
    }
    if (pcap_activate(pcap) != 0) {
        fprintf(stderr, "pcap_activate failed\n");
        retval = -5;
        goto done;
    }
    if (set_filter(pcap, filter, err) != 0) {
        fprintf(stderr, "Who even cares?\n");
        retval = -3;
        goto done;
    }

    pcap_fd = pcap_get_selectable_fd(pcap);
    if (pcap_fd == -1) {
        fprintf(stderr, "pcap_get_sel_fd failed\n");
        retval = -6;
        goto done;
    }

    retval = 0;
done:
    return retval;
}

