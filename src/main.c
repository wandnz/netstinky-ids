#include <assert.h>
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
#include "urlhaus_domain_blacklist.h"
#include "ids_event_list.h"
#include "ids_pcap.h"
#include "mdns/ids_mdns_avahi.h"

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
static uv_poll_t pcap_handle;
static uv_pipe_t stdin_pipe;

AvahiMdnsContext mdns;

struct linked_list *iface_list = NULL;
static int server_port = -1;
char *ip_bl_file = NULL;
char *dn_bl_file = NULL;
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
    ids_mdns_free_mdns(&mdns);
}

int parse_args(int argc, char **argv)
{
	char *getopt_args = "hp:i:";
	struct option long_options[] = {
	    {"ipbl", 1, 0, 0},
		{"dnbl", 1, 0, 0},
		{0, 0, 0, 0}
	};
	const static char *getopt_usage =
	        "\nRun as: %s -p port -i dev1 [-i devn]\n";

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
        	if (0 == option_index)
        	{
				if (!optarg) {
					fprintf(stderr, "Did not receive an option for %s\n",
							long_options[option_index].name);
				} else {
					fprintf(stderr, "Argument --ipbl (IP blacklist file): %s\n",
							optarg);
					ip_bl_file = optarg;
				}
        	}
        	else if (1 == option_index)
        	{
        		if (!optarg) {
        			fprintf(stderr, "Did not receive an option for %s\n",
        					long_options[option_index].name);
        		} else {
        			fprintf(stderr, "Argument --dnbl (domain blacklist file): %s\n",
        					optarg);
        			dn_bl_file = optarg;
        		}
        	}
        	break;
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

int setup_ip_blacklist()
{
    struct ip4_address_range *firehol_list = NULL;
    FILE *fp = NULL;

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

/**
 * Open the domain blacklist provided at the command line and insert all domains into the blacklist
 * structure. Should only be run once. Checks that dn_bl is NULL so an existing data structure is
 * not leaked.
 */
int setup_domain_blacklist()
{
	FILE *bl_fp = NULL;
	if (dn_bl_file)
	{
		assert(!dn_bl);
	    dn_bl = new_domain_blacklist();
	    if (!dn_bl) goto error;

		bl_fp = fopen(dn_bl_file, "r");
		if (!bl_fp) goto error;

		char *domain = NULL;
		while (NULL != (domain = urlhaus_get_next_domain(bl_fp)))
		{
			domain_blacklist_add(dn_bl, domain);
			free(domain);
		}
		fclose(bl_fp);
	}

	DPRINT("domain blacklist setup complete...\n");
	return 1;

error:
	if (bl_fp) fclose(bl_fp);
	return 0;
}

static bool setup_stdin_pipe(uv_loop_t *loop)
{
	assert(loop);
    int ipc = 0;
    uv_file stdin_fd = 0;

    if (0 > uv_pipe_init(loop, &stdin_pipe, ipc))
    {
    	DPRINT("pipe could not be initialized\n");
    	return false;
    }

    if (0 > uv_pipe_open(&stdin_pipe, stdin_fd))
    {
    	DPRINT("pipe could not be opened\n");
    	return false;
    }

    printf("initialized stdin\n");

    return true;
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

/**
 * Called when an event occurs on the pcap file descriptor.
 * @param handle: The handle of the libuv poll handle.
 * @param status: status < 0 indicates that an error occurred, 0 means success.
 * @param events: A bitmask of events.
 */
static void pcap_data_cb(uv_poll_t *handle, int status, int events)
{
    if (status < 0) {
        fprintf(stderr, "Error while polling fd: %s\n", uv_strerror(status));
        return;
    }

    assert(status==0);

    if (events & UV_READABLE) {
        int pkt_num = 0;
        // If we are here, the fd is ready to read
        // cnt = 0 or -1 means read all packets (but -1 will work with older versions of pcap,
        // where 0 does not)
        int cnt = -1;
        pkt_num = pcap_dispatch(pcap, cnt, packet_handler, NULL);

        if (pkt_num == PCAP_ERROR) {
            fprintf(stderr, "Error processing packet\n%s\n",
                    pcap_geterr(pcap));
        } else if (pkt_num == PCAP_ERROR_BREAK) {
            fprintf(stderr, "Pcap requested loop close.\n");
            uv_stop(loop);
        }
    }
}

static bool setup_pcap_handle(uv_loop_t *loop)
{
	assert(loop);
    if (0 > uv_poll_init(loop, &pcap_handle, pcap_fd))
    {
    	printf("polling could not be initialized\n");
    	return false;
    }

    if (0 > uv_poll_start(&pcap_handle, UV_READABLE, pcap_data_cb))
    {
    	printf("could not start polling\n");
    	return false;
    }

    return true;
}

/**
 * Callback when SIGTERM is received by program. Stop the main event loop from running.
 * @param handle: The signal handle.
 * @param signum: The signal which triggered the callback.
 */
void signal_cb(uv_signal_t *handle, int signum)
{
	printf("received signal\n");
	uv_signal_stop(handle);

	uv_stop(loop);
}

/**
 * Sets the stop flag for the loop when the process receives SIGTERM.
 * @param loop: An event loop.
 *
 * The signal handler must be a variable from the main loop or a global, otherwise it will lose
 * its memory allocation after this function has completed.
 */
bool setup_sigterm_handling(uv_loop_t *loop, uv_signal_t *handle)
{
	assert(loop);
	assert(handle);

	if (0 > uv_signal_init(loop, handle))
	{
		fprintf(stderr, "Could not initialize signal handle\n");
		return false;
	}
	if (0 > uv_signal_start(handle, signal_cb, SIGTERM))
	{
		fprintf(stderr, "Could not start signal handling\n");
		return false;
	}
	return true;
}

bool setup_sigint_handling(uv_loop_t *loop, uv_signal_t *handle)
{
	assert(loop);
	assert(handle);
	if (0 > uv_signal_init(loop, handle))
	{
		fprintf(stderr, "Could not initialize signal handle\n");
		return false;
	}
	if (0 > uv_signal_start(handle, signal_cb, SIGINT))
	{
		fprintf(stderr, "Could not start signal handling\n");
		return false;
	}
	return true;
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

static void close_pcap_handle(uv_handle_t *handle)
{
    free_globals();
}

int main(int argc, char **argv)
{
    int retval = -1;
    const char *filter = "(udp dst port 53) or (tcp[tcpflags] & tcp-syn != 0\
 and tcp[tcpflags] & tcp-ack == 0)";
    char err[PCAP_ERRBUF_SIZE];
    uv_check_t mdns_handle;

    memset(&mdns, 0, sizeof(mdns));

    if (!parse_args(argc, argv)) {
        DPRINT("parse_args() failed\n");
        exit(EXIT_FAILURE);
    }

    if (!setup_ip_blacklist()) {
        DPRINT("setup_ip_blacklist() failed\n");
        exit(EXIT_FAILURE);
    }

    if (!setup_domain_blacklist()) {
    	DPRINT("setup_domain_blacklist() failed\n");
    	exit(EXIT_FAILURE);
    }

    // pcap_io_task_setup, configure and add the pcap task to the event
    // loop here.
    event_queue = new_ids_event_list(MAX_EVENTS, MAX_TS);


    if ((retval = configure_pcap(filter, (char *)iface_list->item, err) != 0)) goto done;

    memset(&pcap_handle, 0, sizeof(pcap_handle));
    if (NULL == (loop = uv_default_loop()))
    {
    	DPRINT("loop could not be allocated\n");
    	goto done;
    }

    if (!setup_stdin_pipe(loop)) goto done;

    uv_signal_t sigterm_handle, sigint_handle;
    if (!setup_sigterm_handling(loop, &sigterm_handle)) goto done;
    if (!setup_sigint_handling(loop, &sigint_handle)) goto done;
    printf("setup sigterm\n");

    if (0 > uv_read_start((uv_stream_t *) &stdin_pipe, alloc_buffer, read_stdin)) goto done;

    if (!setup_pcap_handle(loop)) goto done;

    if (!ids_mdns_setup_mdns(&mdns)) goto done;
    if (!mdns_check_setup(loop, &mdns_handle, mdns.simple_poll)
    		|| !mdns_check_start(mdns_handle)) goto done;

    if (0 > uv_run(loop, UV_RUN_DEFAULT)) goto done;

    if (0 > uv_poll_stop(&pcap_handle)) printf("warning: could not stop polling\n");

    // Close the polling loop with a callback, as it will need to close the
    // pcap fd when the polling fd is closed (must wait for polling fd to
    // close to prevent leaks)
    uv_close((uv_handle_t *) &pcap_handle, close_pcap_handle);
    // Close the remaining handles on the running loop
    uv_walk(loop, walk_cb, NULL);

    printf("\n\nCapture finished.\n\n");

    retval = 0;

done:
    if (loop) {
        int close_result;
        while((close_result = uv_loop_close(loop)) == UV_EBUSY) {
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

