#include <assert.h>
#include <ctype.h>
#include <signal.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <getopt.h>
#include <pcap.h>
#include <unistd.h>
#include <uv.h>

#include "blacklist/ids_blacklist.h"
#include "mdns/ids_mdns_avahi.h"
#include "mdns/mdns_libuv_integration.h"
#include "utils/common.h"
#include "ids_event_list.h"
#include "ids_pcap.h"
#include "ids_server.h"

#define MAX_EVENTS 5
#define MAX_TS 5

/* Structure to hold command line argument values. None of these will need to
 * be freed as the strings will be pointers to static memory.
 */
struct IdsArgs
{
	char *domain_filename;
	char *ip_filename;
	char *iface;
	int server_port;
};

// Variables that MUST be global so exit callback can free them
static uv_loop_t *loop = NULL;
static pcap_t *pcap = NULL;
AvahiMdnsContext mdns;
ip_blacklist *ip_bl = NULL;
domain_blacklist *dn_bl = NULL;
struct ids_event_list *event_queue = NULL;

// libuv handles
static uv_check_t mdns_handle;
static uv_pipe_t stdin_pipe;
static uv_poll_t pcap_handle;
static uv_signal_t sigterm_handle, sigint_handle;
static uv_tcp_t server_handle;

static void close_cb(uv_handle_t *handle)
{
	printf("Closed handle: %x\n", handle);
}

void
stream_shutdown_cb(uv_shutdown_t *req, int status)
{
	if (status != 0)
		fprintf(stderr, "Could not shutdown stream at %x\n", req->handle);
	free(req);
}

/**
 * Stop all global handles
 */
static void stop_handles()
{
	uv_shutdown_t *shutdown_req;

	if (0 > uv_check_stop(&mdns_handle)) fprintf(stderr, "Could not stop mdns polling\n");
	if (0 > uv_poll_stop(&pcap_handle)) fprintf(stderr, "Could not stop pcap\n");

	if (0 > uv_read_stop((uv_stream_t *)&stdin_pipe)) fprintf(stderr, "Could not stop reading stdin\n");
	if (NULL == (shutdown_req = malloc(sizeof(*shutdown_req))))
		fprintf(stderr, "Could not allocate shutdown request\n");
	else
		uv_shutdown(shutdown_req, (uv_stream_t *)&stdin_pipe, stream_shutdown_cb);

	if (0 > uv_signal_stop(&sigterm_handle)) fprintf(stderr, "Could not stop SIGTERM handler\n");
	if (0 > uv_signal_stop(&sigint_handle)) fprintf(stderr, "Could not stop SIGINT handler\n");

	if (0 > uv_read_stop((uv_stream_t *)&stdin_pipe)) fprintf(stderr, "Could not stop reading server socket\n");
	if (NULL == (shutdown_req = malloc(sizeof(*shutdown_req))))
		fprintf(stderr, "Could not allocate shutdown request\n");
	else
		uv_shutdown(shutdown_req, (uv_stream_t *)&server_handle, stream_shutdown_cb);
}

/**
 * Close all global handles
 */
static void close_handles()
{
	uv_close((uv_handle_t *)&mdns_handle, close_cb);
	uv_close((uv_handle_t *)&stdin_pipe, close_cb);
	uv_close((uv_handle_t *)&pcap_handle, close_cb);
	uv_close((uv_handle_t *)&sigterm_handle, close_cb);
	uv_close((uv_handle_t *)&sigint_handle, close_cb);
	uv_close((uv_handle_t *)&server_handle, close_cb);
}

static void free_globals(void) {
	DPRINT("Freeing globals...\n");
    if (pcap) pcap_close(pcap);
    if (event_queue) free_ids_event_list(&event_queue);
    if (ip_bl) free_ip_blacklist(&ip_bl);
    if (dn_bl) free_domain_blacklist(&dn_bl);
    ids_mdns_free_mdns(&mdns);
}

int parse_args(struct IdsArgs *args, int argc, char **argv)
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

    memset(args, 0, sizeof(*args));

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
					args->ip_filename = optarg;
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
        			args->domain_filename = optarg;
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
            args->iface = optarg;

            fprintf(stderr, "Argument -i (interface): %s\n", optarg);
            break;
        case 'p':
            // -p requires an argument
            if (!optarg) {
                fprintf(stderr, "-p requires an argument\n");
                success = 0;
            }

            // -p must be given a port number > 0
            args->server_port = atoi(optarg);
            if (args->server_port <= 0) {
                fprintf(stderr, "-p was given an invalid argument: %s\n",
                        optarg);
                success = 0;
            }

            fprintf(stderr, "Argument -p (port number): %d\n", args->server_port);
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

    if (iface_num <= 0 || iface_num > 1) {
    	fprintf(stderr, "Received %d -i arguments. Require exactly 1.\n",
    			iface_num);
        success = 0;
    }

    // Check every required option has been received
    if (args->server_port <= 0) {
        fprintf(stderr, "Required argument -p not received\n");
        success = 0;
    }

    return success;
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

int main(int argc, char **argv)
{
	struct IdsArgs args;
    int retval = -1;
    const char *filter = "(udp dst port 53) or (tcp[tcpflags] & tcp-syn != 0\
 and tcp[tcpflags] & tcp-ack == 0)";
    char err[PCAP_ERRBUF_SIZE];

    memset(&mdns, 0, sizeof(mdns));

    if (!parse_args(&args, argc, argv)) {
        DPRINT("parse_args() failed\n");
        exit(EXIT_FAILURE);
    }

    if (!setup_ip_blacklist(&ip_bl, args.ip_filename)) {
        DPRINT("setup_ip_blacklist() failed\n");
        exit(EXIT_FAILURE);
    }

    if (!setup_domain_blacklist(&dn_bl, args.domain_filename)) {
    	DPRINT("setup_domain_blacklist() failed\n");
    	exit(EXIT_FAILURE);
    }

    // pcap_io_task_setup, configure and add the pcap task to the event
    // loop here.
    event_queue = new_ids_event_list(MAX_EVENTS, MAX_TS);

    if ((retval = configure_pcap(&pcap, filter, args.iface, err) != 0)) goto done;

    memset(&pcap_handle, 0, sizeof(pcap_handle));
    if (NULL == (loop = uv_default_loop()))
    {
    	DPRINT("loop could not be allocated\n");
    	goto done;
    }
    if (!setup_pcap_handle(loop, &pcap_handle, pcap)) goto done;

    if (!setup_stdin_pipe(loop)) goto done;
    if (!setup_sigterm_handling(loop, &sigterm_handle)) goto done;
    if (!setup_sigint_handling(loop, &sigint_handle)) goto done;
    printf("setup sigterm\n");

    if (0 > uv_read_start((uv_stream_t *) &stdin_pipe, alloc_buffer, read_stdin)) goto done;

    if (!ids_mdns_setup_mdns(&mdns, args.server_port)) goto done;
    if (!mdns_check_setup(loop, &mdns_handle, mdns.simple_poll)
    		|| !mdns_check_start(&mdns_handle)) goto done;

    printf("setting up event server...\n");
    if (0 != setup_event_server(loop, &server_handle, args.server_port, event_queue)) goto done;
    printf("setup event server...\n");

    if (0 > uv_run(loop, UV_RUN_DEFAULT)) goto done;
    printf("\n\nCapture finished.\n\n");

    retval = 0;

done:
    if (loop) {
    	stop_handles();
    	close_handles();
        int close_result;
        while((close_result = uv_loop_close(loop)) == UV_EBUSY) {
            uv_run(loop, UV_RUN_NOWAIT);
        }
    } else {
        // Loop hasn't started yet, but pcap may need cleaning up
    }
    free_globals();
    return retval;
}

