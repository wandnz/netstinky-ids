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

#ifndef NO_UPDATES
#include "blacklist/ids_blacklist.h"
#include "updates/ids_tls_update.h"
#endif
#ifndef NO_MDNS
#include "mdns/ids_mdns_avahi.h"
#include "mdns/mdns_libuv_integration.h"
#endif
#include "utils/common.h"
#include "ids_event_list.h"
#include "ids_pcap.h"
#include "ids_server.h"

/**
 * Defining FUZZ_TEST enables different code paths which can be run repeatedly
 * with fuzzed inputs.
 */
#ifdef FUZZ_TEST
#include "test/load_packet.h"
#include "test/fuzz_test_blacklist.h"
#include "test/fuzz_test_pcap.h"
#endif // FUZZ_TEST

#define MAX_EVENTS 5
#define MAX_TS 5

// For debugging with valgrind, which cannot handle programs with extra
// capabilities
#define IGNORE_PCAP_ERRORS (true)

/* Structure to hold command line argument values. None of these will need to
 * be freed as the strings will be pointers to static memory.
 */
struct IdsArgs
{
	char *domain_filename;
	char *ip_filename;
	char *fuzz_filename;
	char *iface;
	int server_port;
};

// Variables that MUST be global so exit callback can free them
static uv_loop_t *loop = NULL;
static pcap_t *pcap = NULL;
#ifndef NO_MDNS
AvahiMdnsContext mdns;
#endif
ip_blacklist *ip_bl = NULL;
domain_blacklist *dn_bl = NULL;
struct ids_event_list *event_queue = NULL;

// libuv handles
#ifndef NO_MDNS
static uv_check_t mdns_handle;
#endif
static uv_pipe_t stdin_pipe;
static uv_poll_t pcap_handle;
static uv_signal_t sigterm_handle, sigint_handle;

// Handle for event server which transmits recently detected events
static uv_tcp_t server_handle;

// Handles for updating blacklists from the server
#ifndef NO_UPDATES
static ids_update_ctx_t ids_update_ctx;
static uv_timer_t update_timer;
#endif

static void close_cb(uv_handle_t *handle)
{
	/* If handle is a TCP client connection (i.e. any TCP handle which is not
	 * the global variable 'server_handle'), free it as it is dynamically
	 * allocated.
	 */
	if (UV_TCP == handle->type && handle != (uv_handle_t *)&server_handle)
		free(handle);
}

void
stream_shutdown_cb(uv_shutdown_t *req, int status)
{
	if (status != 0)
		fprintf(stderr, "Could not shutdown stream: %s\n",
				uv_strerror(status));

	printf("Shutdown stream for writing.\n");
	/* Close handle */
	uv_close((uv_handle_t *)req->handle, close_cb);
	free(req);
}

void walk_and_close_handle_cb(uv_handle_t *handle, void *arg)
{
	int err = 0;
	uv_shutdown_t *shutdown = NULL;

	if (!uv_is_closing(handle))
	{
		/* Stop reading and shutdown writing. Handle will be closed in a
		 * separate callback */
		if (UV_STREAM == handle->type)
		{
			if (0 > (err = uv_read_stop((uv_stream_t *)handle)))
				fprintf(stderr, "Could not stop reading stream: %s",
						uv_strerror(err));
			if (NULL == (shutdown = malloc(sizeof(*shutdown))))
				fprintf(stderr, "Could not allocate shutdown request\n");
			else
				if (0 > (err = uv_shutdown(shutdown, (uv_stream_t *)handle, stream_shutdown_cb)))
					fprintf(stderr, "Could not shutdown stream: %s\n",
							uv_strerror(err));
				else
					// Successfully started shutdown process of stream
					return;
		}

		uv_close(handle, close_cb);
	}
}

static void free_globals(void) {
	DPRINT("Freeing globals...\n");
    if (pcap) pcap_close(pcap);
    if (event_queue) free_ids_event_list(&event_queue);
    if (ip_bl) free_ip_blacklist(&ip_bl);
    if (dn_bl) free_domain_blacklist(&dn_bl);
#ifndef NO_MDNS
    ids_mdns_free_mdns(&mdns);
#endif
#ifndef NO_UPDATES
    teardown_update_context(&ids_update_ctx);
#endif
}

int parse_args(struct IdsArgs *args, int argc, char **argv)
{
	char *getopt_args = "hp:i:";
	struct option long_options[] = {
	    {"ipbl", 1, 0, 0},
		{"dnbl", 1, 0, 0},
		{"fuzz", 1, 0, 0},
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
        	else if (2 == option_index)
        	{
        		if (!optarg) {
        			fprintf(stderr, "Did not receive an option for %s\n",
        					long_options[option_index].name);
        		} else {
        			fprintf(stderr, "Argument --fuzz (fuzz packet file): %s\n",
        					optarg);
        			args->fuzz_filename = optarg;
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
	uv_stop(handle->loop);
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

#ifndef NO_MDNS
    memset(&mdns, 0, sizeof(mdns));
#endif
    memset(&args, 0, sizeof(args));

    if (!parse_args(&args, argc, argv)) {
        DPRINT("parse_args() failed\n");
        exit(EXIT_FAILURE);
    }

	// pcap_io_task_setup, configure and add the pcap task to the event
	// loop here.
	event_queue = new_ids_event_list(MAX_EVENTS, MAX_TS);

#ifdef FUZZ_TEST
    printf("Fuzz testing blacklists...\n");
    fuzz_test_blacklists(args.ip_filename, args.domain_filename);
    if (!args.fuzz_filename) exit(EXIT_SUCCESS);

    printf("Fuzz testing packet capturing...\n");
    fuzz_test_pcap(args.fuzz_filename);
#endif // FUZZ_TEST

    if (!setup_ip_blacklist(&ip_bl)) {
        DPRINT("setup_ip_blacklist() failed\n");
        exit(EXIT_FAILURE);
    }

    if (!setup_domain_blacklist(&dn_bl)) {
    	DPRINT("setup_domain_blacklist() failed\n");
    	exit(EXIT_FAILURE);
    }

    if ((retval = configure_pcap(&pcap, filter, args.iface, err) != 0)
    		&& !IGNORE_PCAP_ERRORS) goto done;

    memset(&pcap_handle, 0, sizeof(pcap_handle));
    if (NULL == (loop = uv_default_loop()))
    {
    	DPRINT("loop could not be allocated\n");
    	goto done;
    }

    if (pcap != NULL && !setup_pcap_handle(loop, &pcap_handle, pcap)) goto done;

    if (!setup_stdin_pipe(loop)) goto done;
    if (!setup_sigterm_handling(loop, &sigterm_handle)) goto done;
    if (!setup_sigint_handling(loop, &sigint_handle)) goto done;
    printf("setup sigterm\n");

    if (0 > uv_read_start((uv_stream_t *) &stdin_pipe, alloc_buffer, read_stdin)) goto done;

#ifndef NO_MDNS
    if (!ids_mdns_setup_mdns(&mdns, args.server_port)) goto done;
    if (!mdns_check_setup(loop, &mdns_handle, mdns.simple_poll)
    		|| !mdns_check_start(&mdns_handle)) goto done;
#endif

    // Setup libcurl and timer for updating blacklists
    /*curl_handle = multi_uv_setup(loop);
    if (NULL == curl_handle) goto done;

    update_timer = ids_update_setup_timer(loop, curl_handle, &ip_bl, &dn_bl);
    if (NULL == update_timer) goto done;*/
#ifndef NO_UPDATES
    if (0 != setup_update_context(&ids_update_ctx, loop, &dn_bl, &ip_bl))
    {
    	printf("Could not setup updates.\n");
    	goto done;
    }
#endif

    if (0 != setup_timer(&update_timer, loop, &ids_update_ctx))
    {
    	printf("Could not setup update timer.\n");
    	goto done;
    }

    printf("setting up event server...\n");
    if (0 != setup_event_server(loop, &server_handle, args.server_port, event_queue)) goto done;
    printf("setup event server...\n");

#ifndef FUZZ_TEST
    if (0 > uv_run(loop, UV_RUN_DEFAULT)) goto done;
#endif
    printf("\n\nCapture finished.\n\n");

    retval = 0;

done:
	if (loop)
	{
		uv_walk(loop, walk_and_close_handle_cb, NULL);
		int close_result;
		while ((close_result = uv_loop_close(loop)) == UV_EBUSY)
		{
			uv_run(loop, UV_RUN_NOWAIT);
		}
	}
    free_globals();
    return retval;
}

