#include <config.h>

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

#include "error/ids_error.h"
#include "blacklist/ids_blacklist.h"
#include "blacklist/feodo_ip_blacklist.h"

#ifndef NO_UPDATES
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
	int help_flag;

#ifndef NO_UPDATES
	char *update_server_host;
	uint16_t update_server_port;
	int ssl_no_verify;
#endif
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
#ifdef DEBUG
static uv_pipe_t stdin_pipe;
#endif
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
	if (handle == (uv_handle_t *) &server_handle)
	{
		return;
	}
#ifndef NO_UPDATES
	else if (handle == (uv_handle_t *) &(ids_update_ctx.stream))
	{
		// The ids_update_ctx.stream global is not malloc-ed
		return;
	}
#endif
	else if (UV_TCP == handle->type)
	{
		free(handle);
	}
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
		else
		{
			// Handle isn't a stream. No need to shutdown before close.
			uv_close(handle, close_cb);
		}
	}
}

static void free_globals(void) {
    if (pcap) pcap_close(pcap);
    if (event_queue) free_ids_event_list(&event_queue);
    if (ip_bl) free_ip_blacklist(&ip_bl);
    if (dn_bl) domain_blacklist_clear(dn_bl);
#ifndef NO_MDNS
    ids_mdns_free_mdns(&mdns);
#endif
#ifndef NO_UPDATES
    teardown_update_context(&ids_update_ctx);
#endif
}

/**
 * Print command line help text.
 * @param prog_name Name of program from command line. Must not be NULL.
 */
void
print_usage(char *prog_name)
{
	assert(prog_name);
	printf("Usage:\n");
	printf("\t%s [-h | --help]\n", prog_name);
	printf("\t%s -p <server_port> -i <interface> ", prog_name);
	printf("[--ipbl <blacklist>] [--dnbl <blacklist]\n");
	printf("Options:\n");
	printf("\t\t[-h | --help]:\tPrint this usage message\n");
	printf("\t\t-i <interface>: The name of the interface to capture traffic from.\n");
	printf("\t-p <server_port>:\tThe port that will be advertised via MDNS ");
	printf("(if enabled) and will accept connections from mobile devices.\n");
	printf("\t[--ipbl <blacklist]:\tPath to a blacklist file containing IP ");
	printf("addresses to load into the blacklist immediately.\n");
	printf("\t[--dnbl <blacklist]:\tPath to a blacklist file containing ");
	printf("domain names to load into the blacklist immediately.\n");
	printf("\t[--update-host]:\tHostname or IP address of the update server.\n");
	printf("\t[--update-port]:\tPort to connect to on the update server.\n");
	printf("\t[--ssl-no-verify]:\tSkip verification of TLS certificates");
}

/**
 * Parse command line arguments.
 */
int parse_args(struct IdsArgs *args, int argc, char **argv)
{
	char *getopt_args = "hp:i:";
	struct option long_options[] = {
	    {"ipbl", required_argument, 0, 0},
		{"dnbl", required_argument, 0, 0},
		{"fuzz", required_argument, 0, 0},
		{"help", no_argument, &args->help_flag, 1},
		{"update-host", required_argument, 0, 0},
		{"update-port", required_argument, 0, 0},
		{"ssl-no-verify", no_argument, &args->ssl_no_verify, 1},
		{0, 0, 0, 0}
	};

    int option_char;
    int option_index = 0;
    unsigned long parsed_ul;
    char *arg_end = NULL;

    memset(args, 0, sizeof(*args));

    if (argc < 1) return 0;

    while(-1 != (option_char = getopt_long(argc, argv, getopt_args,
                 long_options, &option_index))) {
        switch (option_char) {
        case 0:
            // Is a long option
        	if (0 == option_index)
        	{
        		if (optarg) args->ip_filename = optarg;
        		else return NSIDS_CMDLN;
        	}
        	else if (1 == option_index)
        	{
        		if (optarg) args->domain_filename = optarg;
        		else return NSIDS_CMDLN;
        	}
        	else if (2 == option_index)
        	{
        		if (optarg) args->fuzz_filename = optarg;
        		else return NSIDS_CMDLN;
        	}

        	/**
        	 * Options re: the update server.
        	 */
#ifndef NO_UPDATES
        	else if (4 == option_index)
        	{
        		if (optarg) args->update_server_host = optarg;
        		else return NSIDS_CMDLN;
        	}
        	else if (5 == option_index)
        	{
        		if (optarg)
        		{
        			// Parse port as an int
        			errno = 0;
        			parsed_ul = strtoul(optarg, &arg_end, 10);

        			// Check successful parse and within range
        			if (!parsed_ul || ERANGE == errno || parsed_ul > USHRT_MAX)
        			{
        				fprintf(stderr, "Invalid port number: %s\n", optarg);
        				return NSIDS_CMDLN;
        			}
        			args->update_server_port = parsed_ul;
        		}
        		else return NSIDS_CMDLN;
        	}
#endif
        	break;
        case 'h':
        	// Help flag takes priority over all other flags so return as soon
        	// as it is found
            args->help_flag = 1;
            return NSIDS_OK;
        case 'i':
        	// Must have an argument
            if (optarg)
            {
            	// There should only be one interface
            	if (args->iface) return NSIDS_CMDLN;
            	args->iface = optarg;
            }
            else return NSIDS_CMDLN;
            break;
        case 'p':
        	if (optarg) {
        		// Should only receive this option once
        		if (args->server_port) return NSIDS_CMDLN;
        		args->server_port = atoi(optarg);
        		if (args->server_port <= 0) return NSIDS_CMDLN;
        	}
        	else return NSIDS_CMDLN;
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

            return NSIDS_CMDLN;
            break;
        }
    }

    // Check every required option has been received
    if (!args->help_flag && (args->server_port <= 0 || !args->iface))
    	return NSIDS_CMDLN;

    return NSIDS_OK;
}

static void alloc_buffer(uv_handle_t *handle, size_t suggested_size,
             uv_buf_t *buf)
{
    *buf = uv_buf_init((char *) malloc(suggested_size), (uint) suggested_size);
}

#ifdef DEBUG
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

static int setup_stdin_pipe(uv_loop_t *loop)
{
	assert(loop);
    int ipc = 0;
    uv_file stdin_fd = 0;
    int uv_rc;

    if (0 > (uv_rc = uv_pipe_init(loop, &stdin_pipe, ipc)))
    {
    	fprintf(stderr, "Could not open stdin pipe: %s\n", uv_strerror(uv_rc));
    	return NSIDS_UV;
    }

    if (0 > (uv_rc = uv_pipe_open(&stdin_pipe, stdin_fd)))
    {
    	fprintf(stderr, "Could not open stdin pipe: %s\n", uv_strerror(uv_rc));
    	return NSIDS_UV;
    }

    if (0 > (uv_rc = uv_read_start((uv_stream_t *) &stdin_pipe, alloc_buffer, read_stdin)))
    {
    	fprintf(stderr, "Could not open stdin pipe: %s\n", uv_strerror(uv_rc));
    	return NSIDS_UV;
    }

    return NSIDS_OK;
}
#endif

/**
 * Callback when SIGTERM is received by program. Stop the main event loop from running.
 * @param handle: The signal handle.
 * @param signum: The signal which triggered the callback.
 */
void signal_cb(uv_signal_t *handle, int signum)
{
    printf("received signal\n");
    if (signum == SIGINT || signum == SIGTERM)
        uv_stop(handle->loop);
    else if (signum == SIGPIPE)
    {
        fprintf(stderr, "Received SIGPIPE, probably tried to write to a \
closed socket\n");
    }
}

/**
 * Sets the stop flag for the loop when the process receives SIGTERM.
 * @param loop: An event loop.
 *
 * The signal handler must be a variable from the main loop or a global, otherwise it will lose
 * its memory allocation after this function has completed.
 */
int setup_sigterm_handling(uv_loop_t *loop, uv_signal_t *handle)
{
	assert(loop);
	assert(handle);

	int uv_rc;

	if (0 > (uv_rc = uv_signal_init(loop, handle)))
	{
		fprintf(stderr, "Could not initialize SIGTERM handle: %s\n",
				uv_strerror(uv_rc));
		return NSIDS_UV;
	}
	if (0 > (uv_rc = uv_signal_start(handle, signal_cb, SIGTERM)))
	{
		fprintf(stderr, "Could not initialize SIGTERM handle: %s\n",
				uv_strerror(uv_rc));
		return NSIDS_UV;
	}
	return NSIDS_OK;
}

int setup_sigint_handling(uv_loop_t *loop, uv_signal_t *handle)
{
	assert(loop);
	assert(handle);
	int uv_rc;

	if (0 > (uv_rc = uv_signal_init(loop, handle)))
	{
		fprintf(stderr, "Could not initialize SIGINT handle: %s\n",
				uv_strerror(uv_rc));
		return NSIDS_UV;
	}
	if (0 > (uv_rc = uv_signal_start(handle, signal_cb, SIGINT)))
	{
		fprintf(stderr, "Could not initialize SIGINT handle: %s\n",
				uv_strerror(uv_rc));
		return NSIDS_UV;
	}
	return NSIDS_OK;
}

static int setup_sigpipe(void)
{
    struct sigaction sa;
    memset(&sa, 0, sizeof(sa));
    sa.sa_handler = SIG_IGN;
    sa.sa_flags = 0;
    if (sigaction(SIGPIPE, &sa, 0) == -1)
    {
        perror("sigaction");
        return NSIDS_SIG;
    } else {
        return NSIDS_OK;
    }
}

int main(int argc, char **argv)
{
	int n_ip_entries = 0, n_dn_entries = 0;
	struct IdsArgs args;
    int retval = -1;
    const char *filter = "(udp dst port 53) or (tcp[tcpflags] & tcp-syn != 0\
 and tcp[tcpflags] & tcp-ack == 0)";

#ifndef NO_MDNS
    memset(&mdns, 0, sizeof(mdns));
#endif
    memset(&args, 0, sizeof(args));

    // Invalid arguments
    if (parse_args(&args, argc, argv)) {
        fprintf(stderr, "Failed to parse command line arguments\n");
        print_usage(argv[0]);
        exit(EXIT_FAILURE);
    }

    // Request for print usage received
    if (args.help_flag)
    {
    	print_usage(argv[0]);
    	exit(EXIT_SUCCESS);
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


    // Setup blacklists and load entries from files
    if (NSIDS_OK != setup_ip_blacklist(&ip_bl)) goto done;

    if (args.ip_filename)
	{
    	if (0 > (n_ip_entries = import_feodo_blacklist(args.ip_filename, ip_bl)))
    	{
			fprintf(stderr, "Could not import Feodo blacklist from %s\n", args.ip_filename);
			goto done;
    	}
    	else
    		fprintf(stdout, "Imported %d IP blacklist entries\n", n_ip_entries);
	}

    if (NSIDS_OK != setup_domain_blacklist(&dn_bl)) goto done;

    if (args.domain_filename)
	{
    	if (0 > (n_dn_entries = import_urlhaus_blacklist_file(args.domain_filename, dn_bl)))
    	{
			fprintf(stderr, "Could not import domain blacklist from %s\n", args.domain_filename);
			goto done;
    	}
    	else
    		fprintf(stdout, "Imported %d domain blacklist entries\n", n_dn_entries);
	}

    // Setup packet capture handle
    if (NSIDS_OK != configure_pcap(&pcap, filter, args.iface)
    		&& !IGNORE_PCAP_ERRORS) goto done;

    // Begin event loop setup
    if (NULL == (loop = uv_default_loop()))
    {
    	DPRINT("loop could not be allocated\n");
    	goto done;
    }

    if (pcap && setup_pcap_handle(loop, &pcap_handle, pcap)) goto done;

#ifdef DEBUG
    if (setup_stdin_pipe(loop)) goto done;
#endif
    if (setup_sigterm_handling(loop, &sigterm_handle)) goto done;
    if (setup_sigint_handling(loop, &sigint_handle)) goto done;
    if (setup_sigpipe()) goto done;

#ifndef NO_MDNS
    if (ids_mdns_setup_mdns(&mdns, args.server_port)) goto done;
    if (mdns_setup_event_handle(loop, &mdns_handle, mdns.simple_poll)
    		|| mdns_check_start(&mdns_handle)) goto done;
#endif
#ifndef NO_UPDATES
    if (args.update_server_host)
    {
		if (setup_update_context(&ids_update_ctx, loop,
				args.update_server_host,
				(const uint16_t) args.update_server_port,
				args.ssl_no_verify,
				&dn_bl, &ip_bl))
		{
			printf("Could not setup updates.\n");
			goto done;
		}

		if (setup_update_timer(&update_timer, loop, &ids_update_ctx))
		{
			printf("Could not setup update timer.\n");
			goto done;
		}
    }
#endif

    if (setup_event_server(loop, &server_handle, args.server_port, event_queue)) goto done;

#ifndef FUZZ_TEST
    if (0 > uv_run(loop, UV_RUN_DEFAULT)) goto done;
#endif

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
