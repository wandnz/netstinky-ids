/*
 *
 * Copyright (c) 2020 The University of Waikato, Hamilton, New Zealand.
 *
 * This file is part of netstinky-ids.
 *
 * Use of this source code is governed by a BSD-style
 * license that can be found in the LICENSE file or at
 * https://opensource.org/licenses/BSD-2-Clause
 *
 *
 */
/** @file
 *
 * @brief Entry-point for the nsids program
 *
 * @author Andrew Mackintosh
 * @author Marianne Fletcher
 */
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
#include <sys/types.h>
#include <uv.h>

#include "error/ids_error.h"
#include "privileges.h"
#include "blacklist/ids_blacklist.h"
#include "blacklist/feodo_ip_blacklist.h"

#ifndef NO_UPDATES
#include "utils/uvtls/uv_tls.h"
// TODO: Select which backend to use via configure script
#include "utils/uvtls/backends/openssl.h"
#include "updates/ids_tls_update.h"
#endif
#ifndef NO_MDNS
#include "mdns/ids_mdns_avahi.h"
#endif
#include "utils/common.h"
#include "utils/logging.h"
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

#define MAX_EVENTS 5        ///< The maximum number of events to buffer
#define MAX_TS 5            ///< The maximum number of timestamps to buffer
#define NEW_USER "nobody"   ///< The user to switch to after initialization
#define NEW_GROUP "nogroup" ///< The group to switch to after initialization

/** For debugging with valgrind, which cannot handle programs with extra
 * capabilities
 */
#define IGNORE_PCAP_ERRORS (true)

/* Structure to hold command line argument values. None of these will need to
 * be freed as the strings will be pointers to static memory.
 */
struct IdsArgs
{
    /** Filename for a file containing domain IoC records */
    char *domain_filename;
    /** Filename for a file containing IP IoC records*/
    char *ip_filename;
    /** Filename for fuzz testing input */
    char *fuzz_filename;
    /** The name of the interface to capture from */
    char *iface;
    /** The port to use for the IoC event server */
    int server_port;
    /** If the help flag was specified on the cmdline */
    int help_flag;

#ifndef NO_UPDATES
    /** The host to connect to for IoC updates */
    char *update_server_host;
    /** The port on the host to connect to for IoC updates */
    uint16_t update_server_port;
    /** If set to non-zero, do not verify the certificate of the remote host */
    int ssl_no_verify;
#endif
};

// Variables that MUST be global so exit callback can free them
static uv_loop_t *loop = NULL;
static pcap_t *pcap = NULL;
#ifndef NO_MDNS
static AvahiMdnsContext mdns;
#endif
ip_blacklist *ip_bl = NULL;                 ///< The IP IoC blacklist
domain_blacklist *dn_bl = NULL;             ///< The domain IoC blacklist
struct ids_event_list *event_queue = NULL;  ///< The buffer of IoC events

// libuv handles
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
const struct NetStinky_ssl *NetStinky_ssl = &NetStinky_ssl_openssl;
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

/**
 * @brief Handle a shutdown request for libuv stream handle
 * @param req The shutdown request
 * @param status The status of the shutdown operation
 */
void
stream_shutdown_cb(uv_shutdown_t *req, int status)
{
    if (status != 0)
        logger(L_ERROR, "Could not shutdown stream: %s",
                uv_strerror(status));

    logger(L_DEBUG, "Shutdown stream for writing.");
    /* Close handle */
    uv_close((uv_handle_t *)req->handle, close_cb);
    free(req);
}

/**
 * @brief Close the given handle
 *
 * This function is a callback for uv_walk on the event loop such that all
 * remaining active handles on the event loop are closed before shutting down
 *
 * @param handle The current handle to close
 * @param arg A void pointer to an optional argument (given to the uv_walk
 * function call) that may be NULL
 */
void walk_and_close_handle_cb(uv_handle_t *handle,
                              void *arg __attribute__((unused)))
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
                logger(L_WARN, "Could not stop reading stream: %s",
                        uv_strerror(err));
            if (NULL == (shutdown = malloc(sizeof(*shutdown))))
                logger(L_ERROR, "Could not allocate shutdown request");
            else
                if (0 > (err = uv_shutdown(shutdown, (uv_stream_t *)handle, stream_shutdown_cb)))
                    logger(L_ERROR, "Could not shutdown stream: %s",
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
    NetStinky_ssl->library_close();
#endif
}

/**
 * @brief Print command line help text.
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
#ifndef NO_UPDATES
        {"ssl-no-verify", no_argument, &args->ssl_no_verify, 1},
#endif
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

static void alloc_buffer(uv_handle_t *handle __attribute__((unused)),
                        size_t suggested_size, uv_buf_t *buf)
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
        logger(L_ERROR, "Could not open stdin pipe: %s", uv_strerror(uv_rc));
        return NSIDS_UV;
    }

    if (0 > (uv_rc = uv_pipe_open(&stdin_pipe, stdin_fd)))
    {
        logger(L_ERROR, "Could not open stdin pipe: %s", uv_strerror(uv_rc));
        return NSIDS_UV;
    }

    if (0 > (uv_rc = uv_read_start((uv_stream_t *) &stdin_pipe, alloc_buffer, read_stdin)))
    {
        logger(L_ERROR, "Could not open stdin pipe: %s", uv_strerror(uv_rc));
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
    logger(L_DEBUG, "received signal");
    if (signum == SIGINT || signum == SIGTERM)
        uv_stop(handle->loop);
    else if (signum == SIGPIPE)
    {
        logger(L_INFO, "Received SIGPIPE, probably tried to write to a \
closed socket");
    }
}

/**
 * Sets the stop flag for the loop when the process receives SIGTERM.
 * @param loop An event loop
 * @param handle An uninitialized uv_signal_t type handle
 *
 * The signal handler must be a variable from the main loop or a global,
 * otherwise it will lose its memory allocation after this function has
 * completed.
 */
int setup_sigterm_handling(uv_loop_t *loop, uv_signal_t *handle)
{
    assert(loop);
    assert(handle);

    int uv_rc;

    if (0 > (uv_rc = uv_signal_init(loop, handle)))
    {
        logger(L_ERROR, "Could not initialize SIGTERM handle: %s",
                uv_strerror(uv_rc));
        return NSIDS_UV;
    }
    if (0 > (uv_rc = uv_signal_start(handle, signal_cb, SIGTERM)))
    {
        logger(L_ERROR, "Could not initialize SIGTERM handle: %s",
                uv_strerror(uv_rc));
        return NSIDS_UV;
    }
    return NSIDS_OK;
}

/** Sets the stop flag for the loop when the process receives SIGINT.
 * @param loop An event loop
 * @param handle An uninitialized uv_signal_t type handle
 *
 * The signal handler must be a variable from the main loop or a global,
 * otherwise it will lose its memory allocation after this function has
 * completed.
 */
int
setup_sigint_handling(uv_loop_t *loop, uv_signal_t *handle)
{
    assert(loop);
    assert(handle);
    int uv_rc;

    if (0 > (uv_rc = uv_signal_init(loop, handle)))
    {
        logger(L_ERROR, "Could not initialize SIGINT handle: %s",
                uv_strerror(uv_rc));
        return NSIDS_UV;
    }
    if (0 > (uv_rc = uv_signal_start(handle, signal_cb, SIGINT)))
    {
        logger(L_ERROR, "Could not initialize SIGINT handle: %s",
                uv_strerror(uv_rc));
        return NSIDS_UV;
    }
    return NSIDS_OK;
}

/**
 * @brief Override the default signal handler for SIGPIPE
 *
 * Prevent a SIGPIPE signal from crashing the program when writing to a closed
 * socket. While this is an invalid configuration, it is not dire enough to
 * cause the program to exit.
 *
 * @return NSIDS_SIG on success, otherwise NSIDS_SIG on error
 */
static int
setup_sigpipe(void)
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

/**
 * @brief Entrypoint
 */
int
main(int argc, char **argv)
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
        logger(L_ERROR, "Failed to parse command line arguments");
        print_usage(argv[0]);
        exit(EXIT_FAILURE);
    }

    // Request for print usage received
    if (args.help_flag)
    {
        print_usage(argv[0]);
        exit(EXIT_SUCCESS);
    }

#ifdef DEBUG
    set_log_level(L_DEBUG);
#else
    set_log_level(L_WARN);
#endif

    // pcap_io_task_setup, configure and add the pcap task to the event
    // loop here.
    event_queue = new_ids_event_list(MAX_EVENTS, MAX_TS);

#ifdef FUZZ_TEST
    logger(L_DEBUG, "Fuzz testing blacklists...");
    fuzz_test_blacklists(args.ip_filename, args.domain_filename);
    if (!args.fuzz_filename) exit(EXIT_SUCCESS);

    logger(L_DEBUG, "Fuzz testing packet capturing...");
    fuzz_test_pcap(args.fuzz_filename);
#endif // FUZZ_TEST


    // Setup blacklists and load entries from files
    if (NSIDS_OK != setup_ip_blacklist(&ip_bl)) goto done;

    if (args.ip_filename)
    {
        if (0 > (n_ip_entries = import_feodo_blacklist(args.ip_filename, ip_bl)))
        {
            logger(L_ERROR, "Could not import Feodo blacklist from %s", args.ip_filename);
            goto done;
        }
        else
            logger(L_DEBUG, "Imported %d IP blacklist entries", n_ip_entries);
    }

    if (NSIDS_OK != setup_domain_blacklist(&dn_bl)) goto done;

    if (args.domain_filename)
    {
        if (0 > (n_dn_entries = import_urlhaus_blacklist_file(args.domain_filename, dn_bl)))
        {
            logger(L_ERROR, "Could not import domain blacklist from %s", args.domain_filename);
            goto done;
        }
        else
            logger(L_DEBUG, "Imported %d domain blacklist entries", n_dn_entries);
    }

    // Setup packet capture handle
    if (NSIDS_OK != configure_pcap(&pcap, filter, args.iface)
            && !IGNORE_PCAP_ERRORS) goto done;

    // Drop root privileges now that the pcap handle is open
    switch (ch_user(NEW_USER, NEW_GROUP))
    {
    case -1:
        goto done;
    case 1:
        logger(L_DEBUG, "Already not-root user");
    case 0:
        break;
    }

    // Begin event loop setup
    if (NULL == (loop = uv_default_loop()))
    {
        logger(L_ERROR, "loop could not be allocated");
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
    if (ids_mdns_setup_mdns(&mdns, loop, args.server_port)) goto done;
#endif
#ifndef NO_UPDATES
    if (args.update_server_host)
    {
        NetStinky_ssl->library_init();
        if (setup_update_context(&ids_update_ctx, loop,
                args.update_server_host,
                (const uint16_t) args.update_server_port,
                args.ssl_no_verify,
                &dn_bl, &ip_bl))
        {
            logger(L_ERROR, "Could not setup updates.");
            goto done;
        }

        if (setup_update_timer(&update_timer, loop, &ids_update_ctx))
        {
            logger(L_ERROR, "Could not setup update timer.");
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
#ifndef NO_MDNS
    // Free mDNS here, as it causes it's libuv handles to be closed as part of
    // freeing and therefore needs to run the event loop a couple of times
    // before _all_ memory is freed.
    if (&mdns)
        ids_mdns_free_mdns(&mdns);
#endif
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
