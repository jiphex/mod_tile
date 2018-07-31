/* wrapper for storage engines
 */

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <limits.h>
#include <string.h>
#include <errno.h>
#include <stdarg.h>
#include <sys/types.h>
#include <sys/stat.h>
#ifdef HAVE_PTHREAD
#include <pthread.h>
#endif


#include "store.h"
#include "store_file.h"
#include "store_memcached.h"
#include "store_rados.h"
#include "store_ro_http_proxy.h"
#include "store_ro_composite.h"
#include "store_null.h"

//TODO: Make this function handle different logging backends, depending on if on compiles it from apache or something else
void log_message(int log_lvl, const char *format, ...) {
    va_list ap;
    char *msg = malloc(1000*sizeof(char));

    va_start(ap, format);



    if (msg) {
        vsnprintf(msg, 1000, format, ap);
        switch (log_lvl) {
        case STORE_LOGLVL_DEBUG:
            fprintf(stderr, "debug: %s\n", msg);
            break;
        case STORE_LOGLVL_INFO:
            fprintf(stderr, "info: %s\n", msg);
            break;
        case STORE_LOGLVL_WARNING:
            fprintf(stderr, "WARNING: %s\n", msg);
            break;
        case STORE_LOGLVL_ERR:
            fprintf(stderr, "ERROR: %s\n", msg);
            break;
        }
        free(msg);
        fflush(stderr);
    }
    va_end(ap);
}

/**
 * In Apache 2.2, we call the init_storage_backend once per process. For mpm_worker and mpm_event multiple threads therefore use the same
 * storage context, and all storage backends need to be thread-safe in order not to cause issues with these mpm's
 *
 * In Apache 2.4, we call the init_storage_backend once per thread, and therefore each thread has its own storage context to work with.
 */
struct storage_backend * init_storage_backend(const char * options) {
    struct stat st;
    struct storage_backend * store = NULL;
	UriParserStateA state;
	UriUriA store_uri;
    char * store_uri_scheme, memcached_config;

    //Determine the correct storage backend based on the options string
    if (strlen(options) == 0) {
        log_message(STORE_LOGLVL_ERR, "init_storage_backend: Options string was empty");
        return NULL;
    }
    if (options[0] == '/') {
        if (stat(options, &st) != 0) {
            log_message(STORE_LOGLVL_ERR, "init_storage_backend: Failed to stat %s with error: %s", options, strerror(errno));
            return NULL;
        }
        if (S_ISDIR(st.st_mode)) {
            log_message(STORE_LOGLVL_DEBUG, "init_storage_backend: initialising file storage backend at: %s", options);
            store = init_storage_file(options);
            return store;
        } else {
            log_message(STORE_LOGLVL_ERR, "init_storage_backend: %s is not a directory", options, strerror(errno));
            return NULL;
        }
    }

    // Ok so if it's not starting with a /, it's a URI and we can parse it (maybe..)

	state.uri = &store_uri;
	if (uriParseUriA(&state, options) != URI_SUCCESS) {
		uriFreeUriMembersA(&store_uri);
		log_message(STORE_LOGLVL_ERR, "init_storage_backend: %s is not a parseable URL at %s (code %d)", options, state->errorPos, state->errorCode);
		return NULL;
	}
	store_uri_scheme = uri_fetch_part(&store_uri->scheme);
    if(store_uri_scheme != NULL) {
		log_message(STORE_LOGLVL_ERR, "init_storage_backend: %s could not detect URL scheme at %s (code %d)", options, state->errorPos, state->errorCode);
		return NULL;
	}
	log_message(STORE_LOGLVL_DEBUG, "init_storage_backend: parsed %s into scheme=%s", store_uri_scheme);
	switch(store_uri_scheme) {
        case "rados":
			log_message(STORE_LOGLVL_DEBUG, "init_storage_backend: initialising rados storage backend at: %s", options);
			store = init_storage_rados(options);
			return store;
		case "memcached":
			log_message(STORE_LOGLVL_DEBUG, "init_storage_backend: initialising memcached storage backend at: %s", options);
			memcached_config = sprintf("--server %s", uri_fetch_part(&store_uri->hostText)
			store = init_storage_memcached(memcached_config);
			return store;
		case "ro_http_proxy":
			log_message(STORE_LOGLVL_DEBUG, "init_storage_backend: initialising ro_http_proxy storage backend at: %s", options);
			store = init_storage_ro_http_proxy(options);
			return store;
		case "null":
			log_message(STORE_LOGLVL_DEBUG, "init_storage_backend: initialising null storage backend at: %s", options);
			store = init_storage_null();
			return store;
	}
    log_message(STORE_LOGLVL_ERR, "init_storage_backend: No valid storage backend found for options: %s", options);

    return store;
}


char *
uri_fetch_part(UriTextRangeA *part)
{
    char *contents = NULL;
    int length     = length_of(part);

    if (length > 0) {
        contents = calloc(1, sizeof(char) * (length + 1));
        strncpy(contents, part->first, length);
    }

    return contents;
}
