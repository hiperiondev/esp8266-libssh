/*
 * compile_options.h
 *
 *  Created on: 12 ene. 2021
 *      Author: egonzalez
 */

#ifndef COMPONENTS_LIBSSH_ESP8266_COMPILE_OPTIONS_H_
#define COMPONENTS_LIBSSH_ESP8266_COMPILE_OPTIONS_H_

#define PACKAGE "libssh"
#define FALL_THROUGH "__attribute__ ((fallthrough))"
#define SSH_MALLOC(a) pvPortMalloc(a)
#define SSH_CALLOC(a,b) pvPortCalloc(a,b)
#define SSH_REALLOC(a,b) pvPortRealloc(a,b)
#define SSH_FREE(a) vPortFree(a)
#define SYSCONFDIR "/"
#define BINARYDIR "libssh"
#define SOURCEDIR "libssh"
#define SSH_BUFFER_SIZE_MAX esp_get_free_heap_size()
#define GLOBAL_BIND_CONFIG "\"libssh_server_config\""
#define GLOBAL_CLIENT_CONFIG "\"ssh_config\""
#define HAVE_ARGP_H 1
#define HAVE_ARPA_INET_H 1
#define HAVE_GLOB_H 1
#define HAVE_UTMP_H 1
#define HAVE_UTIL_H 1
#define HAVE_SYS_TIME_H 1
#define HAVE_TERMIOS_H 1
#define HAVE_UNISTD_H 1
#define HAVE_STDINT_H 1
#define HAVE_ECC 1
#define HAVE_GLOB_GL_FLAGS_MEMBER 1
#define HAVE_SNPRINTF 1
#define HAVE_VSNPRINTF 1
#define HAVE_ISBLANK 1
#define HAVE_STRNCPY 1
#define HAVE_STRNDUP 1
#define HAVE_CFMAKERAW 1
#define HAVE_GETADDRINFO 1
#define HAVE_POLL 1
#define HAVE_SELECT 1
#define HAVE_CLOCK_GETTIME 1
#define HAVE_STRTOULL 1
#define HAVE_GLOB 1
#define HAVE_LIBMBEDCRYPTO 1
#define HAVE_GCC_THREAD_LOCAL_STORAGE 1
#define HAVE_FALLTHROUGH_ATTRIBUTE 1
#define HAVE_UNUSED_ATTRIBUTE 1
#define HAVE_CONSTRUCTOR_ATTRIBUTE 1
#define HAVE_DESTRUCTOR_ATTRIBUTE 1
#define HAVE_GCC_VOLATILE_MEMORY_PROTECTION 1
#define HAVE_COMPILER__FUNC__ 1
#define HAVE_COMPILER__FUNCTION__ 1
#define WITH_SERVER 1
#define WITH_GEX 1
#define DEBUG_CRYPTO 1
#define DEBUG_PACKET 1
#define DEBUG_CALLTRACE 1
#define DEBUG_BUFFER 1
#define NI_MAXHOST 1

#endif /* COMPONENTS_LIBSSH_ESP8266_COMPILE_OPTIONS_H_ */
