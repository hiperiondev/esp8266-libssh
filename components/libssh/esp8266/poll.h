/* esp-idf has <sys/poll.h> but not <poll.h> */

#define poll(fds,nfds,timeout) lwip_poll(fds,nfds,timeout)
#include <sys/poll.h>
