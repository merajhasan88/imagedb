/* N1d-2: an application of the C client's library alone (build/libimagedb-client.a, OpenSSL, libc and pthread: never
 * libimagedb.a), so the library is shown to hold all it needs. It calls each entry point that pulls in a part (the
 * socket's connect, TCP's with TLS, a query), against nothing listening: an error from each is the expected answer. */
#include <stdio.h>
#include <string.h>

#include "../../client/imagedb_client.h"

int main(void)
{
    imdbc *c = NULL;
    imdb_err e = {0};
    int a = imdbc_connect("/nonexistent/imagedb.sock", "u", "p", 1, &c, &e);
    uint8_t pin[32];
    memset(pin, 0, sizeof pin);
    imdbc_tls t = {NULL, pin};
    imdb_err e2 = {0};
    int b = imdbc_connect_tcp("127.0.0.1", "1", &t, "u", "p", 1, &c, &e2);
    printf("client-link: socket %d, tcp %d (both refused: nothing listens)\n", a, b);
    return a && b ? 0 : 1;
}
