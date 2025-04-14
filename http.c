#include <asm-generic/socket.h>
#define _GNU_SOURCE

#include <errno.h>
#include <netinet/in.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

#define errprint(s)                                                            \
    do {                                                                       \
        fprintf(stderr, "ERROR: " s ": %s (%s)\n", strerror(errno),            \
                strerrorname_np(errno));                                       \
    } while (0);

#define errquit(s)                                                             \
    do {                                                                       \
        errprint(s);                                                           \
        exit(1);                                                               \
    } while (0);

#define eprintf(...) fprintf(stderr, __VA_ARGS__)

#define MAX(a, b) ((a) < (b) ? (b) : (a))
#define MIN(a, b) ((a) < (b) ? (a) : (b))

#define HTTP_SEP "\r\n"

void handle_client(int fd, struct sockaddr_in *addr) {
    (void)addr;
// we'll read at most 1KiB of data until \r\n\r\n
//  if it's more thant 1KiB it will just close the fd
#define DATA_MAX 1024

    char buffer[DATA_MAX];
    size_t data_len = 0;

    while (1) {
        int bytes_read;
        if ((bytes_read = read(fd, buffer + data_len, DATA_MAX - data_len)) <
            0) {
            errprint("read(..)");
            break;
        }

        // end of stream
        if (bytes_read == 0) {
            printf("client read 0 bytes, EOF, closing\n");
            break;
        }

        data_len += bytes_read;

        if (data_len < 4)
            continue;

        if (strncmp(buffer + data_len - 4, HTTP_SEP HTTP_SEP, 4) == 0) {
            break;
        }
    }

    if (data_len < 4 ||
        strncmp(buffer + data_len - 4, HTTP_SEP HTTP_SEP, 4) != 0) {
        eprintf("client sent bad request");
        return;
    }

    char target[128];
    if (sscanf(buffer, "GET %126s HTTP/1.1" HTTP_SEP, target) == EOF) {
        eprintf("client sent bad request");
        return;
    }

    size_t target_len = 127;
    for (size_t i = 0; i < target_len; i++) {
        if (target[i] == '?' || target[i] == '#')
            target_len = i;
    }

    target[target_len] = '\0';
    target_len++;

    char response_message[512];
    int message_len = sprintf(response_message, "Hello %s\n", target);

    char response[1024];
    int response_len =
        sprintf(response,
                "HTTP/1.1 200 OK" HTTP_SEP "Content-Length: %d" HTTP_SEP
                "Content-Type: application/octet-stream" HTTP_SEP HTTP_SEP "%s",
                message_len, response_message);

    int bytes_written = 0;
    while (bytes_written < response_len) {
        int bw;
        if ((bw = write(fd, response + bytes_written,
                        response_len - bytes_written)) < 0) {
            errprint("write(fd, ..)");
            break;
        }

        bytes_written += bw;
    }
}

int main() {
    int sockfd;
    if ((sockfd = socket(AF_INET, SOCK_STREAM, 6)) < 0)
        errquit("socket(..)");

    if (setsockopt(sockfd, SOL_SOCKET, SO_REUSEPORT, &(int){1}, sizeof(int)) <
        0)
        errquit("setsockopt(sockfd, ..)");

    eprintf("socket created: %d\n", sockfd);

    struct sockaddr_in addr;
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = INADDR_ANY;
    addr.sin_port = htons(8080);

    if (bind(sockfd, &addr, sizeof(addr)) < 0)
        errquit("bind(..)");

    eprintf("bind: %d\n", sockfd);

    if (listen(sockfd, 0) < 0)
        errquit("listen(..)");

    eprintf("listen: %d\n", sockfd);

    while (1) {
        int client;

        struct sockaddr_in addr;
        socklen_t addr_len;

        if ((client = accept(sockfd, &addr, &addr_len)) < 0)
            errquit("accept(sockfd, ..)");

        handle_client(client, &addr);
        close(client);
    }

    close(sockfd);
    return 0;
}
