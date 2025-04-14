#define _GNU_SOURCE

#include <errno.h>
#include <fcntl.h>
#include <netinet/in.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/socket.h>
#include <sys/stat.h>
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

int write_all(int fd, char *buf, size_t len) {
    size_t bytes_written = 0;
    while (bytes_written < len) {
        int bw;
        if ((bw = write(fd, buf + bytes_written, len - bytes_written)) < 0)
            return bw;

        bytes_written += bw;
    }

    // unsafe cast, idc
    return (int)bytes_written;
}

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

    int file_fd;

    char *target_file_name = target;
    size_t target_file_name_len = target_len;

    if (target_len >= 1 && target[0] == '/') {
        target_file_name++;
        target_file_name_len--;
    }

    eprintf("trying to send file: %s\n", target_file_name);

        if ((file_fd = open(target_file_name, O_RDONLY)) < 0) {
        errprint("open(..)");

        // TODO: extract into function
        char *response_header = malloc(1024);
        int response_header_len =
            sprintf(response_header, "HTTP/1.1 404 Not Found" HTTP_SEP
                                     "Content-Length: 0" HTTP_SEP HTTP_SEP);

        if (write_all(fd, response_header, response_header_len) < 0) {
            errprint("write_all(fd, response_header, response_header_len)");
            free(response_header);
            return;
        }

        free(response_header);
        return;
    }

    struct stat file_stat;
    if (fstat(file_fd, &file_stat) < 0) {
        errprint("stat(..)");
        return;
    }

    char *response_content =
        mmap(0, file_stat.st_size, PROT_READ, MAP_PRIVATE, file_fd, 0);

    if (response_content == MAP_FAILED) {
        errprint("mmap(..)");
        return;
    }

    char *response_header = malloc(1024);
    int response_header_len =
        sprintf(response_header,
                "HTTP/1.1 200 OK" HTTP_SEP "Content-Length: %zu" HTTP_SEP
                "Content-Type: application/octet-stream" HTTP_SEP HTTP_SEP,
                file_stat.st_size);

    if (write_all(fd, response_header, response_header_len) < 0) {
        errprint("write_all(fd, response_header, response_header_len)");
        goto fail;
    }

    free(response_header);
    response_header = NULL;

    if (write_all(fd, response_content, file_stat.st_size) < 0) {
        errprint("write_all(fd, response_content, file_stat.st_size)");
        goto fail;
    }

fail:
    if (response_header != NULL) {
        free(response_header);
        response_header = NULL;
    }

    if (response_content != NULL) {
        munmap(response_content, file_stat.st_size);
        response_content = NULL;
    }
    return;
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
