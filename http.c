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
#include <limits.h>

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

#define PORT 8080
#define TARGET_DIR "./target"

#define HEADER_MAX 1024
#define HTTP_PATH_MAX 128
#define HTTP_SEP "\r\n"

// concat 2 strings with an option to replace the first string's \0 with some sep
//  this is really convenient when concating paths
//  assumes that the left hand side buffer is big enough to store 2 strings
size_t concat_str(char* l, char *r, char sep) {
    size_t l_len = strlen(l);

    if (sep != 0) {
        l[l_len] = '/';
        l_len++;
    }

    size_t r_len = strlen(r);
    for (size_t i = l_len; i < l_len + r_len; i++) {
        l[i] = r[i - l_len];
    }

    l[l_len + r_len] = '\0';
    return l_len + r_len;
}

int validate_path(char *path, char *disk_path) {
    static char root[256] = {0};
    static size_t root_len = 0;

    if (root_len == 0) {
        char cwd[256];

        printf("initializing root dir\n");
        if (getcwd(cwd, 192) == NULL)
            errquit("validate_path_init: getcwd()");

        concat_str(cwd, TARGET_DIR, '/');

        printf("initializing root dir: %s\n", cwd);

        if (realpath(cwd, root) == NULL)
            errquit("validate_path_init: realpath(..)");

        printf("initializing root dir: %s\n", root);

        root_len = strlen(root);
    }

    // concat path with root
    char target[root_len + HTTP_PATH_MAX];
    char target_real[root_len + HTTP_PATH_MAX];
    strcpy(target, root);

    concat_str(target, path, '/');

    printf("lookup path: %s\n", target);

    if (realpath(target, target_real) == NULL) {
        errprint("validate_path: realpath(..)");
        return -1;
    }

    printf("real lookup path: %s\n", target_real);

    size_t target_real_len = strlen(target_real);

    if (target_real_len < root_len)
        return -1;

    // check if target_real starts with root
    for (size_t i = 0; i < root_len; i++)
        if (target_real[i] != root[i])
            return -1;

    if (disk_path != NULL)
        strcpy(disk_path, target_real);

    return 0;
}

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

typedef struct http_header_s {
    char *path_buf;
    size_t path_buf_len;
} http_header_t;

int read_http_header(int fd, http_header_t *header_ptr) {
    char header[HEADER_MAX];
    size_t header_len = 0;

    while (1) {
        int bytes_read;
        if ((bytes_read =
                 read(fd, header + header_len, HEADER_MAX - header_len)) < 0) {
            errprint("read(..)");
            break;
        }

        // end of stream
        if (bytes_read == 0) {
            printf("client read 0 bytes, EOF, closing\n");
            break;
        }

        header_len += bytes_read;

        if (header_len < 4)
            continue;

        if (strncmp(header + header_len - 4, HTTP_SEP HTTP_SEP, 4) == 0) {
            break;
        }
    }

    if (header_len < 4 ||
        strncmp(header + header_len - 4, HTTP_SEP HTTP_SEP, 4) != 0) {
        return -1;
    }

    char format[64];
    snprintf(format, 64, "GET %%%zus HTTP/1.1" HTTP_SEP,
             header_ptr->path_buf_len - 1);

    if (sscanf(header, format, header_ptr->path_buf) == EOF) {
        return -1;
    }

    header_ptr->path_buf_len = strlen(header_ptr->path_buf);

    return 0;
}

int send_http_response(int fd, uint16_t status, const char *status_desc,
                       char *content, size_t content_len) {
    char response_header[HEADER_MAX];
    int response_header_len =
        sprintf(response_header,
                "HTTP/1.1 %u %s" HTTP_SEP "Content-Length: %zu" HTTP_SEP
                "Content-Type: application/octet-stream" HTTP_SEP HTTP_SEP,
                status, status_desc, (content == NULL ? 0 : content_len));

    int err;
    if ((err = write_all(fd, response_header, response_header_len)) < 0)
        return err;

    if (content == NULL)
        return 0;

    if ((err = write_all(fd, content, content_len)) < 0)
        return err;

    return 0;
}

void handle_client(int fd) {
    char path[HTTP_PATH_MAX];

    http_header_t header = {.path_buf = path, .path_buf_len = HTTP_PATH_MAX};

    if (read_http_header(fd, &header) < 0) {
        errprint("read_http_header(fd, ..)");
        return;
    }

    // truncate at ? or #
    for (size_t i = 0; i < header.path_buf_len; i++) {
        if (path[i] == '?' || path[i] == '#')
            header.path_buf_len = i;
    }

    int file_fd;

    size_t leading_slash = 0;
    while (leading_slash < header.path_buf_len - 1 && path[leading_slash] == '/')
        leading_slash++;

    char *path_rel = path + leading_slash;
    char path_disk[HTTP_PATH_MAX];

    if (validate_path(path_rel, path_disk) < 0) {
        errprint("validate_path()");
 
        if (send_http_response(fd, 404, "Not Found", NULL, 0) < 0)
            errprint("send_http_response(fd, ..)");

        return;
    }

    eprintf("trying to send file: %s\n", path_rel);

    if ((file_fd = open(path_disk, O_RDONLY)) < 0) {
        errprint("open(..)");

        if (send_http_response(fd, 404, "Not Found", NULL, 0) < 0)
            errprint("send_http_response(fd, ..)");

        return;
    }

    struct stat file_stat;
    if (fstat(file_fd, &file_stat) < 0) {
        errprint("stat(..)");
        return;
    }

    // careful with polling, mmap can block
    char *response_content =
        mmap(0, file_stat.st_size, PROT_READ, MAP_PRIVATE, file_fd, 0);

    if (response_content == MAP_FAILED) {
        errprint("mmap(..)");
        return;
    }

    if (send_http_response(fd, 200, "OK", response_content, file_stat.st_size) <
        0)
        errprint("send_http_response(fd, ..)");

    if (response_content != NULL) {
        munmap(response_content, file_stat.st_size);
        response_content = NULL;
    }

    return;
}

int main() {
    if (validate_path(".", NULL) < 0)
        errquit("validate_path");

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
    addr.sin_port = htons(PORT);

    if (bind(sockfd, &addr, sizeof(addr)) < 0)
        errquit("bind(..)");

    eprintf("bind: %d\n", sockfd);

    if (listen(sockfd, 0) < 0)
        errquit("listen(..)");

    eprintf("listen: %d\n", sockfd);

    while (1) {
        int client;

        if ((client = accept(sockfd, NULL, NULL)) < 0)
            errquit("accept(sockfd, ..)");

        handle_client(client);
        close(client);
    }

    close(sockfd);
    return 0;
}
