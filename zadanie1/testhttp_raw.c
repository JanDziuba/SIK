#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <fcntl.h>
#include <limits.h>
#include <stdbool.h>

#include <sys/socket.h>
#include <netinet/in.h>
#include <netdb.h>

#define BUFFER_SIZE 1024

enum transfer_encoding {chunked, identity};

int socket_connect(char *address, char *port) {

    int ret_value;
    int sock;
    struct addrinfo addr_hints, *addr_result;

    sock = socket(PF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (sock < 0) {
        fprintf(stderr, "ERROR: creating socket at %s (%d)\n", __FILE__, __LINE__);
        exit(1);
    }

    memset(&addr_hints, 0, sizeof(struct addrinfo));
    addr_hints.ai_flags = 0;
    addr_hints.ai_family = AF_INET;
    addr_hints.ai_socktype = SOCK_STREAM;
    addr_hints.ai_protocol = IPPROTO_TCP;

    ret_value = getaddrinfo(address, port, &addr_hints, &addr_result);
    if (ret_value != 0) {
        fprintf(stderr, "ERROR: getaddrinfo at %s (%d)\n", __FILE__, __LINE__);
        exit(1);
    }

    if (connect(sock, addr_result->ai_addr, addr_result->ai_addrlen) != 0) {
        fprintf(stderr, "ERROR: connect at %s (%d)\n", __FILE__, __LINE__);
        exit(1);
    }
    freeaddrinfo(addr_result);

    return sock;
}

void separate_address_port(const char *address_port, char **address_p, char **port_p) {

    char *address;
    char *port;
    int index = 0;
    int address_size;
    int port_size;

    while (address_port[index] != ':' && address_port[index] != '\0') {
        index++;
    }

    if (address_port[index] == '\0') {
        fprintf(stderr, "ERROR: argv[1] nie jest postaci "
                        "<adres połączenia>:<port> %s (%d)\n", __FILE__, __LINE__);
        exit(1);
    }

    address_size = index + 1;
    address = (char *) malloc(sizeof(char) * address_size);
    if (address == NULL) {
        fprintf(stderr, "ERROR: failed malloc at %s (%d)\n", __FILE__, __LINE__);
        exit(1);
    }

    while (address_port[index] != '\0') {
        index++;
    }
    port_size = index - address_size + 1;
    port = (char *) malloc(sizeof(char) * port_size);
    if (port == NULL) {
        fprintf(stderr, "ERROR: failed malloc at %s (%d)\n", __FILE__, __LINE__);
        exit(1);
    }
    index = 0;

    while (address_port[index] != ':') {
        address[index] = address_port[index];
        index++;
    }
    address[index] = '\0';
    index++;

    int port_index = 0;

    while (address_port[index] != '\0') {
        port[port_index] = address_port[index];
        index++;
        port_index++;
    }
    port[port_index] = '\0';

    *address_p = address;
    *port_p = port;
}

char *build_cookies(const char *cookies_path) {

    long buffer_size;
    long file_size;
    FILE *file = fopen(cookies_path, "r");
    if (file == NULL) {
        fprintf(stderr, "ERROR: file open %s at %s (%d)\n", cookies_path, __FILE__, __LINE__);
        exit(1);
    }
    fseek(file, 0, SEEK_END);
    file_size = ftell(file);
    fclose(file);

    buffer_size = (file_size + 100) * 2;
    char *cookies_string = malloc(buffer_size);
    if (cookies_string == NULL) {
        fprintf(stderr, "ERROR: failed malloc at %s (%d)\n", __FILE__, __LINE__);
        exit(1);
    }

    file = fopen(cookies_path, "r");
    if (file == NULL) {
        fprintf(stderr, "ERROR: file open %s at %s (%d)\n", cookies_path, __FILE__, __LINE__);
        exit(1);
    }

    int temp_char;
    unsigned int temp_char_idx;

    strcpy(cookies_string, "Cookie: ");
    temp_char_idx = strlen("Cookie: ");

    while (!feof(file)) {
        temp_char = getc(file);

        if (temp_char == EOF) {
            cookies_string[temp_char_idx] = '\0';
            break;
        } else if (temp_char == '\n') {

            temp_char = getc(file);
            if (temp_char == EOF) {
                cookies_string[temp_char_idx] = '\0';
                break;
            }
            ungetc(temp_char, file);
            cookies_string[temp_char_idx] = ';';
            temp_char_idx++;
            cookies_string[temp_char_idx] = ' ';
            temp_char_idx++;
            continue;
        } else {
            cookies_string[temp_char_idx] = (char) temp_char;
            temp_char_idx++;
        }
    }
    fclose(file);

    return cookies_string;
}

void separate_request_URL(const char *request_URL, char **request_path_p, char **host_p) {

    char *request_path;
    char *host;

    char *host_start = strchr(request_URL, '/') + 2;
    char *host_end = strchr(host_start, '/');

    long host_length = host_end - host_start;
    host = malloc(sizeof(char) * (host_length + 1));
    if (host == NULL) {
        fprintf(stderr, "ERROR: failed malloc at %s (%d)\n", __FILE__, __LINE__);
        exit(1);
    }
    memcpy(host, host_start, host_length);
    host[host_length] = '\0';

    char *request_path_start = host_end;
    char *request_path_end = strchr(request_path_start, '\0');

    long request_path_length = request_path_end - request_path_start;
    request_path = malloc(sizeof(char) * (request_path_length + 1));
    if (request_path == NULL) {
        fprintf(stderr, "ERROR: failed malloc at %s (%d)\n", __FILE__, __LINE__);
        exit(1);
    }
    strcpy(request_path, request_path_start);

    *request_path_p = request_path;
    *host_p = host;
}

char *build_request(const char *cookies_path, const char *request_URL) {
    char *cookies_string = build_cookies(cookies_path);
    char *request_path;
    char *host;

    separate_request_URL(request_URL, &request_path, &host);

    unsigned long buffer_size = sizeof(char) * (strlen("GET  HTTP/1.1\r\n") +
                                                strlen(request_path) +
                                                strlen("Host: \r\n") +
                                                strlen(host) +
                                                strlen("\r\n") +
                                                strlen(cookies_string) +
                                                strlen("Connection: close\r\n\r\n") + 1);
    char *request = malloc(buffer_size);
    if (request == NULL) {
        fprintf(stderr, "ERROR: failed malloc at %s (%d)\n", __FILE__, __LINE__);
        exit(1);
    }

    int ret_val;

    ret_val = snprintf(request, buffer_size, "GET %s HTTP/1.1\r\n"
                                             "Host: %s\r\n"
                                             "%s\r\n"
                                             "Connection: close\r\n\r\n",
                       request_path, host, cookies_string);

    if (ret_val < 0 || ret_val > buffer_size) {
        printf("%d", ret_val);
        fprintf(stderr, "ERROR: at %s (%d)\n increase buffer_size.\n", __FILE__, __LINE__);
        exit(1);
    }

    free(cookies_string);
    free(request_path);
    free(host);

    return request;
}

char *get_response(const int socket) {

    int response_size = BUFFER_SIZE;
    char *response = malloc(response_size);
    if (response == NULL) {
        fprintf(stderr, "ERROR: failed malloc at %s (%d)\n", __FILE__, __LINE__);
        exit(1);
    }
    int response_index = 0;
    int bytes_received;

    while ((bytes_received = read(socket, &response[response_index], BUFFER_SIZE)) > 0) {
        response_index += bytes_received;
        if (response_size <= response_index + BUFFER_SIZE) {
            response_size *= 2;
            response = realloc(response, response_size);
            if (response == NULL) {
                fprintf(stderr, "ERROR: failed malloc at %s (%d)\n", __FILE__, __LINE__);
                exit(1);
            }
        }
    }

    if(bytes_received < 0)
    {
        fprintf(stderr, "ERROR: failed read at %s (%d)\n", __FILE__, __LINE__);
        exit(1);
    }

    response[response_index] = '\0';

    return response;
}

char *get_header_line(const char **cur_line_p, bool *is_last_line_p) {

    const char *cur_line = *cur_line_p;
    bool is_last_line = *is_last_line_p;

    char *end_of_line = strchr(cur_line, '\r');
    if (end_of_line == NULL) {
        fprintf(stderr, "ERROR: no header line end at %s (%d)\n", __FILE__, __LINE__);
        exit(1);
    }
    long cur_lineLen = end_of_line - cur_line;
    char *header_line = (char *) malloc(sizeof(char) * (cur_lineLen + 1));
    if (header_line == NULL) {
        fprintf(stderr, "ERROR: failed malloc at %s (%d)\n", __FILE__, __LINE__);
        exit(1);
    }

    memcpy(header_line, cur_line, cur_lineLen);
    header_line[cur_lineLen] = '\0';

    cur_line = &end_of_line[2];

    if(cur_line[0] == '\r') {
        is_last_line = true;
    }

    *cur_line_p = cur_line;
    *is_last_line_p = is_last_line;

    return header_line;
}

void write_cookie(const char *report_line) {

    const char *cookie_key_start;
    const char *cookie_value_end;

    cookie_value_end = strchr(report_line, ';');
    if (cookie_value_end == NULL) {
        cookie_value_end = strchr(report_line, '\0');
        if (cookie_value_end == NULL) {
            fprintf(stderr, "ERROR: incorrect cookie at %s (%d)\n", __FILE__, __LINE__);
            exit(1);
        }
    }

    cookie_key_start = report_line + strlen("Set-Cookie: ");

    long cookie_length = cookie_value_end - cookie_key_start;
    char *cookie = (char *) malloc(sizeof(char) * (cookie_length + 1));
    if (cookie == NULL) {
        fprintf(stderr, "ERROR: failed malloc at %s (%d)\n", __FILE__, __LINE__);
        exit(1);
    }

    memcpy(cookie, cookie_key_start, cookie_length);
    cookie[cookie_length] = '\0';

    printf("%s\n", cookie);

    free(cookie);
}

enum transfer_encoding get_transfer_encoding(const char *response) {

    const char *cur_line = response;
    bool is_last_header_line = false;

    while(!is_last_header_line){

        char *header_line = get_header_line(&cur_line, &is_last_header_line);

        if (strstr(header_line, "Transfer-Encoding: chunked") == header_line) {

            free(header_line);
            return chunked;

        } else if (strstr(header_line, "Transfer-Encoding: identity") == header_line) {

            free(header_line);
            return identity;

        } else if (strstr(header_line, "Transfer-Encoding: ") == header_line) {

            free(header_line);
            fprintf(stderr, "ERROR: unsupported Transfer-Encoding at %s (%d)\n", __FILE__, __LINE__);
            exit(1);

        }
        free(header_line);
    }
    return identity;
}

void write_cookies(const char *response) {

    const char *cur_line = response;
    bool is_last_header_line = false;

    while(!is_last_header_line){

        char *header_line = get_header_line(&cur_line, &is_last_header_line);

        if (strstr(header_line, "Set-Cookie: ") == header_line) {

            write_cookie(header_line);
        }
        free(header_line);
    }
}

char *get_response_line(const char **curLine_p, bool *is_last_line_p) {

    const char *curLine = *curLine_p;
    bool is_last_line = *is_last_line_p;

    char *end_of_line = strchr(curLine, '\r');
    if (end_of_line == NULL) {
        end_of_line = strchr(curLine, '\0');
        if (end_of_line == NULL) {
            fprintf(stderr, "ERROR: no string_end at %s (%d)\n", __FILE__, __LINE__);
            exit(1);
        }
        is_last_line = true;
    }
    long curLineLen = end_of_line - curLine;
    char *report_line = (char *) malloc(sizeof(char) * (curLineLen + 1));
    if (report_line == NULL) {
        fprintf(stderr, "ERROR: failed malloc at %s (%d)\n", __FILE__, __LINE__);
        exit(1);
    }

    memcpy(report_line, curLine, curLineLen);
    report_line[curLineLen] = '\0';

    curLine = &end_of_line[2];

    *curLine_p = curLine;
    *is_last_line_p = is_last_line;

    return report_line;
}

const char *get_message_body_start(const char *response) {

    const char *cur_line = response;
    bool is_last_header_line = false;

    while(!is_last_header_line){

        free(get_header_line(&cur_line, &is_last_header_line));
    }
    free(get_response_line(&cur_line, &is_last_header_line));

    return cur_line;
}

int hexadecimal_to_decimal(char* hex_val)
{
    int len = (int)strlen(hex_val);
    int base = 1;
    int dec_val = 0;

    // Extracting characters as digits from last character
    for (int i = len - 1; i>=0; i--) {

        if (hex_val[i] >= '0' && hex_val[i] <= '9') {
            dec_val += (hex_val[i] - '0') * base;
            base = base * 16;

        } else if (hex_val[i] >= 'A' && hex_val[i] <= 'F') {
            dec_val += (hex_val[i] - 'A' + 10) * base;
            base = base * 16;

        } else if (hex_val[i] >= 'a' && hex_val[i] <= 'f') {
            dec_val += (hex_val[i] - 'a' + 10) * base;
            base = base * 16;
        }
    }

    return dec_val;
}

void write_chunked_response_length(const char *message_body_start) {

    int response_length = 0;
    const char *cur_line = message_body_start;
    bool is_last_line = false;
    char *response_line;
    int chunk_size = INT_MAX;

    while (true) {
        response_line = get_response_line(&cur_line, &is_last_line);
        chunk_size = hexadecimal_to_decimal(response_line);
        response_length += chunk_size;
        free(response_line);

        if (chunk_size == 0) {
            printf("Dlugosc zasobu: %d\n", response_length);
            return;
        } else if (is_last_line) {
            fprintf(stderr, "ERROR: unexpected end of response at %s (%d)\n", __FILE__, __LINE__);
            exit(1);
        }

        //non-trailing CRFL are counted in chunk_size
        while (chunk_size > -(int)strlen("\r\n") && !is_last_line) {
            response_line = get_response_line(&cur_line, &is_last_line);
            chunk_size -= (int)(strlen(response_line) + strlen("\r\n"));
            free(response_line);
        }
        if (is_last_line) {
            fprintf(stderr, "ERROR: unexpected end of response at %s (%d)\n", __FILE__, __LINE__);
            exit(1);
        }
        if (chunk_size != -(int)strlen("\r\n")) {
            fprintf(stderr, "ERROR: incorrect chunk size %d at %s (%d)\n", chunk_size, __FILE__, __LINE__);
            exit(1);
        }
    }

}

void write_response_length(const char *response) {

    enum transfer_encoding encoding = get_transfer_encoding(response);

    const char *message_body_start = get_message_body_start(response);

    if (encoding == identity) {

        printf("Dlugosc zasobu: %lu\n", strlen(message_body_start));
        return;

    } else if (encoding == chunked) {

        write_chunked_response_length(message_body_start);
        return;

    } else {
        fprintf(stderr, "ERROR: unexpected enum at %s (%d)\n", __FILE__, __LINE__);
        exit(1);
    }
}

void write_report(const char *response) {

    const char *first_line = response;
    bool is_last_line = false;

    char *status_line = get_header_line(&first_line, &is_last_line);
    if (strstr(status_line, "200 OK") == NULL) {
        printf("%s\n", status_line);
    } else {
        write_cookies(response);
        write_response_length(response);
    }

    free(status_line);
}

int main(int argc, char *argv[]) {

    if (argc != 4) {
        fprintf(stderr, "ERROR: Usage: %s <adres połączenia>:<port> "
                        "<plik ciasteczek> <testowany adres http>\n", argv[0]);
        exit(1);
    }

    int socket;
    char *address;
    char *port;

    separate_address_port(argv[1], &address, &port);

    socket = socket_connect(address, port);

    char *request = build_request(argv[2], argv[3]);

    if (write(socket, request, strlen(request) + 1) < 0) {
        fprintf(stderr, "ERROR: writing on stream socket at %s (%d)\n", __FILE__, __LINE__);
        exit(1);
    }

    char *response = get_response(socket);

    write_report(response);

    shutdown(socket, SHUT_RDWR);
    if (close(socket) < 0) {
        fprintf(stderr, "ERROR: closing stream socket at %s (%d)\n", __FILE__, __LINE__);
        exit(1);
    }

    free(address);
    free(port);
    free(request);
    free(response);

    return 0;
}
