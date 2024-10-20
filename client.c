#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <sys/select.h>
#include <fcntl.h>

#define PORT 8080
#define SHM_SIZE 1024  // Size of shared memory segment

void init_openssl() {
    SSL_load_error_strings();
    OpenSSL_add_ssl_algorithms();
}

void cleanup_openssl() {
    EVP_cleanup();
}

SSL_CTX *create_context() {
    const SSL_METHOD *method;
    SSL_CTX *ctx;

    method = SSLv23_client_method();
    ctx = SSL_CTX_new(method);
    if (!ctx) {
        perror("Unable to create SSL context");
        ERR_print_errors_fp(stderr);
        exit(EXIT_FAILURE);
    }

    return ctx;
}

void configure_context(SSL_CTX *ctx, const char *cert_file) {
    SSL_CTX_set_verify(ctx, SSL_VERIFY_PEER, NULL);
    if (SSL_CTX_load_verify_locations(ctx, cert_file, NULL) <= 0) {
        ERR_print_errors_fp(stderr);
        exit(EXIT_FAILURE);
    }
}

int main(int argc, char *argv[]) {
    int sock;
    struct sockaddr_in serv_addr;
    SSL_CTX *ctx;
    SSL *ssl;
    char buffer[SHM_SIZE] = {0};
    fd_set read_fds;
    char username[50];
    char password[50];

    const char *cert_file = "cert.pem";

    // Parse command-line arguments for custom cert file
    for (int i = 1; i < argc; i++) {
        if (strcmp(argv[i], "-cert") == 0 && i + 1 < argc) {
            cert_file = argv[i + 1];
        }
    }

    init_openssl();
    ctx = create_context();
    configure_context(ctx, cert_file);

    printf("Enter username: ");
    fgets(username, sizeof(username), stdin);
    username[strcspn(username, "\n")] = 0; // Remove newline character

    printf("Enter password: ");
    fgets(password, sizeof(password), stdin);
    password[strcspn(password, "\n")] = 0; // Remove newline character

    if ((sock = socket(AF_INET, SOCK_STREAM, 0)) < 0) {
        printf("\nSocket creation error\n");
        return -1;
    }

    serv_addr.sin_family = AF_INET;
    serv_addr.sin_port = htons(PORT);

    if (inet_pton(AF_INET, "127.0.0.1", &serv_addr.sin_addr) <= 0) {
        printf("\nInvalid address\n");
        return -1;
    }

    if (connect(sock, (struct sockaddr *)&serv_addr, sizeof(serv_addr)) < 0) {
        printf("\nConnection failed\n");
        return -1;
    }

    ssl = SSL_new(ctx);
    SSL_set_fd(ssl, sock);

    if (SSL_connect(ssl) <= 0) {
        ERR_print_errors_fp(stderr);
    } else {
        char auth_message[SHM_SIZE];
        snprintf(auth_message, sizeof(auth_message), "%s|%s", username, password);

        SSL_write(ssl, auth_message, strlen(auth_message));

        int bytes_read = SSL_read(ssl, buffer, sizeof(buffer) - 1);
        if (bytes_read > 0) {
            buffer[bytes_read] = '\0';
            if (strcmp(buffer, "Authenticated") == 0) {
                printf("Successfully authenticated.\n");

                fcntl(sock, F_SETFL, O_NONBLOCK); // Set socket to non-blocking

                while (1) {
                    FD_ZERO(&read_fds);
                    FD_SET(sock, &read_fds);
                    FD_SET(STDIN_FILENO, &read_fds);

                    int max_fd = sock > STDIN_FILENO ? sock : STDIN_FILENO;

                    int activity = select(max_fd + 1, &read_fds, NULL, NULL, NULL);

                    if (activity < 0 && errno != EINTR) {
                        printf("select error\n");
                        break;
                    }

                    if (FD_ISSET(STDIN_FILENO, &read_fds)) {
                        printf("Enter message: ");
                        fgets(buffer, SHM_SIZE, stdin);
                        SSL_write(ssl, buffer, strlen(buffer));
                        memset(buffer, 0, SHM_SIZE);
                    }

                    if (FD_ISSET(sock, &read_fds)) {
                        while ((bytes_read = SSL_read(ssl, buffer, sizeof(buffer) - 1)) > 0) {
                            buffer[bytes_read] = '\0';
                            printf("\n%s: %s\n", username, buffer); // Print with username
                            printf("Enter message: "); // Re-prompt for input
                            fflush(stdout);
                            memset(buffer, 0, SHM_SIZE);
                        }
                    }
                }
            } else {
                printf("Authentication failed: %s\n", buffer);
            }
        }
    }

    SSL_shutdown(ssl);
    SSL_free(ssl);
    close(sock);
    SSL_CTX_free(ctx);
    cleanup_openssl();
    return 0;
}

