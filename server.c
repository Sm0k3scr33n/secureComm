#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <pthread.h>
#include <sys/ipc.h>
#include <sys/shm.h>
#include <sys/sem.h>
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <json-c/json.h>
#include <bcrypt.h>

#define PORT 8080
#define SHM_SIZE 1024
#define SEM_KEY 1234
#define MAX_CLIENTS 10

SSL *clients[MAX_CLIENTS];
int client_count = 0;
pthread_mutex_t lock = PTHREAD_MUTEX_INITIALIZER;

typedef struct {
    char username[50];
    char password_hash[100];
    char bcrypt_seed[100];
} User;

User users[MAX_CLIENTS];
int user_count = 0;

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
    method = SSLv23_server_method();
    ctx = SSL_CTX_new(method);
    if (!ctx) {
        perror("Unable to create SSL context");
        ERR_print_errors_fp(stderr);
        exit(EXIT_FAILURE);
    }
    return ctx;
}

void configure_context(SSL_CTX *ctx, const char *cert_file, const char *key_file) {
    if (SSL_CTX_use_certificate_file(ctx, cert_file, SSL_FILETYPE_PEM) <= 0) {
        ERR_print_errors_fp(stderr);
        exit(EXIT_FAILURE);
    }
    if (SSL_CTX_use_PrivateKey_file(ctx, key_file, SSL_FILETYPE_PEM) <= 0) {
        ERR_print_errors_fp(stderr);
        exit(EXIT_FAILURE);
    }
}

void load_users() {
    FILE *file = fopen("config.json", "r");
    if (!file) {
        perror("Error opening config.json");
        exit(EXIT_FAILURE);
    }
    
    char buffer[SHM_SIZE];
    fread(buffer, sizeof(buffer), 1, file);
    fclose(file);

    struct json_object *parsed_json;
    struct json_object *json_users;
    struct json_object *json_user;
    struct json_object *username;
    struct json_object *password_hash;
    struct json_object *bcrypt_seed;

    parsed_json = json_tokener_parse(buffer);
    json_users = json_object_object_get(parsed_json, "users");

    user_count = json_object_array_length(json_users);
    printf("Number of users: %d\n", user_count);

    for (int i = 0; i < user_count; i++) {
        json_user = json_object_array_get_idx(json_users, i);

        json_object_object_get_ex(json_user, "username", &username);
        json_object_object_get_ex(json_user, "password_hash", &password_hash);
        json_object_object_get_ex(json_user, "bcrypt_seed", &bcrypt_seed);

        strcpy(users[i].username, json_object_get_string(username));
        strcpy(users[i].password_hash, json_object_get_string(password_hash));
        strcpy(users[i].bcrypt_seed, json_object_get_string(bcrypt_seed));

        printf("Loaded user: %s\n", users[i].username);
    }
}

int authenticate_user(char *username, char *password) {
    char hash[100];
    for (int i = 0; i < user_count; i++) {
        if (strcmp(users[i].username, username) == 0) {
            if (bcrypt_hashpw(password, users[i].bcrypt_seed, hash) == 0 &&
                strcmp(hash, users[i].password_hash) == 0) {
                return 1;
            }
        }
    }
    return 0;
}

void *handle_client(void *arg) {
    SSL *ssl = (SSL *)arg;
    char buffer[SHM_SIZE];
    int bytes_read;

    // Authentication
    if ((bytes_read = SSL_read(ssl, buffer, sizeof(buffer) - 1)) > 0) {
        buffer[bytes_read] = '\0';
        char *username = strtok(buffer, "|");
        char *password = strtok(NULL, "|");
        if (authenticate_user(username, password)) {
            SSL_write(ssl, "Authenticated", strlen("Authenticated"));
        } else {
            SSL_write(ssl, "Authentication Failed", strlen("Authentication Failed"));
            SSL_shutdown(ssl);
            SSL_free(ssl);
            return NULL;
        }
    }

    while ((bytes_read = SSL_read(ssl, buffer, sizeof(buffer) - 1)) > 0) {
        buffer[bytes_read] = '\0';
        printf("Received: %s\n", buffer);

        pthread_mutex_lock(&lock);
        for (int i = 0; i < client_count; i++) {
            if (clients[i] != ssl) {
                SSL_write(clients[i], buffer, strlen(buffer));
            }
        }
        pthread_mutex_unlock(&lock);
    }

    SSL_shutdown(ssl);
    SSL_free(ssl);
    return NULL;
}

int main(int argc, char *argv[]) {
    int server_fd, client_fd;
    struct sockaddr_in address;
    int addrlen = sizeof(address);
    SSL_CTX *ctx;

    const char *cert_file = "cert.pem";
    const char *key_file = "key.pem";

    for (int i = 1; i < argc; i++) {
        if (strcmp(argv[i], "-cert") == 0 && i + 1 < argc) {
            cert_file = argv[i + 1];
        } else if (strcmp(argv[i], "-key") == 0 && i + 1 < argc) {
            key_file = argv[i + 1];
        }
    }

    load_users();

    init_openssl();
    ctx = create_context();
    configure_context(ctx, cert_file, key_file);

    if ((server_fd = socket(AF_INET, SOCK_STREAM, 0)) == 0) {
        perror("socket failed");
        exit(EXIT_FAILURE);
    }

    address.sin_family = AF_INET;
    address.sin_addr.s_addr = INADDR_ANY;
    address.sin_port = htons(PORT);

    if (bind(server_fd, (struct sockaddr *)&address, sizeof(address)) < 0) {
        perror("bind failed");
        exit(EXIT_FAILURE);
    }

    if (listen(server_fd, 3) < 0) {
        perror("listen");
        exit(EXIT_FAILURE);
    }

    while ((client_fd = accept(server_fd, (struct sockaddr *)&address, (socklen_t *)&addrlen)) >= 0) {
        SSL *ssl = SSL_new(ctx);
        SSL_set_fd(ssl, client_fd);

        if (SSL_accept(ssl) <= 0) {
            ERR_print_errors_fp(stderr);
        } else {
            pthread_mutex_lock(&lock);
            if (client_count < MAX_CLIENTS) {
                clients[client_count++] = ssl;
                pthread_t thread;
                pthread_create(&thread, NULL, handle_client, ssl);
            } else {
                printf("Maximum clients reached\n");
                SSL_shutdown(ssl);
                SSL_free(ssl);
                close(client_fd);
            }
            pthread_mutex_unlock(&lock);
        }
    }

    close(server_fd);
    SSL_CTX_free(ctx);
    cleanup_openssl();
    return 0;
}

