#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <json-c/json.h>
#include <bcrypt.h>

#define BUFFER_SIZE 1024

void print_usage(char *program_name) {
    printf("Usage: %s -if <input_file> -of <output_file>\n", program_name);
}

int main(int argc, char *argv[]) {
    if (argc != 5 || strcmp(argv[1], "-if") != 0 || strcmp(argv[3], "-of") != 0) {
        print_usage(argv[0]);
        return -1;
    }

    char *input_file = argv[2];
    char *output_file = argv[4];

    FILE *csv_file = fopen(input_file, "r");
    if (!csv_file) {
        perror("Error opening input file");
        return -1;
    }

    struct json_object *jobj = json_object_new_object();
    struct json_object *jusers = json_object_new_array();

    char line[BUFFER_SIZE];
    while (fgets(line, sizeof(line), csv_file)) {
        char *username = strtok(line, ",");
        char *password = strtok(NULL, "\n");

        if (!username || !password) {
            fprintf(stderr, "Invalid format in CSV\n");
            continue;
        }

        char bcrypt_seed[100];
        char password_hash[100];

        // Generate bcrypt seed
        strcpy(bcrypt_seed, "$2y$12$");

        // Generate bcrypt hash
        bcrypt_gensalt(12, bcrypt_seed);
        bcrypt_hashpw(password, bcrypt_seed, password_hash);

        struct json_object *juser = json_object_new_object();
        json_object_object_add(juser, "username", json_object_new_string(username));
        json_object_object_add(juser, "password_hash", json_object_new_string(password_hash));
        json_object_object_add(juser, "bcrypt_seed", json_object_new_string(bcrypt_seed));

        json_object_array_add(jusers, juser);
    }

    fclose(csv_file);

    json_object_object_add(jobj, "users", jusers);

    // Write JSON to file
    FILE *fp = fopen(output_file, "w");
    if (fp != NULL) {
        fputs(json_object_to_json_string_ext(jobj, JSON_C_TO_STRING_PRETTY), fp);
        fclose(fp);
        printf("%s generated successfully.\n", output_file);
    } else {
        printf("Error opening %s for writing.\n", output_file);
    }

    // Free JSON object
    json_object_put(jobj);

    return 0;
}

