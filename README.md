# Secure Communication System with UI

This project implements a secure client-server communication system with user authentication, leveraging OpenSSL for secure communication, bcrypt for password hashing, and Motif for the user interface.

## Table of Contents

- [Prerequisites](#prerequisites)
- [File Descriptions](#file-descriptions)
- [Installation](#installation)
- [Usage](#usage)
  - [Generating TLS Keys](#generating-tls-keys)
  - [Generating Configuration File](#generating-configuration-file)
  - [Running the Server](#running-the-server)
  - [Running the Client](#running-the-client)
- [Troubleshooting](#troubleshooting)
- [Contributing](#contributing)
- [License](#license)

## Prerequisites

Ensure you have the following installed:

- GCC (GNU Compiler Collection)
- OpenSSL
- bcrypt
- json-c
- Motif

## File Descriptions:

    server.c: Server code that handles secure communication and user authentication.

    client.c: Client code that connects to the server and authenticates.

    generate_config.c: Utility to generate config.json from a CSV file.

    generate_tls.sh: Script to generate TLS keys and certificates.

    users.csv: Sample input file with user credentials.

    config.json: Generated configuration file with hashed passwords and seeds.

    Makefile: Builds the project.

## Installation

### Step 1: Install Dependencies

Install the required libraries:

```sh
sudo dnf install openssl openssl-devel
sudo dnf install json-c json-c-devel


For bcrypt, install it from source:

wget https://github.com/rg3/bcrypt/archive/refs/heads/master.zip
unzip master.zip
cd bcrypt-master
make
sudo cp libbcrypt.a /usr/local/lib/
sudo cp bcrypt.h /usr/local/include/


### Step 2: Generate the TLS key and cert:

chmod +x generate_tls.sh

Use default names:

./generate_tls.sh 
NOTE: Keys will be named key.pem and cert.pem by default

You may also specify custom names for the certificate and key:

./generate_tls.sh -c custom_cert.pem -k custom_key.pem


### Step 3: Generating Configuration File

Create a CSV file named users.csv with user credentials in the format username,password.


Example users.csv:

admin,password123
user2,secret



### Running the Server

Start the server:
Run the server with default key and cert names:
./server

Run the server with custom key and cert names:
./server -cert custom_cert.pem -key custom_key.pem

### Running the Client

Run the client with default cert name:

./client

Run the client with custom cert name:

./client -cert custom_cert.pem

Follow the prompts to enter your username and password.


## Contributing

Feel free to submit issues, fork the repository, and send pull requests. Contributions are welcome!
