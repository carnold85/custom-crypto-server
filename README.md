# custom-cryptd

A C++ custom encryption and decryption network server using **Libgcrypt** and **libb64**.

`custom-cryptd` is a network server that provides encryption and decryption services over a custom protocol, inspired by SMTP. It supports AES-256 with Galois/Counter Mode (GCM) for secure and efficient encryption. The server includes features for standalone and persistent key management, as well as real-time usage statistics.

---

## Features

- **Custom Protocol**: Interact with the server using commands like `ENCRYPT`, `DECRYPT`, and `STATS`.
- **AES-256-GCM Encryption**: High-performance, authenticated encryption using Libgcrypt.
- **Key Management**:
  - Standalone mode for ephemeral keys.
  - Persistent key files secured with `scrypt` KDF.
- **Real-time Stats**: Track connection and encryption/decryption usage metrics.
- **Base64 Encoding**: All encrypted data is Base64 encoded for safe transfer.

---

## Installation

### Requirements
- **Debian-based systems**: 
  - `make`, `g++`, `libgcrypt20-dev`, `libb64-dev`
- **Libpthread** (usually part of the base system)

### Build
To compile the program, use the provided Makefile:
```bash
make       # Build the program
make all   # Alternative to build
make clean # Remove compiled files
```

---

## Usage

### Supported Command-Line Options
```text
Usage: ./custom-cryptd [-p port] [-P pidfile] [-d] [-l] [-S] cryptoFile [...]
OR:     -g cryptoFile
        -S
        -? or -h
        -V

Switches:
-p:        Port number for incoming connection (default 10000)
-l:        Listen only on localhost IP address
-d:        Start in Daemon mode
-P:        Path and filename for PID file (default /var/run/custom-cryptd.pid)
-S:        Standalone Key mode - generate and use key without saving it.
-g:        Generate a persistent key file
-? or -h:  Show help
-V:        Show version and build information
cryptoFile(s): Use pre-generated key files
```


### Key Management
To generate and use persistent key files:
1. **Generate a Key**:
   ```bash
   sudo ./custom-cryptd -g <keyfile>
   ```
   Example:
   ```plaintext
   ./custom-cryptd trying to generate KeyFile: foo.key
   GCRYPT INFO: Generating new AESKey done!
   Please enter passphrase:
   Password received - doing magic...
   GCRYPT INFO: Key file with KeyID <3972C4AA> successfully generated!
   ```

2. **Use a Key**:
   ```bash
   sudo ./custom-cryptd <keyfile>
   ```
   Example:
   ```plaintext
   ./custom-cryptd trying to load KeyFile: foo.key
   GCRYPT INFO: Found key file with KeyID <3972C4AA>
   Please enter passphrase:
   Password received - doing magic...
   GCRYPT INFO: Key file decrypted successful
   ```


### Standalone Mode
In standalone mode (`-S`), the server generates an ephemeral key on-the-fly, which is not saved. This key is only valid for the current session and cannot be reused once the server shuts down. 

```bash
sudo ./custom-cryptd -S
```

**Caution**: Use standalone mode only for temporary or one-time encryption tasks, as data cannot be decrypted after the server exits.

---

## Protocol Overview

### Connection Greeting
When a client connects to the server, a greeting is sent in the following format:
```plaintext
220 CSP/1.0 Custom Crypto Server
```
Clients should respond with an `EHLO` command followed by the protocol version (`CSP/1.0`) and a custom client name (used for logging):
```plaintext
EHLO CSP/1.0 <CustomClientName>
```
Example:
```plaintext
EHLO CSP/1.0 LocalClient001
```

The server responds with:
```plaintext
250 OK
```

### Newline and Termination with `.`

All data sent to the server must be terminated by a newline (`\n`) and a single period (`.`) on a new line. This format is essential for signaling the end of a command or data block.

Example of sending a string for encryption:
```plaintext
ENCRYPT
354 Send data.
Hello World!
.
```
The server processes the data and returns the result, also terminated with `.`:
```plaintext
537 OK, data follows
$13771D9F7... (Base64 Encrypted String)
.
```

This mechanism is consistent for all commands (`ENCRYPT`, `DECRYPT`, and `STATS`).

### Commands
- **ENCRYPT**: Encrypt data.
  - Usage: Send plaintext data followed by `.` to encrypt.
- **DECRYPT**: Decrypt data.
  - Usage: Send Base64-encoded ciphertext followed by `.` to decrypt.
- **STATS**: Display server statistics.

---

## Example Protocol Session

Here’s a complete example of a session:

```plaintext
$ telnet 127.0.0.1 10000
Trying 127.0.0.1...
Connected to 127.0.0.1.
220 CSP/1.0 Custom Crypto Server
EHLO CSP/1.0 LocalClient001
250 OK
ENCRYPT
354 Send data.
Hello World!
.
537 OK, data follows
$13771D9F7dmfTIShK16AaG7H5p1o6j1t4+A2X5BgzZ9/sSy7H8XwTjTFQ6zwApXrsTIw=
.
DECRYPT
354 Send data.
$13771D9F7dmfTIShK16AaG7H5p1o6j1t4+A2X5BgzZ9/sSy7H8XwTjTFQ6zwApXrsTIw=
.
537 OK, data follows
Hello World!
.
STATS
custom-cryptd running since:              Mon, 06 Jan 2025 00:01:17 +0100
Overall connections:                      2
Current active connections:               1
Key ID <3771D9F7> encryption successes:   1
Key ID <3771D9F7> encryption failures:    0
Key ID <3771D9F7> decryption successes:   2
Key ID <3771D9F7> decryption failures:    0
Other de-/encryption failures:            0
custom-cryptd Version 1.0
Compiled on Jan  5 2025 at 23:59:51
.
QUIT
421 Have a nice day
Connection closed by foreign host.
```

---

## Cryptographic Details

- **Cipher**: AES-256 with Galois/Counter Mode (GCM)
- **Key Management**:
  - Keys stored securely in files and protected with `scrypt` KDF.
  - Ephemeral keys supported in standalone mode (`-S`).
- **Initialization Vector (IV)**: 16 bytes
- **Block Size**: 16 bytes
- **Key Size**: 32 bytes
- **Password-based Key Derivation**:
  - CPU/memory cost: `65536`
  - Parallelization parameter: `16`

---

## Notes

- This project was written in 2018 and may not reflect modern best practices.
- Root privileges (`sudo`) are required due to `GCRYCTL_INIT_SECMEM`.



## **Running with Docker**

You can use Docker to easily run and manage the `custom-cryptd` server and key generator.

### **Generating Keys**
To generate a new key, use the following command:
```bash
docker-compose run --rm cryptd-generator
```
This will generate a new key file in the shared volume (`crypto-keys`) and exit.

---

### **Starting the Server**
To start the `cryptd-server`, use the following command:
```bash
docker-compose up -d cryptd-server
```
This will run the server in detached mode.

---

### **Entering Passphrases**
The `cryptd-server` requires you to enter the passphrases for your keys during startup. To do this:
1. Attach to the running `cryptd-server` container:
   ```bash
   docker attach cryptd-server
   ```
2. Enter the required passphrases when prompted.

---

### **Detaching from the Server**
Once you've entered the passphrases:
1. Detach from the container without stopping it:
   - Press **`Ctrl+P`** followed by **`Ctrl+Q`**.

The `cryptd-server` will continue running in the background.

---

### **Accessing Logs**
To view logs from the `cryptd-server`:
```bash
docker-compose logs -f cryptd-server