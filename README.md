# Encrypted Bind Shell

## Disclaimer

**This script is intended for educational purposes only. This should not be used for malicious purposes like attacking someone or anything like that. Always ensure you have explicit permission before performing such actions on any system.**

This script was included in the Python201 course by TCM Security. I have enhanced it a little bit and modified some more advanced features.

## Prerequisites

- Python 3.x
- Required libraries: `pycryptodome`, `argparse`

You can install the required libraries using:
```sh
pip install pycryptodome
```

## Script Overview

This script creates a bind shell server and client with AES encryption to secure the data transmitted between them. The server listens for incoming connections from clients and executes shell commands received from them, sending back the output. The communication between the server and clients is encrypted using AES-256.

### Key Features:
- AES-256 encryption for secure communication
- Handling large data chunks for reliable transmission
- Multithreading to support multiple clients simultaneously

## How to Use

### Server Mode

To start the bind shell server, run:
```sh
python encrypted_bind_shell.py --server --port PORT --clients MAX_CLIENTS --key AES_KEY
```

- `--port`: Port number to use (default: 9999)
- `--clients`: Maximum number of simultaneous clients (default: 5)
- `--key`: AES encryption key in hexadecimal format (64 characters for 256-bit key)

Example:
```sh
python encrypted_bind_shell.py --server --port 9999 --clients 5 --key 0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef
```

### Client Mode

To start the bind shell client, run:
```sh
python encrypted_bind_shell.py --target TARGET_IP --port PORT --key AES_KEY
```

- `--target`: IP address of the target server
- `--port`: Port number to use (default: 9999)
- `--key`: AES encryption key in hexadecimal format (64 characters for 256-bit key)

Example:
```sh
python encrypted_bind_shell.py --target 192.168.1.10 --port 9999 --key 0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef
```

## Demonstration
A Basic Demonstration of the Server and Client Side
![demo1](https://github.com/user-attachments/assets/913a4c00-c7c0-4cac-aaa0-31d62826b85b)

In case If the server limit setted by user is reached then the waiting list starts and client is connected to server as soon as the server is free
![demo2](https://github.com/user-attachments/assets/dd2e2bbe-5951-4be7-b96c-ddac5d161643)



## Libraries and Concepts Used

### Libraries
- `socket`: Provides low-level networking interface.
- `subprocess`: Allows for spawning new processes, connecting to their input/output/error pipes, and obtaining their return codes.
- `threading`: Offers a way to run multiple threads (tasks, function calls) at once.
- `argparse`: A parser for command-line options, arguments, and subcommands.
- `pycryptodome`: A self-contained Python package of low-level cryptographic primitives.

### Concepts
- **AES Encryption**: Advanced Encryption Standard used to encrypt and decrypt data ensuring secure communication.
- **Bind Shell**: A type of reverse shell where the server binds to a specific port and waits for an incoming connection from a client.
- **Multithreading**: Running multiple threads simultaneously to handle multiple client connections.

## Further Improvements

- Implementing better error handling and logging mechanisms.
- Adding more server and client features.
- Enhancing the user interface for a more intuitive interaction.
- Integrating more advance encryption modes and security features.

## Contact Me

For questions or further discussions, please contact me at [syed4000saad@gmail.com](mailto:syed4000saad@gmail.com).

## Contributing

Feel free to submit issues or pull requests for improvements.

## References
- [Python Socket Programming Documentation](https://docs.python.org/3/library/socket.html)
- ChatGPT by OpenAI (for debugging :) )
