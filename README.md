![Node.js](https://img.shields.io/badge/node.js-100%25-green)
![GitHub top language](https://img.shields.io/github/languages/top/Ramy-Badr-Ahmed/node-tls?cacheSeconds=1&color=yellow)
![GitHub](https://img.shields.io/github/license/Ramy-Badr-Ahmed/node-tls?cacheSeconds=1&color=red)

# TLS Communication with Node.js

A TLS server and client implementation using Node.js's tls module, operating at the Presentation Layer of the OSI Model. 
This implementation focuses on encrypted and authenticated communication, suitable for secure and trusted networks.

#### Use Cases:

- Network Security

    > Ensure secure communication between network segments with TLS encryption and certificate-based authentication.

- Secure Embedded Systems Communication

    > Integrate TLS client with embedded devices (e.g., Raspberry Pi, Arduino with Ethernet/Wi-Fi shields) to send data securely to a central server for monitoring and control.

- Secure Time Synchronization

    > Use the server to provide a timestamp service for devices on a network, ensuring synchronized time across various systems with TLS security.

- Secure IoT Applications

    > Use the TLS server as a central hub to collect data from various IoT devices securely.
    
    > Set up the TLS client to send sensor data periodically from remote IoT devices to the server for analysis (centralized secure data receiver/logger).

### Quick Start:

Prerequisites:

- Node.js (v14.x or later)
- OpenSSL (for generating certificates)

Server:

Place server certificate and key under the `Certs\server` directory

```shell
npm install
node tlsServer.js   # Runs Server
```  

Client:

Place client certificate and key under the `Certs\client` directory

```shell
npm install
node tlsClient.js   # Runs Client
```  

Logs and Outputs:

The server and client will log various events and actions, such as connection establishment, data transmission, handshake report, session management, and encountered errors.
