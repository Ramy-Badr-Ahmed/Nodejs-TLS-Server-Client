![NODE.JS](https://img.shields.io/badge/NODE.JS-%2343853D.svg?&style=plastic&logo=node.js&logoColor=white) ![JavaScript](https://img.shields.io/badge/JavaScript-323330?style=plastic&logo=javascript&logoColor=f7df1e)

[![SWH](https://archive.softwareheritage.org/badge/swh:1:dir:8017c373f704257957a1cc9b5044c7347651b899/)](https://archive.softwareheritage.org/swh:1:dir:8017c373f704257957a1cc9b5044c7347651b899;origin=https://github.com/Ramy-Badr-Ahmed/node-tls;visit=swh:1:snp:eec57a10aaa0a231ac22e6c8a476c167a0669b66;anchor=swh:1:rev:0b48c4c274fb30ea4c7913f1d77083f9e2baa888) ![GitHub](https://img.shields.io/github/license/Ramy-Badr-Ahmed/nodejs-tls_server-client?color=green)

# TLS Communication with Node.js

A TLS server and client implementation using Node.js's tls module, operating at the Presentation Layer of the OSI Model. 

This implementation focuses on encrypted and authenticated communication, suitable for secure and trusted networks.

The TCP variant (@Transport-Layer of the OSI Model) is located here: [Node-TCP](https://github.com/Ramy-Badr-Ahmed/node-tcp)

#### Use Cases:

- Network Security

    > Ensure secure communication between network segments with TLS encryption and certificate-based authentication.

- Secure Embedded Systems Communication

    > Integrate TLS client with embedded devices (e.g., Raspberry Pi, Arduino with Ethernet/Wi-Fi shields) to send data securely to a central server (for monitoring and control).

- Secure Time Synchronization

    > Use the server to provide a timestamp service for devices on a network (ensure synchronized time across various systems with TLS security).

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

References

- [TLS (SSL) Module](https://nodejs.org/api/tls.html)
