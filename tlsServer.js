import tls from 'tls';
import fs from 'fs';
import { v4 as uuidv4, v5 as uuidv5 } from 'uuid';
import crypto from 'crypto';

const { logHandshakeDetails } = require('./handshakeLoggerServer');

const options = {
    selfHost: 'Your_Host',
    servername: 'Your-Server-Name',
    isServer: true,
    requestCert: true,
    rejectUnauthorized: true,
    minVersion: 'TLSv1.2',
    ecdhCurve: 'P-521:P-384:P-256',
    honorCipherOrder: true,
    sessionTimeout: 300,    
    sessionIdContext: crypto.randomBytes(16).toString('hex'),
    ticketKeys: crypto.randomBytes(48),
    handshakeTimeout: 120000,
    ca: [
        fs.readFileSync(__dirname + "/Certs/server/ed25519/Your-CA-chain-bundle-cert.pem"),
        fs.readFileSync(__dirname + "/Certs/server/ecdsa/Your-CA-chain-bundle-cert.pem"),
        fs.readFileSync(__dirname + "/Certs/server/rsa/Your-CA-chain-bundle-cert.pem")
    ],
    key: fs.readFileSync(__dirname + '/Certs/server/ed25519/Your-server-key.pem'),
    cert: fs.readFileSync(__dirname + '/Certs/server/ed25519/Your-server-cert.pem')
};

const sessions = {};        // Session storage (you can use a database or an in-memory object)

let clients = 0;

const requestListener = function (socket) {
    clients++;
    console.log('Client connected:', clients);
    
    const datetime = new Date();
    socket.setEncoding('utf8');
    
    const now = {
        "uuid4": uuidv4({ random: crypto.randomFillSync(new Uint8Array(16)) }),
        "En_GB": datetime.toLocaleString('en-GB'),
        "ISO": datetime.toISOString(),
        "JSON": datetime.toJSON(),
        "To_UTC_String": datetime.toUTCString(),
        "To_Time_String": datetime.toTimeString(),
        "To_LocaleString": datetime.toLocaleString(),
        "TO_LocaleDateString": datetime.toLocaleDateString(),
        "To_DateString": datetime.toDateString(),
        "ms_since1970": datetime.getTime(),
        "Custom_Time": `${datetime.getHours() < 10 ? '0' + datetime.getHours() : datetime.getHours()}:${datetime.getMinutes() < 10 ? '0' + datetime.getMinutes() : datetime.getMinutes()}:${datetime.getSeconds()}:${datetime.getMilliseconds()}`,
        "Custom_Date": `${datetime.getFullYear()}-${datetime.getMonth() + 1 < 10 ? '0' + `${datetime.getMonth() + 1}` : datetime.getMonth() + 1 }-${datetime.getDate() < 10 ? '0' + datetime.getDate() : datetime.getDate()}`
    };
    
    const custom_namespace = now.uuid4;
    now.uuidv5 = uuidv5('Hello, World!', custom_namespace);
    
    socket.write(`\r\n\n${JSON.stringify(now)} \r\n\n`);
    socket.end();
    
    socket.on('data', function (data) {
        console.log('Client Sent: ', data.toString());
    });
    
    socket.on('end', () => {
        console.log(`\n\t\u2192 \u2192\t"End" Event emitted: End of Client Transmission`);
        console.log('Client Disconnected:', clients);        
    });
}

const server = tls.createServer(options, requestListener);

server.listen(port, host, () => {
    if (server.listening) console.log(`\n\tTime-Server is publicly running on Secure TCP Socket: ${host}:${port}`);
});

server.on('error', (err) => {
    console.log('Something went wrong');
    throw err;
});

server.on('listening', () => {
    console.log(`\n\t\u2192 \u2192\t"Listening" Event emitted: server.listen() has been called`);
});

server.on('close', () => {
    console.log(`\n\t\u2192 \u2192\t"Close" Event emitted: Server is closed`);
});

server.on('connection', function () {
    console.log(`\n\t\u2192 \u2192\t"Connection" Event emitted: Successful Connection to Server Initialised. Handshake will begin now ...`);
});

server.on('OCSPRequest', function (cert, issuer, callback) {
    console.log(`\n\t\u2192 \u2192\t"OCSPRequest" Event emitted: Client has sent certificate status request \n`);
    callback();
});

server.on('secureConnection', function (tlssocket) {
    console.log(`\n\t\u2192 \u2192\t"secureConnection" Event emitted: Handshake process successfully completed. Creating Handshake Report..\n`);    
   
    console.log("TLS Session", {
        'Reused': tlssocket.isSessionReused(),
        'Server Ticket Key': server.getTicketKeys().toString('hex')         
    });

    // Log details about the connection and security parameters. Consider extracting this to a separate rotating logfile.
    logHandshakeDetails(tlssocket);
});

server.on('newSession', function (sessionId, sessionData, callback) {
    console.log(`\n\t\u2192 \u2192\t"newSession" Event emitted: A new TLS session created with ID: ${sessionId.toString("hex")}\n`);

    sessions[sessionId.toString("hex")] = sessionData;

    console.log(`TLS Session Ticket: ${server.getTicketKeys().toString('hex')}`);
    console.log('Current Sessions:', sessions);

    callback(); 
});

server.on('resumeSession', function (sessionId, callback) {
    console.log(`\n\t\u2192 \u2192\t"resumeSession" Event emitted: Client requested to resume a TLS session with ID: ${sessionId.toString("hex")}\n`);

    sessionId = sessionId.toString("hex");

    if (sessionId in sessions) {
        console.log('Resuming an existing session');
        callback(null, sessions[sessionId]); 
    } else {
        console.log('Starting a new session');
        callback(null, null); 
    }
});

server.on('keylog', (line, tlssocket) => {

    let KeyLogs_Array = [];

    if (line.toString().split(" ")[0] === 'SERVER_HANDSHAKE_TRAFFIC_SECRET') {
        console.log(`\n\t\u2192 \u2192\t"keylog" Event emitted: Capturing TLS Traffic ...`);
    }
    KeyLogs_Array.push(line.toString().split(" "));
    if (line.toString().split(" ")[0] === 'CLIENT_TRAFFIC_SECRET_0') {
        console.log(`\nLogging TLS Traffic for ${tlssocket.remoteAddress}`);
        console.log(KeyLogs_Array);        
    }
});

server.on('tlsClientError', function (err, tlssocket) {
    console.log(`\t\u2192 \u2192\t"tlsClientError Event emitted": An error occurred before a secure connection is established \n`);
    if (err) console.log(err.code);
    if (err.code === 'ECONNRESET' || !tlssocket.writable) {
        console.log('\n\t\t-----------------------------------------');
        console.log("\t\tAuthorised Client: " + tlssocket.authorized);
        console.log("\t\tAuthorisation Error: " + tlssocket.authorizationError);
        console.log(`\t\tClosing/Destroying the Underlying Socket`);
        console.log('\t\t-----------------------------------------');
        tlssocket.destroy();
        return;
    }
});
