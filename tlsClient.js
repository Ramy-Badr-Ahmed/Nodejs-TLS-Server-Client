import tls from 'tls';
import net from 'net';
import fs from 'fs';

const { logHandshakeClientDetails } = require('./handshakeloggerClinet');


var retryInterval = 3000; 
var retriedTimes = 0;
var maxRetries = 3;

let storedSession = null;

const options = {
    host: 'Your-Connecting-Host',
    port: 'Your-Connecting-Port',
    session: undefined,
    isServer: false,
    rejectUnauthorized: true,
    headers: {
        'X-Forwarded-For': 'Server IP'
    },
    checkServerIdentity: (serverHostname, serverCert) => {
        const altNames = serverCert.subjectaltname;

        if (!altNames) {    // not of type X.509.v3
            console.error('\nServer certificate does not have subjectAltName. Aborting request.');
            throw new Error('Server certificate does not have subjectAltName.');
        }

        const dnsNames = [];
        const ips = [];

        const altNamesArr = altNames.split(', ');

        for (const name of altNamesArr) {
            if (name.startsWith('DNS:')) {
                dnsNames.push(name.slice(4));
            } else if (name.startsWith('IP Address:')) {
                ips.push(name.slice(11));
            }
        }

        let validHostname = false;

        if (net.isIP(serverHostname) === 0) {
            console.log(`\nConnecting host '${serverHostname}' is a DNS name.`);
            console.log(`\nComparing server's hostname '${serverHostname}' with DNS altNames [${dnsNames.join(', ')}].`);
            validHostname = dnsNames.includes(serverHostname);
        } else {
            console.log(`\nConnecting host '${serverHostname}' is an IP address.`);
            console.log(`\nComparing server's IP address '${serverHostname}' with IP altNames [${ips.join(', ')}].`);
            validHostname = ips.includes(serverHostname);
        }

        if (!validHostname) {
            console.error(`\nServer identity mismatch (HN!=AltName). Aborting request.`);
            throw new Error(`Server hostname '${serverHostname}' does not match any DNS or IP altNames in the certificate.`);
        }

        console.log(`\nComparing server's hostname '${serverHostname}' with CN '${serverCert.subject.CN}'.`);
        if (serverHostname !== serverCert.subject.CN) {
            console.error(`\nServer identity mismatch (HN!=CN). Aborting request.`);
            console.log(`IP: ${serverHostname} is not in the cert's list: ${ips.join(', ')}`);
            throw new Error(`\nServer hostname '${serverHostname}' does not match CN '${serverCert.subject.CN}' in the certificate.`);
        }
    },
    ca: [
        fs.readFileSync(__dirname + "/Certs/client/ed25519/Your-CA-chain-bundle-cert.pem"),
        fs.readFileSync(__dirname + "/Certs/client/ecdsa/Your-CA-chain-bundle-cert.pem"),
        fs.readFileSync(__dirname + "/Certs/client/rsa/Your-CA-chain-bundle-cert.pem")
    ],
    key: fs.readFileSync(__dirname + '/Certs/client/ecdsa/Your-Client-key.pem'),
    cert: fs.readFileSync(__dirname + '/Certs/client/ecdsa/Your-Client-cert.pem')
};

var conn = tls.connect(options, connectionListener);

function connectionListener() {
    
    conn.write('Your Time is?\r\n', () => {
        console.log('\nData was written out. Requested From Server');
    });    
    conn.end();     
}
    
    conn.on('data', (data) => {
        console.log('\n\nIncoming Data:', data.toString()); 
        //console.log('\n\nJSON Buffer Object Incoming Date:', data.toJSON());     
        //console.log('\n\nJSON Object Incoming Date:', JSON.parse(data.toString()));          
    });
        
    conn.on('connect', function () {
        console.log('\n\t\u2192 \u2192\tConnected to Time Server');
    });

    
    conn.on('close', function (hadError) {
        console.log('\nSocket is fully closed', hadError ? 'due to an error' : '');

        if (!hadError) {
            retriedTimes = 0;
            return;        
        }
    
        retriedTimes++;
        console.log(`\n\t\u2192 \u2192\t"Close" Event emitted: Socket is fully closed due to an Error. ${retriedTimes < maxRetries ? 'Attempting reconnection ' + retriedTimes + '/' + maxRetries : 'Reconnection times out'}`);
            
        if (retriedTimes < maxRetries) {
            setTimeout(() => {
                console.log(`\nAttempting reconnection ${retriedTimes + 1}/${maxRetries}`);
                conn.connect(options, connectionListener);
            }, retryInterval);
        } else {
            console.log('\nMax retries exceeded. Reconnection attempts aborted.');
            throw new Error('\nMax retries have been exceeded, I give up.');            
        }
    });

    
    conn.on('error', function (err) {
        console.error('Error occurred:', err);
        console.log('\n\t\t-----------------------------------------');
        console.log("\t\tAuthorised Server: " + conn.authorized);         
        console.log("\t\tAuthorisation Error: " + conn.authorizationError);
        console.log(`\t\tClosing/Destroying the Underlying Socket`);
        console.log('\t\t-----------------------------------------');
    });

    conn.on('lookup', function (err, address, family, host) {                    
        console.log(`\n\t\u2192 \u2192\t"lookup" Event emitted: resolving the host name but before connecting`);
        if (err) {
            console.error('\nLookup error:', err.message);
            throw err;
        } else {
            console.log(`\n\tFound address: ${address}, family: ${family}, host: ${host}`);
        }
    });
    
    conn.on('ready', function () {                       
        console.log(`\n\t\u2192 \u2192\t"Ready" Event emitted: Socket is ready.`);
        console.log(`\tCurrent retry attempts: ${retriedTimes}`);
    });
        
    conn.on('OCSPRequest', function (cert, issuer, callback) {
        console.log('\nClient sent certificate status request');
        callback();
    });

    let KeyLogs_Array = [];

    conn.on('keylog', (line, tlssocket) => {
        if (line.toString().split(" ")[0] === 'SERVER_HANDSHAKE_TRAFFIC_SECRET') {
            console.log(`\n\t\u2192 \u2192\t"keylog" Event emitted: Capturing TLS Traffic ...`);
        }

        KeyLogs_Array.push(line.toString().split(" "));

        if (KeyLogs_Array[KeyLogs_Array.length - 1][0] === 'CLIENT_TRAFFIC_SECRET_0') {
            console.log(`\nLogging TLS Traffic for ${conn.remoteAddress}`);
            console.log(KeyLogs_Array);
        }
    });


    conn.on('secureConnect', function () {
        console.log('\nSecure connection established');
        logHandshakeClientDetails(conn);
    });

    conn.on('session', function (SessBuffer) {
        console.log(`"\nSession" Event emitted: A new session or TLS ticket is available`);
        storedSession = SessBuffer;

        console.log("\nReused Session : ", conn.isSessionReused());
        console.log('\nSession Data: ', conn.getSession());
        console.log('\ngetTLSTicket(): ', conn.getTLSTicket());
    });

    conn.on('newSession', (sessionId, sessionData) => {
        console.log(`\nNew session created by server. ID: ${sessionId.toString('hex')}`);
        // Optionally handle and store new sessions if needed
    });

    conn.on('resumeSession', (sessionId, callback) => {
        console.log(`Server requested to resume session with ID: ${sessionId.toString('hex')}`);
            
        if (storedSession) {
            console.log('\nResuming session...');
            callback(null, storedSession);
        } else {
            console.log('\nNo session available for resumption. Starting new session.');
            callback(null, null);
        }
    });
