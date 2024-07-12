
function logHandshakeDetails(tlssocket) {

     // Export keying materials
     class ExportedKeyingMaterials {
        constructor(clientFinished, serverFinished, masterSecret, keyExpansion, ttlsChallenge, ttlsKeyingMaterial, clientEapEncryption) {
            this.client = clientFinished;
            this.server = serverFinished;
            this.master = masterSecret;
            this.keyExp = keyExpansion;
            this.ttlsCh = ttlsChallenge;
            this.keying = ttlsKeyingMaterial;
            this.ClEAP = clientEapEncryption;
        }
    }

    const keyingMaterial = new ExportedKeyingMaterials(
        tlssocket.exportKeyingMaterial(128, 'client finished'),
        tlssocket.exportKeyingMaterial(128, 'server finished'),
        tlssocket.exportKeyingMaterial(128, 'master secret'),
        tlssocket.exportKeyingMaterial(128, 'key expansion'),
        tlssocket.exportKeyingMaterial(128, 'ttls challenge'),
        tlssocket.exportKeyingMaterial(128, 'ttls keying material'),
        tlssocket.exportKeyingMaterial(128, 'client EAP encryption')
    );

    console.log(`\n\t→→ Handshake Report:\n`);
    
    console.log(`\t→→ Client's certificate:\n`);
    console.log(`\t\t - Subject: ${tlssocket.getPeerCertificate().subject.CN}`);
    console.log(`\t\t - Issuer: ${tlssocket.getPeerCertificate().issuer.CN}`);
    console.log(`\t\t - Valid from: ${tlssocket.getPeerCertificate().valid_from}`);
    console.log(`\t\t - Valid to: ${tlssocket.getPeerCertificate().valid_to}`);
    
    console.log(`\t→→ Secure connection parameters:\n`);
    console.log(`\t\t - Cipher (OpenSSL): ${tlssocket.getCipher().name}`);    
    console.log(`\t\t - Cipher (IETF): ${tlssocket.getCipher().standardName}`);
    console.log(`\t\t - Protocol: ${tlssocket.getProtocol()}`);
    console.log(`\t\t - Key exchange algorithm: ${tlssocket.getEphemeralKeyInfo().keyExchange}`);
    console.log(`\t\t - Public key type: ${tlssocket.getEphemeralKeyInfo().publicKeyType}`);                    
    
    console.log(`\t→→ Additional information:\n`);
    console.log(`\t\t - Remote address: ${tlssocket.remoteAddress}`);
    console.log(`\t\t - Remote port: ${tlssocket.remotePort}`);
    console.log(`\t\t - Authorised: ${tlssocket.authorized}`);
    console.log(`\t\t - Authorization error: ${tlssocket.authorizationError || 'None'}`);

    console.log(`\t→→ Exported keying materials:\n`, keyingMaterial);

    console.log(`\nShared Signature Algorithms:`);
    console.log(tlssocket.getSharedSigalgs());

    console.log(`\nHandshake's "Finished" Message: `)
    console.log({ "Sent": tlssocket.getFinished(), "Received": tlssocket.getPeerFinished() });
    console.log({ "Sent": tlssocket.getFinished().toString('hex'), "Received": tlssocket.getPeerFinished().toString('hex') });
    
}


export { logHandshakeDetails };