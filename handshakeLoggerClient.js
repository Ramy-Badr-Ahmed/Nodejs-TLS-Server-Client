

function logHandshakeClientDetails(conn) {

    class Exported_keyingMaterials {
        constructor(client_finished, server_finished, master_secret, key_expansion, ttls_challenge, ttls_keying_material, client_EAP_encryption) {
            this.client = client_finished;
            this.server = server_finished;
            this.master = master_secret;
            this.keyExp = key_expansion;
            this.ttlsCh = ttls_challenge;
            this.keying = ttls_keying_material;
            this.Cl_EAP = client_EAP_encryption;
        }
    }

    const keyingMaterial = new Exported_keyingMaterials(
        conn.exportKeyingMaterial(128, 'client finished'),
        conn.exportKeyingMaterial(128, 'server finished'),
        conn.exportKeyingMaterial(128, 'master secret'),
        conn.exportKeyingMaterial(128, 'key expansion'),
        conn.exportKeyingMaterial(128, 'ttls challenge'),
        conn.exportKeyingMaterial(128, 'ttls keying material'),
        conn.exportKeyingMaterial(128, 'client EAP encryption')
    );

    console.log(`Server's Cert fingerprint256: ${conn.getPeerCertificate().fingerprint256}`);
    console.log(`Server's Cert Serial Number: ${conn.getPeerCertificate().serialNumber}`);

    console.log("TLS Session Ticket", conn.getTLSTicket());

    console.log("Keying Materials:", keyingMaterial);

    console.log(`"Secure-Connect Event emitted": Handshake process successfully completed`);

    const serverCert = conn.getPeerCertificate(true);
    console.log("Server Certificate:", serverCert);

    console.log("Authorized Server:", conn.authorized);
    console.log("Authorization Error:", conn.authorizationError);
    console.log("Encrypted:", conn.encrypted);
    console.log("Protocol:", conn.getProtocol());
    console.log("Remote Address:", conn.remoteAddress + ":" + conn.remotePort);

    console.log("Negotiated Cipher Suite:", conn.getCipher());
    console.log("Ephemeral Key Exchange:", conn.getEphemeralKeyInfo());

    console.log("Handshake Finished Messages:", {
        "Sent": conn.getFinished().toString('hex'),
        "Received": conn.getPeerFinished().toString('hex')
    });

    console.log("Shared Signature Algorithms:", conn.getSharedSigalgs());

    console.log("-------------------------------------------------------");

    if (!conn.authorized) {
        console.log("Server Verification Failed. Aborting");
        conn.destroy();
    }
}

export { logHandshakeClientDetails};
