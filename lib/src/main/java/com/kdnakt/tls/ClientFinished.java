package com.kdnakt.tls;

import java.io.IOException;
import java.io.OutputStream;
import java.util.ArrayList;
import java.util.List;

import javax.crypto.spec.SecretKeySpec;

public class ClientFinished {

    private byte[] clientWriteIV;
    private SecretKeySpec masterSecret;
    private List<HandshakeMessage> handshakes = new ArrayList<>();

    public ClientFinished(byte[] clientWriteIV, SecretKeySpec masterSecret, ClientHello clientHello, ServerHello sh, Certificate certificate, ServerKeyExchange ske,
            ServerHelloDone done, ClientKeyExchange cke, ClientChangeCipherSpec cccs) {
        this.clientWriteIV = clientWriteIV;
        this.masterSecret = masterSecret;
        handshakes.add(clientHello);
        handshakes.add(sh);
        handshakes.add(certificate);
        handshakes.add(ske);
        handshakes.add(done);
        handshakes.add(cke);
        handshakes.add(cccs);
    }

    public void writeTo(OutputStream out) throws IOException {
        byte[] message = null;
        // record header
        // encryption IV
        // encrypted handshake message

        // handshake message
        // type = 14
        // length = uint24

        // verify data
        // seed = "client finished" + SHA256(all handshake messages)
        // a0 = seed
        // a1 = HMAC-SHA256(key=MasterSecret, data=a0)
        // p1 = HMAC-SHA256(key=MasterSecret, data=a1 + seed)
        // verify_data = p1[first 12 bytes]
        out.write(message);
    }

    public List<HandshakeMessage> getHandshakes() {
        return handshakes;
    }

}
