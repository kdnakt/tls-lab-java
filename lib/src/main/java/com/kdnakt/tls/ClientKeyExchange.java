package com.kdnakt.tls;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.OutputStream;
import java.security.PublicKey;

public class ClientKeyExchange implements HandshakeMessage {

    private PublicKey pubKey;
    public ClientKeyExchange(PublicKey pubKey) {
        this.pubKey = pubKey;
    }
    public void writeTo(OutputStream out) throws IOException {
        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        baos.write(0x16); // type handshake
        baos.write(0x03); // major version
        baos.write(0x03); // minor version

        // calculate length
        byte handshakeType = 0x10;
        byte[] encoded = pubKey.getEncoded();
        int encodedLen = encoded.length;
        int mLen = encodedLen + 1;
        int handshakeLen = mLen + 3 + 1;
        baos.write(handshakeLen >> 8);
        baos.write(handshakeLen);
        baos.write(handshakeType);
        baos.write(mLen >> 16);
        baos.write(mLen >> 8);
        baos.write(mLen);
        baos.write(encodedLen);
        baos.write(encoded);
        baos.writeTo(out);
    }

    @Override
    public int[] getMessage() {
        int[] message = new int[40];
        return message;
    }

}
