package com.kdnakt.tls;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.OutputStream;
import java.security.PublicKey;

public class ClientKeyExchange {

    private PublicKey pubKey;
    public ClientKeyExchange(PublicKey pubKey) {
        this.pubKey = pubKey;
    }
    public void writeTo(OutputStream out) throws IOException {
        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        baos.write(0x16); // type handshake
        baos.write(0x03); // major version
        baos.write(0x01); // minor version

        // calculate length
        baos.write(0x25);
        byte handshakeType = 0x10;
        baos.write(handshakeType);
        byte messageLen1 = 0x00;
        baos.write(messageLen1);
        byte messageLen2 = 0x00;
        baos.write(messageLen2);
        byte messageLen3 = 0x21;
        baos.write(messageLen3);
        byte encodedLen = 0x20;
        baos.write(encodedLen);
        byte[] encoded = pubKey.getEncoded();
        baos.write(encoded, 9, encodedLen);
        baos.writeTo(out);
    }

}
