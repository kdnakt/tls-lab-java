package com.kdnakt.tls;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.OutputStream;
import java.security.PublicKey;
import java.security.interfaces.ECPublicKey;
import java.security.spec.ECPoint;
import java.util.Arrays;

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
        ECPoint p = ((ECPublicKey) pubKey).getW();
        byte[] x = Arrays.copyOfRange(p.getAffineX().toByteArray(), 1, 33);
        byte[] y = Arrays.copyOfRange(p.getAffineY().toByteArray(), 1, 33);
        int encodedLen = 1 + x.length + y.length;
        byte[] encoded = new byte[encodedLen];
        // TODO: read value from server hello Supported Point Formats Extension
        encoded[0] = 0x04; // uncompressed
        System.arraycopy(x, 0, encoded, 1, x.length);
        System.arraycopy(y, 0, encoded, 1 + x.length, y.length);
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
