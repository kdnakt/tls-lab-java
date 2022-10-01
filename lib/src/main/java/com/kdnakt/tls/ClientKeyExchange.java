package com.kdnakt.tls;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.OutputStream;
import java.security.PublicKey;
import java.security.interfaces.ECPublicKey;
import java.security.spec.ECPoint;
import java.security.spec.EllipticCurve;
import java.util.Arrays;

public class ClientKeyExchange implements HandshakeMessage {

    private PublicKey pubKey;
    private EllipticCurve curve;
    public ClientKeyExchange(PublicKey pubKey, EllipticCurve curve) {
        this.pubKey = pubKey;
        this.curve = curve;
    }
    public void writeTo(OutputStream out) throws IOException {
        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        baos.write(getType());
        baos.write(0x03); // major version
        baos.write(0x03); // minor version

        // calculate length
        byte handshakeType = 0x10;
        ECPoint p = ((ECPublicKey) pubKey).getW();
        // cf: https://github.com/AdoptOpenJDK/openjdk-jdk11/blob/master/src/java.base/share/classes/sun/security/util/ECUtil.java#L64
        int n = (curve.getField().getFieldSize() + 7) >> 3;
        byte[] xb = trimZeroes(p.getAffineX().toByteArray());
        byte[] yb = trimZeroes(p.getAffineY().toByteArray());
        if ((xb.length > n) || (yb.length > n)) {
            throw new RuntimeException
                ("Point coordinates do not match field size");
        }

        byte[] encoded = new byte[1 + (n << 1)];
        encoded[0] = 4; // uncompressed
        System.arraycopy(xb, 0, encoded, n - xb.length + 1, xb.length);
        System.arraycopy(yb, 0, encoded, encoded.length - yb.length, yb.length);
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
        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        try {
            writeTo(baos);
        } catch (IOException ignore) {
        }
        byte[] message = baos.toByteArray();
        int[] res = new int[message.length];
        for (int i = 0; i < message.length; i++) {
            res[i] = message[i];
        }
        return res;
    }


    static byte[] trimZeroes(byte[] b) {
        int i = 0;
        while ((i < b.length - 1) && (b[i] == 0)) {
            i++;
        }
        if (i == 0) {
            return b;
        }

        return Arrays.copyOfRange(b, i, b.length);
    }

    @Override
    public int getType() {
        return 16;
    }
}
