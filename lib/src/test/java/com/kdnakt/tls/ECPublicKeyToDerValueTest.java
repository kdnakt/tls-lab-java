package com.kdnakt.tls;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.fail;

import java.io.ByteArrayOutputStream;
import java.math.BigInteger;
import java.security.AlgorithmParameters;
import java.security.KeyFactory;
import java.security.PublicKey;
import java.security.Security;
import java.security.spec.ECGenParameterSpec;
import java.security.spec.ECParameterSpec;
import java.security.spec.ECPoint;
import java.security.spec.ECPublicKeySpec;
import java.util.Arrays;

import org.junit.jupiter.api.Test;

public class ECPublicKeyToDerValueTest {
    @Test
    void test() {
        try {
            int[] publicKey = {
                4, 56, 176, 231, 62, 245, 228, 43, 86, 31,
                136, 199, 204, 62, 123, 93, 81, 221, 183,
                183, 243, 160, 128, 1, 64, 23, 22, 242, 116,
                9, 47, 18, 58, 106, 129, 67, 92, 55, 117, 78,
                64, 227, 215, 32, 101, 115, 220, 0, 170, 38,
                105, 91, 232, 39, 125, 8, 235, 45, 227, 94,
                160, 114, 224, 97, 249
            };
            AlgorithmParameters params = AlgorithmParameters.getInstance("EC", Security.getProvider("SunEC"));
            // params.init(new ECGenParameterSpec("1.3.101.110")); // X25519
            params.init(new ECGenParameterSpec("secp256r1"));
            ECParameterSpec ecParams = params.getParameterSpec(ECParameterSpec.class);

            KeyFactory f = KeyFactory.getInstance("EC");
            ByteArrayOutputStream point = new ByteArrayOutputStream();
            for (int k : publicKey) {
                point.write(k);
            }
            // cf: sun.security.util.ECUtil#decodePoint
            byte[] data = point.toByteArray();
            int n = (data.length - 1) / 2;
            byte[] xb = Arrays.copyOfRange(data, 1, 1 + n);
            byte[] yb = Arrays.copyOfRange(data, 1 + n, n + 1 + n);
            ECPoint ecPoint = new ECPoint(new BigInteger(1, xb), new BigInteger(1, yb));
            ECPublicKeySpec spec = new ECPublicKeySpec(ecPoint, ecParams);
            PublicKey serverPubKey = f.generatePublic(spec);
            assertEquals("EC", serverPubKey.getAlgorithm());
            assertEquals("X.509", serverPubKey.getFormat());
        } catch (Exception e) {
            fail(e);
        }
    }
}
