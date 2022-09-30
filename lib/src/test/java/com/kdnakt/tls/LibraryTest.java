package com.kdnakt.tls;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.fail;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.math.BigInteger;
import java.net.Socket;
import java.security.AlgorithmParameters;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PublicKey;
import java.security.Security;
import java.security.cert.X509Certificate;
import java.security.interfaces.ECPrivateKey;
import java.security.spec.ECGenParameterSpec;
import java.security.spec.ECParameterSpec;
import java.security.spec.ECPoint;
import java.security.spec.ECPublicKeySpec;
import java.util.Arrays;

import javax.crypto.KeyAgreement;
import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;

import org.junit.jupiter.api.Test;

class LibraryTest {
    @Test void testClientHello() {
        try (Socket socket = new Socket("localhost", 443);
            OutputStream out = socket.getOutputStream();
            InputStream in = socket.getInputStream()) {

            ClientHello clientHello = new ClientHello();
            clientHello.writeTo(out);

            System.out.println();
            // Server Hello
            System.out.println("\n---Response---\n");
            int type = in.read();
            System.out.println(type);
            assertEquals(22, type);
            int majorVersion = in.read();
            System.out.println(majorVersion);
            assertEquals(3, majorVersion);
            int minorVersion = in.read();
            System.out.println(minorVersion);
            assertEquals(3, minorVersion);
            int length1 = in.read();
            System.out.println(length1);
            assertEquals(0, length1);
            int length2 = in.read();
            System.out.println(length2);
            assertEquals(55, length2);
            for (int i = 0; i < length2; i++) {
                System.out.print(in.read());
                System.out.print(' ');
            }
            System.out.println();
            System.out.println("Stop reading input stream.");
            // Certificate, Server Key Exchange, Server Hello Done
        } catch (IOException e) {
            fail(e);
        }
    }

    @Test void testServerHello() {
        try (Socket socket = new Socket("localhost", 443);
            OutputStream out = socket.getOutputStream();
            InputStream in = socket.getInputStream()) {

            ClientHello clientHello = new ClientHello();
            clientHello.writeTo(out);

            System.out.println();
            // Server Hello
            ServerHello serverHello = (ServerHello) TLSRecordFactory.readRecord(in).getHandshakeMessage();
            assertEquals(51, serverHello.length());
            assertEquals(32, serverHello.getRandom().length);
            System.out.println("Stop reading input stream.");
            // Certificate, Server Key Exchange, Server Hello Done
        } catch (IOException e) {
            fail(e);
        }
    }

    @Test void testCertificate() {
        try (Socket socket = new Socket("localhost", 443);
            OutputStream out = socket.getOutputStream();
            InputStream in = socket.getInputStream()) {

            ClientHello clientHello = new ClientHello();
            clientHello.writeTo(out);

            System.out.println();
            // Server Hello
            TLSRecordFactory.readRecord(in);
            // Certificate
            Certificate certificate = (Certificate) TLSRecordFactory.readRecord(in).getHandshakeMessage();
            X509Certificate c = certificate.getX509Certificate();
            assertNotNull(c);
            assertEquals("ST=Tokyo,C=JP", c.getIssuerX500Principal().getName());
            System.out.println("Stop reading input stream.");
            // Certificate, Server Key Exchange, Server Hello Done
        } catch (Exception e) {
            fail(e);
        }
    }

    @Test void testServerKeyExchange() {
        try (Socket socket = new Socket("localhost", 443);
            OutputStream out = socket.getOutputStream();
            InputStream in = socket.getInputStream()) {

            ClientHello clientHello = new ClientHello();
            clientHello.writeTo(out);

            System.out.println();
            // Server Hello
            TLSRecordFactory.readRecord(in);
            // Certificate
            TLSRecordFactory.readRecord(in);
            // ServerKeyExchange
            ServerKeyExchange ske = (ServerKeyExchange) TLSRecordFactory.readRecord(in).getHandshakeMessage();
            int hashAlgorithm = ske.getHashAlgorithm();
            assertEquals(4, hashAlgorithm); // SHA256
            int signatureAlgorithm = ske.getSignatureAlgorithm();
            assertEquals(3, signatureAlgorithm); // ECDSA
            System.out.println("Stop reading input stream.");
        } catch (Exception e) {
            fail(e);
        }
    }

    @Test void testServerHelloDone() {
        try (Socket socket = new Socket("localhost", 443);
            OutputStream out = socket.getOutputStream();
            InputStream in = socket.getInputStream()) {

            ClientHello clientHello = new ClientHello();
            clientHello.writeTo(out);

            System.out.println();
            // Server Hello
            TLSRecordFactory.readRecord(in);
            // Certificate
            TLSRecordFactory.readRecord(in);
            // ServerKeyExchange
            TLSRecordFactory.readRecord(in);
            // ServerHelloDone
            ServerHelloDone serverHelloDone = (ServerHelloDone) TLSRecordFactory.readRecord(in).getHandshakeMessage();
            assertEquals(0, serverHelloDone.length());
            System.out.println("Stop reading input stream.");
        } catch (Exception e) {
            fail(e);
        }
    }

    @Test void testClientKeyExchange() {
        try (Socket socket = new Socket("localhost", 443);
            OutputStream out = socket.getOutputStream();
            InputStream in = socket.getInputStream()) {

            ClientHello clientHello = new ClientHello();
            clientHello.writeTo(out);

            // Server Hello
            TLSRecordFactory.readRecord(in).getHandshakeMessage();
            // Certificate
            TLSRecordFactory.readRecord(in).getHandshakeMessage();
            // ServerKeyExchange
            ServerKeyExchange ske = (ServerKeyExchange) TLSRecordFactory.readRecord(in).getHandshakeMessage();
            int namedCurve = ske.getNamedCurve();
            // ServerHelloDone
            TLSRecordFactory.readRecord(in).getHandshakeMessage();

            // Calculate Client Key
            AlgorithmParameters params = AlgorithmParameters.getInstance("EC", Security.getProvider("SunEC"));
            params.init(new ECGenParameterSpec(NamedCurve.of(namedCurve)));
            ECParameterSpec ecParams = params.getParameterSpec(ECParameterSpec.class);

            KeyPairGenerator generator = KeyPairGenerator.getInstance("EC");
            generator.initialize(ecParams);
            KeyPair pair = generator.generateKeyPair();
            ClientKeyExchange cke = new ClientKeyExchange(pair.getPublic(), ecParams.getCurve());
            cke.writeTo(out);

            System.out.println("Stop reading input stream.");
        } catch (Exception e) {
            fail(e);
        }
    }

    @Test void testClientChangeCipherSpec() {
        try (Socket socket = new Socket("localhost", 443);
            OutputStream out = socket.getOutputStream();
            InputStream in = socket.getInputStream()) {

            ClientHello clientHello = new ClientHello();
            clientHello.writeTo(out);

            // Server Hello
            TLSRecordFactory.readRecord(in).getHandshakeMessage();
            // Certificate
            TLSRecordFactory.readRecord(in).getHandshakeMessage();
            // ServerKeyExchange
            TLSRecordFactory.readRecord(in).getHandshakeMessage();
            // ServerHelloDone
            TLSRecordFactory.readRecord(in).getHandshakeMessage();

            // Calculate Client Key
            AlgorithmParameters params = AlgorithmParameters.getInstance("EC", Security.getProvider("SunEC"));
            params.init(new ECGenParameterSpec("secp256r1")); // TODO: use namedCurve
            ECParameterSpec ecParams = params.getParameterSpec(ECParameterSpec.class);

            KeyPairGenerator generator = KeyPairGenerator.getInstance("EC");
            generator.initialize(new ECGenParameterSpec("secp256r1"));
            KeyPair pair = generator.generateKeyPair();

            ClientKeyExchange cke = new ClientKeyExchange(pair.getPublic(), ecParams.getCurve());
            cke.writeTo(out);

            ClientChangeCipherSpec cccs = new ClientChangeCipherSpec();
            cccs.writeTo(out);

            System.out.println("Stop reading input stream.");
        } catch (Exception e) {
            fail(e);
        }
    }

    @Test void testAlertBadRecordMac() {
        try (Socket socket = new Socket("localhost", 443);
            OutputStream out = socket.getOutputStream();
            InputStream in = socket.getInputStream()) {

            ClientHello clientHello = new ClientHello();
            clientHello.writeTo(out);

            int[] clientRandom = clientHello.getRandom();
            assertEquals(32, clientRandom.length);

            System.out.println();
            // Server Hello
            // Cipher Suite: TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256 (0xcca9)
            ServerHello sh = (ServerHello) TLSRecordFactory.readRecord(in).getHandshakeMessage();
            int[] serverRandom = sh.getRandom();
            // Certificate
            Certificate certificate = (Certificate) TLSRecordFactory.readRecord(in).getHandshakeMessage();
            // ServerKeyExchange
            ServerKeyExchange ske = (ServerKeyExchange) TLSRecordFactory.readRecord(in).getHandshakeMessage();
            int namedCurve = ske.getNamedCurve(); // 13+160=173=x25519
            int[] publicKey = ske.getPublicKey();
            // ServerHelloDone
            ServerHelloDone done = (ServerHelloDone) TLSRecordFactory.readRecord(in).getHandshakeMessage();

            // Calculate Client Key
            AlgorithmParameters params = AlgorithmParameters.getInstance("EC", Security.getProvider("SunEC"));
            params.init(new ECGenParameterSpec("secp256r1")); // TODO: use namedCurve
            ECParameterSpec ecParams = params.getParameterSpec(ECParameterSpec.class);

            KeyPairGenerator generator = KeyPairGenerator.getInstance("EC");
            generator.initialize(new ECGenParameterSpec("secp256r1"));
            KeyPair pair = generator.generateKeyPair();
            ECPrivateKey privateKey = (ECPrivateKey) pair.getPrivate();

            KeyFactory f = KeyFactory.getInstance("EC");
            ByteArrayOutputStream point = new ByteArrayOutputStream();
            for (int k : publicKey) point.write(k);
            byte[] data = point.toByteArray();
            int n = (data.length - 1) / 2;
            byte[] xb = Arrays.copyOfRange(data, 1, 1 + n);
            byte[] yb = Arrays.copyOfRange(data, 1 + n, n + 1 + n);
            ECPoint ecPoint = new ECPoint(new BigInteger(1, xb), new BigInteger(1, yb));
            ECPublicKeySpec spec = new ECPublicKeySpec(ecPoint, ecParams);
            PublicKey serverPubKey = f.generatePublic(spec);
            KeyAgreement ecdh = KeyAgreement.getInstance("ECDH");
            ecdh.init(privateKey);
            ecdh.doPhase(serverPubKey, true);
            byte[] preMasterSecret = ecdh.generateSecret();

            /**
             * seed = "master secret" + client_random + server_random
                a0 = seed
                a1 = HMAC-SHA256(key=PreMasterSecret, data=a0)
                a2 = HMAC-SHA256(key=PreMasterSecret, data=a1)
                p1 = HMAC-SHA256(key=PreMasterSecret, data=a1 + seed)
                p2 = HMAC-SHA256(key=PreMasterSecret, data=a2 + seed)
                MasterSecret = p1[all 32 bytes] + p2[first 16 bytes]
             */
            byte[] ms = "master secret".getBytes();
            int msLen = ms.length;

            byte[] seed = new byte[msLen + 32 + 32];
            System.arraycopy(ms, 0, seed, 0, msLen);
            ByteArrayOutputStream cr = new ByteArrayOutputStream();
            for (int i : clientRandom) cr.write(i);
            byte[] crarr = cr.toByteArray();
            System.arraycopy(crarr, 0, seed, msLen, 32);
            ByteArrayOutputStream sr = new ByteArrayOutputStream();
            for (int i : serverRandom) sr.write(i);
            byte[] srarr = sr.toByteArray();
            System.arraycopy(srarr, 0, seed, msLen + 32, 32);

            String algorithm = "HmacSHA256";
            SecretKeySpec pms = new SecretKeySpec(preMasterSecret, algorithm);
            Mac mac = Mac.getInstance(algorithm);
            mac.init(pms);

            byte[] a1 = mac.doFinal(seed);
            byte[] a2 = mac.doFinal(a1);
            byte[] data1 = new byte[seed.length + a1.length];
            System.arraycopy(seed, 0, data1, 0, seed.length);
            System.arraycopy(a1, 0, data1, seed.length, a1.length);
            byte[] data2 = new byte[seed.length + a2.length];
            System.arraycopy(seed, 0, data2, 0, seed.length);
            System.arraycopy(a2, 0, data2, seed.length, a2.length);
            byte[] p1 = mac.doFinal(data1);
            byte[] p2 = mac.doFinal(data2);
            byte[] masterSecret = new byte[48];
            System.arraycopy(p1, 0, masterSecret, 0, 32);
            System.arraycopy(p2, 0, masterSecret, 32, 16);

            SecretKeySpec master_secret = new SecretKeySpec(masterSecret, algorithm);
            // generate final encryption keys
            // seed = "key expansion" + server_random + client_random
            byte[] ke = "key expansion".getBytes();
            int keLen = ke.length;
            byte[] keySeed = new byte[keLen + 32 + 32];
            System.arraycopy(ke, 0, keySeed, 0, keLen);
            System.arraycopy(crarr, 0, keySeed, keLen, 32);
            System.arraycopy(srarr, 0, keySeed, keLen + 32, 32);

            mac.reset();
            mac.init(master_secret);
            // a0 = seed
            byte[] ke_a0 = keySeed;
            // a1 = HMAC-SHA256(key=MasterSecret, data=a0)
            byte[] ke_a1 = mac.doFinal(ke_a0);
            // a2 = HMAC-SHA256(key=MasterSecret, data=a1)
            byte[] ke_a2 = mac.doFinal(ke_a1);
            // a3 = HMAC-SHA256(key=MasterSecret, data=a2)
            byte[] ke_a3 = mac.doFinal(ke_a2);
            // a4 = ...
            byte[] ke_a4 = mac.doFinal(ke_a3);
            // p1 = HMAC-SHA256(key=MasterSecret, data=a1 + seed)
            byte[] ke_data1 = new byte[ke_a1.length + keLen];
            System.arraycopy(ke_a1, 0, ke_data1, 0, ke_a1.length);
            System.arraycopy(keySeed, 0, ke_data1, ke_a1.length, keLen);
            byte[] ke_p1 = mac.doFinal(ke_data1);
            // p2 = HMAC-SHA256(key=MasterSecret, data=a2 + seed)
            byte[] ke_data2 = new byte[ke_a2.length + keLen];
            System.arraycopy(ke_a2, 0, ke_data2, 0, ke_a2.length);
            System.arraycopy(keySeed, 0, ke_data2, ke_a2.length, keLen);
            byte[] ke_p2 = mac.doFinal(ke_data2);
            // p3 = HMAC-SHA256(key=MasterSecret, data=a3 + seed)
            byte[] ke_data3 = new byte[ke_a3.length + keLen];
            System.arraycopy(ke_a3, 0, ke_data3, 0, ke_a3.length);
            System.arraycopy(keySeed, 0, ke_data3, ke_a3.length, keLen);
            byte[] ke_p3 = mac.doFinal(ke_data3);
            // p4 = ...
            byte[] ke_data4 = new byte[ke_a4.length + keLen];
            System.arraycopy(ke_a4, 0, ke_data4, 0, ke_a4.length);
            System.arraycopy(keySeed, 0, ke_data4, ke_a4.length, keLen);
            byte[] ke_p4 = mac.doFinal(ke_data4);
            // p = p1 + p2 + p3 + p4 ...
            byte[] p = new byte[ke_p1.length + ke_p2.length + ke_p3.length + ke_p4.length];
            System.arraycopy(ke_p1, 0, p, 0, ke_p1.length);
            System.arraycopy(ke_p2, 0, p, ke_p1.length, ke_p2.length);
            System.arraycopy(ke_p3, 0, p, ke_p1.length + ke_p2.length, ke_p3.length);
            System.arraycopy(ke_p4, 0, p, ke_p1.length + ke_p2.length + ke_p3.length, ke_p4.length);
            // client write mac key = [first 20 bytes of p]
            byte[] clientWriteMacKey = new byte[20];
            System.arraycopy(p, 0, clientWriteMacKey, 0, 20);
            // server write mac key = [next 20 bytes of p]
            byte[] serverWriteMacKey = new byte[20];
            System.arraycopy(p, 20, serverWriteMacKey, 0, 20);
            // client write key = [next 16 bytes of p]
            byte[] clientWriteKey = new byte[16];
            System.arraycopy(p, 20 + 16, clientWriteKey, 0, 16);
            // server write key = [next 16 bytes of p]
            byte[] serverWriteKey = new byte[16];
            System.arraycopy(p, 20 + 16 + 16, serverWriteKey, 0, 16);
            // client write IV = [next 16 bytes of p]
            byte[] clientWriteIV = Arrays.copyOfRange(p, 20 + 16 + 16 + 16, 20 + 16 + 16 + 16 + 16);
            // server write IV = [next 16 bytes of p]
            byte[] serverWriteIV = new byte[16];
            System.arraycopy(p, 20 + 16 + 16 + 16 + 16, serverWriteIV, 0, 16);
            ClientKeyExchange cke = new ClientKeyExchange(pair.getPublic(), ecParams.getCurve());
            cke.writeTo(out);

            ClientChangeCipherSpec cccs = new ClientChangeCipherSpec();
            cccs.writeTo(out);

            ClientFinished cf = new ClientFinished(
                clientWriteIV,
                master_secret,
                clientWriteKey,
                clientWriteMacKey,
                clientHello,
                sh,
                certificate,
                ske,
                done,
                cke
            );
            cf.writeTo(out);

            Alert alert = (Alert) TLSRecordFactory.readRecord(in).getAlert();
            assertNotNull(alert);
            // fatal
            assertEquals(2, alert.getLevel());
            // bad record mac
            assertEquals(20, alert.getDescription());
            System.out.println("Stop reading input stream.");
        } catch (Exception e) {
            fail(e);
        }
    }

    @Test void testClientFinished() {
        try (Socket socket = new Socket("localhost", 443);
            OutputStream out = socket.getOutputStream();
            InputStream in = socket.getInputStream()) {

            ClientHello clientHello = new ClientHello();
            clientHello.writeTo(out);

            int[] clientRandom = clientHello.getRandom();
            assertEquals(32, clientRandom.length);

            System.out.println();
            // Server Hello
            // Cipher Suite: TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256 (0xcca9)
            ServerHello sh = (ServerHello) TLSRecordFactory.readRecord(in).getHandshakeMessage();
            int[] serverRandom = sh.getRandom();
            // Certificate
            Certificate certificate = (Certificate) TLSRecordFactory.readRecord(in).getHandshakeMessage();
            // ServerKeyExchange
            ServerKeyExchange ske = (ServerKeyExchange) TLSRecordFactory.readRecord(in).getHandshakeMessage();
            int namedCurve = ske.getNamedCurve(); // 13+160=173=x25519
            int[] publicKey = ske.getPublicKey();
            // ServerHelloDone
            ServerHelloDone done = (ServerHelloDone) TLSRecordFactory.readRecord(in).getHandshakeMessage();

            // Calculate Client Key
            ECGenParameterSpec ecSpec = new ECGenParameterSpec(NamedCurve.of(namedCurve));
            AlgorithmParameters params = AlgorithmParameters.getInstance("EC", Security.getProvider("SunEC"));
            params.init(ecSpec);
            ECParameterSpec ecParams = params.getParameterSpec(ECParameterSpec.class);

            KeyPairGenerator generator = KeyPairGenerator.getInstance("EC");
            generator.initialize(ecSpec);
            KeyPair pair = generator.generateKeyPair();
            ECPrivateKey privateKey = (ECPrivateKey) pair.getPrivate();

            KeyFactory f = KeyFactory.getInstance("EC");
            ByteArrayOutputStream point = new ByteArrayOutputStream();
            for (int k : publicKey) point.write(k);
            byte[] data = point.toByteArray();
            int n = (data.length - 1) / 2;
            byte[] xb = Arrays.copyOfRange(data, 1, 1 + n);
            byte[] yb = Arrays.copyOfRange(data, 1 + n, n + 1 + n);
            ECPoint ecPoint = new ECPoint(new BigInteger(1, xb), new BigInteger(1, yb));
            ECPublicKeySpec spec = new ECPublicKeySpec(ecPoint, ecParams);
            PublicKey serverPubKey = f.generatePublic(spec);
            KeyAgreement ecdh = KeyAgreement.getInstance("ECDH");
            ecdh.init(privateKey);
            ecdh.doPhase(serverPubKey, true);
            byte[] preMasterSecret = ecdh.generateSecret();

            /**
             * seed = "master secret" + client_random + server_random
                a0 = seed
                a1 = HMAC-SHA256(key=PreMasterSecret, data=a0)
                a2 = HMAC-SHA256(key=PreMasterSecret, data=a1)
                p1 = HMAC-SHA256(key=PreMasterSecret, data=a1 + seed)
                p2 = HMAC-SHA256(key=PreMasterSecret, data=a2 + seed)
                MasterSecret = p1[all 32 bytes] + p2[first 16 bytes]
             */
            byte[] ms = "master secret".getBytes();
            int msLen = ms.length;

            byte[] seed = new byte[msLen + 32 + 32];
            System.arraycopy(ms, 0, seed, 0, msLen);
            ByteArrayOutputStream cr = new ByteArrayOutputStream();
            for (int i : clientRandom) cr.write(i);
            byte[] crarr = cr.toByteArray();
            System.arraycopy(crarr, 0, seed, msLen, 32);
            ByteArrayOutputStream sr = new ByteArrayOutputStream();
            for (int i : serverRandom) sr.write(i);
            byte[] srarr = sr.toByteArray();
            System.arraycopy(srarr, 0, seed, msLen + 32, 32);

            String algorithm = "HmacSHA256";
            SecretKeySpec pms = new SecretKeySpec(preMasterSecret, algorithm);
            Mac mac = Mac.getInstance(algorithm);
            mac.init(pms);

            byte[] a1 = mac.doFinal(seed);
            byte[] a2 = mac.doFinal(a1);
            byte[] data1 = new byte[seed.length + a1.length];
            System.arraycopy(seed, 0, data1, 0, seed.length);
            System.arraycopy(a1, 0, data1, seed.length, a1.length);
            byte[] data2 = new byte[seed.length + a2.length];
            System.arraycopy(seed, 0, data2, 0, seed.length);
            System.arraycopy(a2, 0, data2, seed.length, a2.length);
            byte[] p1 = mac.doFinal(data1);
            byte[] p2 = mac.doFinal(data2);
            byte[] masterSecret = new byte[48];
            System.arraycopy(p1, 0, masterSecret, 0, 32);
            System.arraycopy(p2, 0, masterSecret, 32, 16);

            SecretKeySpec master_secret = new SecretKeySpec(masterSecret, algorithm);
            // generate final encryption keys
            // seed = "key expansion" + server_random + client_random
            byte[] ke = "key expansion".getBytes();
            int keLen = ke.length;
            byte[] keySeed = new byte[keLen + 32 + 32];
            System.arraycopy(ke, 0, keySeed, 0, keLen);
            System.arraycopy(crarr, 0, keySeed, keLen, 32);
            System.arraycopy(srarr, 0, keySeed, keLen + 32, 32);

            mac.reset();
            mac.init(master_secret);
            // a0 = seed
            byte[] ke_a0 = keySeed;
            // a1 = HMAC-SHA256(key=MasterSecret, data=a0)
            byte[] ke_a1 = mac.doFinal(ke_a0);
            // a2 = HMAC-SHA256(key=MasterSecret, data=a1)
            byte[] ke_a2 = mac.doFinal(ke_a1);
            // a3 = HMAC-SHA256(key=MasterSecret, data=a2)
            byte[] ke_a3 = mac.doFinal(ke_a2);
            // a4 = ...
            byte[] ke_a4 = mac.doFinal(ke_a3);
            // p1 = HMAC-SHA256(key=MasterSecret, data=a1 + seed)
            byte[] ke_data1 = new byte[ke_a1.length + keLen];
            System.arraycopy(ke_a1, 0, ke_data1, 0, ke_a1.length);
            System.arraycopy(keySeed, 0, ke_data1, ke_a1.length, keLen);
            byte[] ke_p1 = mac.doFinal(ke_data1);
            // p2 = HMAC-SHA256(key=MasterSecret, data=a2 + seed)
            byte[] ke_data2 = new byte[ke_a2.length + keLen];
            System.arraycopy(ke_a2, 0, ke_data2, 0, ke_a2.length);
            System.arraycopy(keySeed, 0, ke_data2, ke_a2.length, keLen);
            byte[] ke_p2 = mac.doFinal(ke_data2);
            // p3 = HMAC-SHA256(key=MasterSecret, data=a3 + seed)
            byte[] ke_data3 = new byte[ke_a3.length + keLen];
            System.arraycopy(ke_a3, 0, ke_data3, 0, ke_a3.length);
            System.arraycopy(keySeed, 0, ke_data3, ke_a3.length, keLen);
            byte[] ke_p3 = mac.doFinal(ke_data3);
            // p4 = ...
            byte[] ke_data4 = new byte[ke_a4.length + keLen];
            System.arraycopy(ke_a4, 0, ke_data4, 0, ke_a4.length);
            System.arraycopy(keySeed, 0, ke_data4, ke_a4.length, keLen);
            byte[] ke_p4 = mac.doFinal(ke_data4);
            // p = p1 + p2 + p3 + p4 ...
            byte[] p = new byte[ke_p1.length + ke_p2.length + ke_p3.length + ke_p4.length];
            System.arraycopy(ke_p1, 0, p, 0, ke_p1.length);
            System.arraycopy(ke_p2, 0, p, ke_p1.length, ke_p2.length);
            System.arraycopy(ke_p3, 0, p, ke_p1.length + ke_p2.length, ke_p3.length);
            System.arraycopy(ke_p4, 0, p, ke_p1.length + ke_p2.length + ke_p3.length, ke_p4.length);
            // client write mac key = [first 20 bytes of p]
            byte[] clientWriteMacKey = new byte[20];
            System.arraycopy(p, 0, clientWriteMacKey, 0, 20);
            // server write mac key = [next 20 bytes of p]
            byte[] serverWriteMacKey = new byte[20];
            System.arraycopy(p, 20, serverWriteMacKey, 0, 20);
            // client write key = [next 16 bytes of p]
            byte[] clientWriteKey = new byte[16];
            System.arraycopy(p, 20 + 16, clientWriteKey, 0, 16);
            // server write key = [next 16 bytes of p]
            byte[] serverWriteKey = new byte[16];
            System.arraycopy(p, 20 + 16 + 16, serverWriteKey, 0, 16);
            // client write IV = [next 16 bytes of p]
            byte[] clientWriteIV = Arrays.copyOfRange(p, 20 + 16 + 16 + 16, 20 + 16 + 16 + 16 + 16);
            // server write IV = [next 16 bytes of p]
            byte[] serverWriteIV = new byte[16];
            System.arraycopy(p, 20 + 16 + 16 + 16 + 16, serverWriteIV, 0, 16);
            ClientKeyExchange cke = new ClientKeyExchange(pair.getPublic(), ecParams.getCurve());
            cke.writeTo(out);

            ClientChangeCipherSpec cccs = new ClientChangeCipherSpec();
            cccs.writeTo(out);

            ClientFinished cf = new ClientFinished(
                clientWriteIV,
                master_secret,
                clientWriteKey,
                clientWriteMacKey,
                clientHello,
                sh,
                certificate,
                ske,
                done,
                cke
            );
            cf.writeTo(out);

            ServerChangeCipherSpec sccc = (ServerChangeCipherSpec) TLSRecordFactory.readRecord(in).getHandshakeMessage();
            assertNotNull(sccc);
            System.out.println("Stop reading input stream.");
        } catch (Exception e) {
            fail(e);
        }
    }
}
