package com.kdnakt.tls;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.fail;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.Socket;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PublicKey;
import java.security.cert.X509Certificate;
import java.security.interfaces.ECPrivateKey;
import java.security.spec.KeySpec;
import java.security.spec.X509EncodedKeySpec;

import javax.crypto.KeyAgreement;
import javax.crypto.Mac;
import javax.crypto.SecretKey;
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
            ServerHello serverHello = (ServerHello) TLSRecordFactory.readRecord(in);
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
            Certificate certificate = (Certificate) TLSRecordFactory.readRecord(in);
            X509Certificate c = certificate.getX509Certificate();
            assertNotNull(c);
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
            ServerKeyExchange ske = (ServerKeyExchange) TLSRecordFactory.readRecord(in);
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
            ServerHelloDone serverHelloDone = (ServerHelloDone) TLSRecordFactory.readRecord(in);
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

            int[] clientRandom = clientHello.getRandom();
            assertEquals(32, clientRandom.length);

            System.out.println();
            // Server Hello
            // Cipher Suite: TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256 (0xcca9)
            ServerHello sh = (ServerHello) TLSRecordFactory.readRecord(in);
            int[] serverRandom = sh.getRandom();
            // Certificate
            Certificate certificate = (Certificate) TLSRecordFactory.readRecord(in);
            // ServerKeyExchange
            ServerKeyExchange ske = (ServerKeyExchange) TLSRecordFactory.readRecord(in);
            int namedCurve = ske.getNamedCurve(); // 13+160=173=x25519
            int[] publicKey = ske.getPublicKey();
            // ServerHelloDone
            ServerHelloDone done = (ServerHelloDone) TLSRecordFactory.readRecord(in);

            // Calculate Client Key
            KeyPairGenerator generator = KeyPairGenerator.getInstance("EC");
            generator.initialize(256);
            KeyPair pair = generator.genKeyPair();
            ECPrivateKey privateKey = (ECPrivateKey) pair.getPrivate();
            KeyFactory f = KeyFactory.getInstance("EC");
            ByteArrayOutputStream encodedKey = new ByteArrayOutputStream();
            for (int k : publicKey) encodedKey.write(k);
            X509EncodedKeySpec spec = new X509EncodedKeySpec(encodedKey.toByteArray());
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
            System.arraycopy(cr.toByteArray(), 0, seed, msLen, 32);
            ByteArrayOutputStream sr = new ByteArrayOutputStream();
            for (int i : serverRandom) sr.write(i);
            System.arraycopy(sr.toByteArray(), 0, seed, msLen + 32, 32);

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

            ClientKeyExchange cke = new ClientKeyExchange(pair.getPublic());
            cke.writeTo(out);

            ClientChangeCipherSpec cccs = new ClientChangeCipherSpec();
            cccs.writeTo(out);

            ClientFinished cf = new ClientFinished(
                clientHello,
                sh,
                certificate,
                ske,
                done,
                cke,
                cccs
            );
            cf.writeTo(out);
            System.out.println("Stop reading input stream.");
        } catch (Exception e) {
            fail(e);
        }
    }
}
