package com.kdnakt.tls;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.fail;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.Socket;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;

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
}
