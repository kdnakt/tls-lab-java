package com.kdnakt.tls;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.OutputStream;

public class ClientHello implements HandshakeMessage {

    private int[] random = {
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
        0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f,
    };
    public int[] getRecordHeader() {
        return new int[]{
            // Record header
            0x16, // type handshake
            0x03, 0x01, // protocol version TLS1.0(3.1)
            // 0x00, 0xa5, // 165 bytes follows
            // 0x00, 0x9b, // 155 bytes follows
        };
    }

    @Override
    public int[] getMessage() {
        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        // example from https://tls12.xargs.org/
        final int[] clientHello = {
            // // Handshake header
            // 0x01, // type ClientHello
            // // 0x00, 0x00, 0xa1, // 161 bytes follows
            // 0x00, 0x00, 0x97, // 151 bytes follows

            // ClientHello
            // Client version
            0x03, 0x03, // TLS1.2 (3.3)
            // Client random
            0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
            0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f,
            // Session id
            0x00,
            // Cipher Suites
            0x00, 0x20, // 32 bytes follows
            0xc0, 0x2f, // TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256
            0xc0, 0x2b, // TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256
            0xcc, 0xa8, // TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256
            0xcc, 0xa9, // TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256
            0xc0, 0x30, // TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384
            0xc0, 0x2c, // TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384
            0xc0, 0x13, // TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA
            0xc0, 0x09, // TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA
            0xc0, 0x14, // TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA
            0xc0, 0x0a, // TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA
            0x00, 0x9c, // TLS_RSA_WITH_AES_128_GCM_SHA256
            0x00, 0x9d, // TLS_RSA_WITH_AES_256_GCM_SHA384
            0x00, 0x2f, // TLS_RSA_WITH_AES_128_CBC_SHA
            0x00, 0x35, // TLS_RSA_WITH_AES_256_CBC_SHA
            0xc0, 0x12, // TLS_ECDHE_RSA_WITH_3DES_EDE_CBC_SHA
            0x00, 0x0a, // TLS_RSA_WITH_3DES_EDE_CBC_SHA
            // Compression method
            0x01, 0x00,
            // Extensions length
            // 0x00, 0x58, // 88
            0x00, 0x4e, // 78
            // Extension
                // server_name
                0x00, 0x00, // server name
                // 0x00, 0x18, // 24 bytes follows
                0x00, 0x0e, // 14 bytes follows
                // 0x00, 0x16, // 22 bytes follows
                0x00, 0x0c, // 12 bytes
                0x00, // type dns hostname
                // 0x00, 0x13, // hostname 19 bytes follows
                // 0x65, 0x78, 0x61, 0x6d, 0x70, 0x6c, 0x65, 0x2e, 0x75, 0x6c, // example.ul
                // 0x66, 0x68, 0x65, 0x69, 0x6d, 0x2e, 0x6e, 0x65, 0x74,       // fheim.net

                0x00, 0x09, // hostname 9 bytes follows
                0x6c, // l
                0x6f, // o
                0x63, // c
                0x61, // a
                0x6c, // l
                0x68, // h
                0x6f, // o
                0x73, // s
                0x74, // t

                // status_request
                0x00, 0x05, // status request
                0x00, 0x05, // 5 bytes follows
                0x01, // type ocsp
                0x00, 0x00, // 0 bytes of responder id follows
                0x00, 0x00, // 0 bytes of request extension information
                // supported_groups
                0x00, 0x0a, // supported groups
                0x00, 0x0a, // 10 bytes follows
                0x00, 0x08, // 8 bytes follows
                0x00, 0x17, // curve secp256r1
                0x00, 0x18, // curve secp384r1
                0x00, 0x19, // curve secp521r1
                0x00, 0x1d, // curve x25519
                // ec_point_formats
                0x00, 0x0b, // ec point formats
                0x00, 0x02, // 2 bytes follows
                0x01, // 1 byte follows
                0x00, // uncompressed form
                // signature_algorithms
                0x00, 0x0d, // signature algorithms
                0x00, 0x12, // 18 bytes follows
                0x00, 0x10, // 16 bytes follows
                0x04, 0x01, // RSA/PKCS1/SHA256
                0x04, 0x03, // ECDSA/SECP256r1/SHA256
                0x05, 0x01, // RSA/PKCS1/SHA384
                0x05, 0x03, // ECDSA/SECP384r1/SHA384
                0x06, 0x01, // RSA/PKCS1/SHA512
                0x06, 0x03, // ECDSA/SECP521r1/SHA512
                0x02, 0x01, // RSA/PKCS1/SHA1
                0x02, 0x03, // ECDSA/SHA1
                // renegotiation_info
                0xff, 0x01, // renegotiation info
                0x00, 0x01, // 1 byte follows
                0x00, // length 0
                // sct
                0x00, 0x12, // signed certificate timestamp
                0x00, 0x00 // 0 byte follows
        };
        return clientHello;
    }

    public void writeTo(final OutputStream out) throws IOException {
        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        System.out.println("\n---Request---\n");
        int[] recordHeader = getRecordHeader();
        for (int r : recordHeader) {
            baos.write(r);
            System.out.print(r);
            System.out.print(' ');
        }
        int[] message = getMessage();
        int len1 = (message.length + 4) >> 8;
        baos.write(len1);
        System.out.print(len1);
        System.out.print(' ');
        int len2 = message.length + 4;
        baos.write(len2);
        System.out.print(len2);
        System.out.print(' ');

        // handshake message
        int type = 0x01;
        baos.write(type); // type client hello
        System.out.print(type);
        System.out.print(' ');
        int handLen = message.length;
        int hLen1 = handLen >> 16;
        int hLen2 = handLen >> 8;
        int hLen3 = handLen;
        baos.write(hLen1);
        System.out.print(hLen1);
        System.out.print(' ');
        baos.write(hLen2);
        System.out.print(hLen2);
        System.out.print(' ');
        baos.write(hLen3);
        System.out.print(hLen3);
        System.out.print(' ');

        for (int i : message) {
            baos.write(i);
            System.out.print(i);
            System.out.print(' ');
        }
        baos.writeTo(out);
        System.out.println();
    }

    public int[] getRandom() {
        return random;
    }
}
