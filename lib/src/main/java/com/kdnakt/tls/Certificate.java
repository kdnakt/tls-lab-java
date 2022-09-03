package com.kdnakt.tls;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.InputStream;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;

public class Certificate implements HandshakeMessage {

    private int[] message;
    private X509Certificate cert;

    public Certificate(int[] message) {
        this.message = message;
    }

    public X509Certificate getX509Certificate() throws CertificateException {
        if (cert == null) {
            int len1 = message[0] << 16;
            int len2 = message[1] << 8;
            int len3 = message[2];
            int certificatesLength = len1 + len2 + len3;
            int clen1 = message[3] << 16;
            int clen2 = message[4] << 8;
            int clen3 = message[5];
            int certificateLength = clen1 + clen2 + clen3;
            ByteArrayOutputStream baos = new ByteArrayOutputStream();
            for (int i = 6; i < certificateLength + 6; i++) {
                baos.write(message[i]);
            }
            InputStream in = new ByteArrayInputStream(baos.toByteArray());
            CertificateFactory f = CertificateFactory.getInstance("X.509");
            cert = (X509Certificate) f.generateCertificate(in);
        }
        // TODO: generate multiple certificates
        return cert;
    }

}
