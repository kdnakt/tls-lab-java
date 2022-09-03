package com.kdnakt.tls;

import java.security.cert.X509Certificate;

public class Certificate implements HandshakeMessage {

    private byte[] message;

    public Certificate(byte[] message) {
        this.message = message;
    }

    public X509Certificate getX509Certificate() {
        return null;
    }

}
