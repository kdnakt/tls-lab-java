package com.kdnakt.tls;

import java.util.Arrays;

public class ServerKeyExchange implements HandshakeMessage {

    private int[] message;
    private int curveType;
    private int namedCurve;
    private int[] pubKey;
    private HashAlgorithm hashAlgorithm;
    private SignatureAlgorithm signatureAlgorithm;
    private int[] signature;

    public ServerKeyExchange(int[] message) {
        this.message = message;
        int i = 0;
        curveType = message[i++];
        namedCurve = (message[i++] << 8) + message[i++];
        int pubKeyLen = message[i++];
        pubKey = Arrays.copyOfRange(message, i, i + pubKeyLen);
        i += pubKeyLen;
        hashAlgorithm = HashAlgorithm.valueOf(message[i++]);
        signatureAlgorithm = SignatureAlgorithm.valueOf(message[i++]);
        int sigLen = (message[i++] << 8) + message[i++];
        signature = Arrays.copyOfRange(message, i, i + sigLen);
    }

    public int[] getPublicKey() {
        return pubKey;
    }

    public int getHashAlgorithm() {
        return hashAlgorithm.getId();
    }

    public int getSignatureAlgorithm() {
        return signatureAlgorithm.getId();
    }

    public int getNamedCurve() {
        return namedCurve;
    }

    @Override
    public int[] getMessage() {
        return message;
    }

    @Override
    public int getType() {
        return 12;
    }

}
