package com.kdnakt.tls;

import java.util.Arrays;

public class ServerKeyExchange implements HandshakeMessage {

    private int curveType;
    private int namedCurve;
    private int[] pubKey;
    private int hashAlgorithm;
    private int signatureAlgorithm;
    private int[] signature;

    public ServerKeyExchange(int[] message) {
        int i = 0;
        curveType = message[i++];
        namedCurve = (message[i++] << 8) + message[i++];
        int pubKeyLen = message[i++];
        pubKey = Arrays.copyOfRange(message, i, i + pubKeyLen);
        i += pubKeyLen;
        hashAlgorithm = message[i++];
        signatureAlgorithm = message[i++];
        int sigLen = (message[i++] << 8) + message[i++];
        signature = Arrays.copyOfRange(message, i, i + sigLen);
    }

    public int[] getPublicKey() {
        return pubKey;
    }

    public int getHashAlgorithm() {
        return hashAlgorithm;
    }

    public int getSignatureAlgorithm() {
        return signatureAlgorithm;
    }

    public int getNamedCurve() {
        return namedCurve;
    }

}
