package com.kdnakt.tls;

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
        pubKey = new int[pubKeyLen];
        System.arraycopy(message, i, pubKey, 0, pubKeyLen);
        i += pubKeyLen;
        hashAlgorithm = message[i++];
        signatureAlgorithm = message[i++];
        int sigLen = (message[i++] << 8) + message[i++];
        signature = new int[sigLen];
        System.arraycopy(message, i, signature, 0, sigLen);
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

}
