package com.kdnakt.tls;

import java.util.ArrayList;
import java.util.List;

public class ServerHello implements HandshakeMessage {

    private int[] message;
    private int majorVersion;
    private int minorVersion;
    private int[] random = new int[32];
    private int sessionIdLen;
    private int cipherSuite;
    private int compressionMethod;
    private int extLen;
    private List<TLSExtension> extensions = new ArrayList<>();

    public ServerHello(int[] message) {
        this.message = message;
        int i = 0;
        majorVersion = message[i++];
        minorVersion = message[i++];
        System.arraycopy(message, i, random, 0, 32);
        i += 32;
        sessionIdLen = message[i++];
        cipherSuite = (message[i++] << 8) + message[i++];
        compressionMethod = message[i++];
        extLen = (message[i++] << 8) + message[i++];
        for (int j = i; j < i + extLen;) {
            int type = (message[j++] << 8) + message[j++];
            int len = (message[j++] << 8) + message[j++];
            int[] extensionData = new int[len];
            System.arraycopy(message, i, extensionData, 0, len);
            j += len;
            extensions.add(TLSExtension.valueOf(type, extensionData));
        }
    }

    public int[] getRandom() {
        return random;
    }
    public int length() {
        return message.length;
    }
    public int[] getMessage() {
        return message;
    }
}
