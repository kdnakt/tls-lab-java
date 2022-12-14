package com.kdnakt.tls;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

public class ServerHello implements HandshakeMessage {

    private int[] message;
    private int majorVersion;
    private int minorVersion;
    private int[] random;
    private int sessionIdLen;
    private CipherSuite cipherSuite;
    private int compressionMethod;
    private int extLen;
    private List<TLSExtension> extensions = new ArrayList<>();

    public ServerHello(int[] message) {
        this.message = message;
        int i = 0;
        majorVersion = message[i++];
        minorVersion = message[i++];
        random = Arrays.copyOfRange(message, i, i + 32);
        i += 32;
        sessionIdLen = message[i++];
        // Cipher Suite: TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256 (0xc0 0x2b)
        cipherSuite = CipherSuite.valueOf((message[i++] << 8) + message[i++]);
        compressionMethod = message[i++];
        extLen = (message[i++] << 8) + message[i++];
        for (int j = i; j < i + extLen;) {
            int type = (message[j++] << 8) + message[j++];
            int len = (message[j++] << 8) + message[j++];
            int[] extensionData = Arrays.copyOfRange(message, i, i + len);
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
    public int[] getMessageBody() {
        return message;
    }

    @Override
    public int getType() {
        return 2;
    }
}
