package com.kdnakt.tls;

import java.util.Arrays;

public interface HandshakeMessage {

    static HandshakeMessage valueOf(int[] bytes) {
        int type = bytes[0];
        int len1 = bytes[1];
        int len2 = bytes[2];
        int len3 = bytes[3];
        int length = (len1 << 16) + (len2 << 8) + len3;
        int[] message = Arrays.copyOfRange(bytes, 4, 4 + length);
        switch (type) {
            case 2:
                return new ServerHello(message);
            case 11:
                return new Certificate(message);
            case 12:
                return new ServerKeyExchange(message);
            case 14:
                return new ServerHelloDone(length);
            default:
                throw new RuntimeException("Unknown Handshake Message type: " + type);
        }
    }

    int getType();

    default int[] getMessage() {
        int[] body = getMessageBody();
        int[] message = new int[body.length + 4];
        message[0] = getType();
        message[1] = body.length >> 16;
        message[2] = body.length >> 8;
        message[3] = body.length;
        System.arraycopy(body, 0, message, 4, body.length);
        return message;
    }

    int[] getMessageBody();

}
