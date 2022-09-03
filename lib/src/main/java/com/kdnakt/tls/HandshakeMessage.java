package com.kdnakt.tls;

public interface HandshakeMessage {

    static HandshakeMessage valueOf(byte[] bytes) {
        int type = bytes[0];
        int len1 = bytes[1];
        int len2 = bytes[2];
        int len3 = bytes[3];
        int length = (len1 << 16) + (len2 << 8) + len3;
        byte[] message = new byte[length];
        System.arraycopy(bytes, 4, message, 0, length);
        switch (type) {
            case 2:
                return new ServerHello(message);
            case 11:
                return new Certificate(message);
            default:
                throw new RuntimeException("Unknown Handshake Message type: " + type);
        }
    }

}
