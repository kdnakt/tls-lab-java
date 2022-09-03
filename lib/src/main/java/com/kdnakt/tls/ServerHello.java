package com.kdnakt.tls;

public class ServerHello implements HandshakeMessage {

    private byte[] message;

    public ServerHello(byte[] message) {
        this.message = message;
    }

    public int length() {
        return message.length;
    }
    public byte[] getMessage() {
        return message;
    }
}
