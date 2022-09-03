package com.kdnakt.tls;

public class ServerHello implements HandshakeMessage {

    private int[] message;

    public ServerHello(int[] message) {
        this.message = message;
    }

    public int length() {
        return message.length;
    }
    public int[] getMessage() {
        return message;
    }
}
