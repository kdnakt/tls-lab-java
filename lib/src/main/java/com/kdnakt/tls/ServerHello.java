package com.kdnakt.tls;

public class ServerHello {

    private int length;
    private byte[] message;

    public ServerHello(int length, byte[] message) {
        this.length = length;
        this.message = message;
    }

    public int length() {
        return length;
    }
    public byte[] getMessage() {
        return message;
    }
}
