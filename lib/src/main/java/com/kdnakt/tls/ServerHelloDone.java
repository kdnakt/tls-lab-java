package com.kdnakt.tls;

public class ServerHelloDone implements HandshakeMessage {

    private int length;

    public ServerHelloDone(int length) {
        this.length = length;
    }

    public int length() {
        return length;
    }

    @Override
    public int[] getMessage() {
        int[] message = new int[4];
        message[0] = 14; // type
        // length is 0
        return message;
    }

    @Override
    public int getType() {
        return 14;
    }

}
