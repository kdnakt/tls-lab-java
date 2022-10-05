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
    public int[] getMessageBody() {
        int[] message = new int[0];
        return message;
    }

    @Override
    public int getType() {
        return 14;
    }

}
