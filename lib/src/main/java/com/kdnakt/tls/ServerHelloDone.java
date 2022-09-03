package com.kdnakt.tls;

public class ServerHelloDone implements HandshakeMessage {

    private int length;

    public ServerHelloDone(int length) {
        this.length = length;
    }

    public int length() {
        return length;
    }

}
