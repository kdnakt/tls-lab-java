package com.kdnakt.tls;

public class ServerHello {

    private int length;

    public ServerHello(int length) {
        this.length = length;
    }

    public int length() {
        return length;
    }

}
