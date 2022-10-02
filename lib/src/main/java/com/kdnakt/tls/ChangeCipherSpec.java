package com.kdnakt.tls;

public class ChangeCipherSpec {

    public static ChangeCipherSpec valueOf(int[] message) {
        if (message == null || message.length != 1 || message[0] != 1) {
            throw new IllegalArgumentException("ChangeCipherSpec payload should be 0x01");
        }
        return new ServerChangeCipherSpec();
    }

    public int[] getMessage() {
        int[] res = {0x01};
        return res;
    }

}
