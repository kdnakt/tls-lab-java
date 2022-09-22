package com.kdnakt.tls;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.OutputStream;

public class ClientChangeCipherSpec implements HandshakeMessage {

    public void writeTo(OutputStream out) throws IOException {
        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        for (int b : getMessage()) {
            baos.write(b);
        }
        out.write(baos.toByteArray());
    }

    @Override
    public int[] getMessage() {
        int[] message = {
            0x14,
            0x03,
            0x03,
            0x00,
            0x01,
            0x01,
        };
        return message;
    }

}
