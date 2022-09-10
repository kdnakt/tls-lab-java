package com.kdnakt.tls;

import java.io.IOException;
import java.io.OutputStream;

public class ClientChangeCipherSpec implements HandshakeMessage {

    public void writeTo(OutputStream out) throws IOException {
        byte[] message = {
            0x14,
            0x03,
            0x03,
            0x00,
            0x01,
            0x01,
        };
        out.write(message);
    }

}
