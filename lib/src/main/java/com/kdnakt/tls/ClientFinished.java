package com.kdnakt.tls;

import java.io.IOException;
import java.io.OutputStream;

public class ClientFinished {

    public ClientFinished(ClientHello clientHello, ServerHello sh, Certificate certificate, ServerKeyExchange ske,
            ServerHelloDone done, ClientKeyExchange cke, ClientChangeCipherSpec cccs) {
    }

    public void writeTo(OutputStream out) throws IOException {
        byte[] message = null;
        out.write(message);
    }

}
