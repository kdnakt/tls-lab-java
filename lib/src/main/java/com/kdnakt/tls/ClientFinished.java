package com.kdnakt.tls;

import java.io.IOException;
import java.io.OutputStream;

public class ClientFinished {

    public void writeTo(OutputStream out) throws IOException {
        byte[] message = null;
        out.write(message);
    }

}
