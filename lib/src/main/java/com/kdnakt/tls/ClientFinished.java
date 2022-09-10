package com.kdnakt.tls;

import java.io.IOException;
import java.io.OutputStream;
import java.util.ArrayList;
import java.util.List;

public class ClientFinished {

    private List<HandshakeMessage> handshakes = new ArrayList<>();

    public ClientFinished(ClientHello clientHello, ServerHello sh, Certificate certificate, ServerKeyExchange ske,
            ServerHelloDone done, ClientKeyExchange cke, ClientChangeCipherSpec cccs) {
        handshakes.add(clientHello);
        handshakes.add(sh);
        handshakes.add(certificate);
        handshakes.add(ske);
        handshakes.add(done);
        handshakes.add(cke);
        handshakes.add(cccs);
    }

    public void writeTo(OutputStream out) throws IOException {
        byte[] message = null;
        out.write(message);
    }

    public List<HandshakeMessage> getHandshakes() {
        return handshakes;
    }

}
