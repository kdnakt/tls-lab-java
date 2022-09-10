package com.kdnakt.tls;

import static org.junit.jupiter.api.Assertions.assertEquals;

import org.junit.jupiter.api.Test;

public class ClientFinishedTest {
    @Test
    void testClientFinishedConstructor() {
        ClientHello ch = new ClientHello();
        int[] serverHello = {3,3,0,1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16,17,18,19,20,21,22,23,24,25,26,27,28,29,30,31,0,0,0,5,0,0,0,0,0};
        ServerHello sh = new ServerHello(serverHello);
        Certificate c = new Certificate(null);
        int[] serverKeyExchange = {0,0,0,1,0,0,0,0,1,0};
        ServerKeyExchange ske = new ServerKeyExchange(serverKeyExchange);
        ServerHelloDone done = new ServerHelloDone(0);
        ClientKeyExchange cke = new ClientKeyExchange(null);
        ClientChangeCipherSpec cccs = new ClientChangeCipherSpec();
        ClientFinished sut = new ClientFinished(null, null, ch, sh, c, ske, done, cke, cccs);
        assertEquals(7, sut.getHandshakes().size());
    }
}
