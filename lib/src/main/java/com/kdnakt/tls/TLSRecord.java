package com.kdnakt.tls;

public class TLSRecord {

    private HandshakeMessage handshakeMessage;
    private ChangeCipherSpec changeCipherSpec;

    private TLSRecord() {
        // do nothing
    }

    static TLSRecord valueOf(HandshakeMessage handshakeMessage) {
        TLSRecord rec = new TLSRecord();
        rec.handshakeMessage = handshakeMessage;
        return rec;
    }

    boolean isHandshake() {
        return handshakeMessage != null;
    }

    static TLSRecord valueOf(ChangeCipherSpec ccs) {
        TLSRecord rec = new TLSRecord();
        rec.changeCipherSpec = ccs;
        return rec;
    }

    boolean isChangeCipherSpec() {
        return changeCipherSpec != null;
    }

    public HandshakeMessage getHandshakeMessage() {
        return handshakeMessage;
    }

    public ChangeCipherSpec getChangeCipherSpec() {
        return changeCipherSpec;
    }

}