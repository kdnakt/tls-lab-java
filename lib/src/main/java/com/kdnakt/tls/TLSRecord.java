package com.kdnakt.tls;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.OutputStream;

public class TLSRecord {

    private TLSVersion version = TLSVersion.TLS12;
    private HandshakeMessage handshakeMessage;
    private ChangeCipherSpec changeCipherSpec;
    private Alert alert;

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

    public static TLSRecord valueOf(Alert alert) {
        TLSRecord rec = new TLSRecord();
        rec.alert = alert;
        return rec;
    }

    public Alert getAlert() {
        return alert;
    }

    public void writeTo(final OutputStream out) throws IOException {
        out.write(getRecordType());
        out.write(version.getMajorVersion());
        out.write(version.getMinorVersion());
        int[] mes = getMessage();
        int mLen = mes.length;
        out.write(mLen >> 8);
        out.write(mLen);
        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        for (int m : mes) baos.write(m);
        out.write(baos.toByteArray());
    }

    int getRecordType() {
        if (isHandshake()) {
            return 0x16;
        } else if (isChangeCipherSpec()) {
            return 0x14;
        }
        throw new RuntimeException("no message");
    }

    int[] getMessage() {
        if (isHandshake()) {
            return handshakeMessage.getMessage();
        } else if (isChangeCipherSpec()) {
            return changeCipherSpec.getMessage();
        }
        throw new RuntimeException("no message");
    }
}