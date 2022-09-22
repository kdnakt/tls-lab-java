package com.kdnakt.tls;

import java.io.IOException;
import java.io.OutputStream;
import java.security.InvalidKeyException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.ArrayList;
import java.util.List;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;

public class ClientFinished {

    private byte[] clientWriteIV;
    private SecretKeySpec masterSecret;
    private List<HandshakeMessage> handshakes = new ArrayList<>();

    public ClientFinished(byte[] clientWriteIV, SecretKeySpec masterSecret, ClientHello clientHello, ServerHello sh, Certificate certificate, ServerKeyExchange ske,
            ServerHelloDone done, ClientKeyExchange cke, ClientChangeCipherSpec cccs) {
        this.clientWriteIV = clientWriteIV;
        this.masterSecret = masterSecret;
        handshakes.add(clientHello);
        handshakes.add(sh);
        handshakes.add(certificate);
        handshakes.add(ske);
        handshakes.add(done);
        handshakes.add(cke);
        handshakes.add(cccs);
    }

    public void writeTo(OutputStream out) throws IOException, NoSuchAlgorithmException, InvalidKeyException {
        byte[] message = null;
        // record header
        // encryption IV
        // TODO: make it random
        byte[] encryptionIV = {
            0x40, 0x41, 0x42, 0x43, 0x44, 0x45, 0x46, 0x47,
            0x48, 0x49, 0x4a, 0x4b, 0x4c, 0x4d, 0x4e, 0x4f
        };
        // encrypted handshake message

        // handshake message to encrypt
        // type = 14
        // length = uint24

        // verify data
        // seed = "client finished" + SHA256(all handshake messages)
        byte[] cf = "client finished".getBytes();
        byte[] seed = new byte[cf.length + 32];
        System.arraycopy(cf, 0, seed, 0, cf.length);
        MessageDigest sha256 = MessageDigest.getInstance("SHA-256");
        int hmLen = 0;
        for (HandshakeMessage m : handshakes) hmLen += m.getMessage().length;
        byte[] handshakeMessages = new byte[hmLen];
        byte[] hashed = sha256.digest(handshakeMessages);
        System.arraycopy(hashed, 0, seed, cf.length, 32);
        byte[] a0 = seed;
        // a0 = seed

        String algorithm = "HmacSHA256";
        Mac mac = Mac.getInstance(algorithm);
        mac.init(masterSecret);

        // a1 = HMAC-SHA256(key=MasterSecret, data=a0)
        byte[] a1 = mac.doFinal(a0);
        byte[] data = new byte[a1.length + seed.length];
        System.arraycopy(a1, 0, data, 0, a1.length);
        System.arraycopy(seed, 0, data, a1.length, seed.length);
        // p1 = HMAC-SHA256(key=MasterSecret, data=a1 + seed)
        byte[] p1 = mac.doFinal(data);
        // verify_data = p1[first 12 bytes]
        byte[] verifyData = new byte[12];
        System.arraycopy(p1, 0, verifyData, 0, 12);

        // TODO: encrypt verify data
        out.write(verifyData);
    }

    public List<HandshakeMessage> getHandshakes() {
        return handshakes;
    }

}
