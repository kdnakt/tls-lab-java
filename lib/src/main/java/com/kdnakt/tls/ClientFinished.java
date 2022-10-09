package com.kdnakt.tls;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.OutputStream;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.Mac;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;

public class ClientFinished implements HandshakeMessage {

    private byte[] clientWriteIV;
    private byte[] clientWriteKey;
    private byte[] clientWriteMacKey;
    private SecretKeySpec masterSecret;
    private List<HandshakeMessage> handshakes = new ArrayList<>();

    public ClientFinished(byte[] clientWriteIV, SecretKeySpec masterSecret,
            byte[] clientWriteKey, byte[] clientWriteMacKey,
            ClientHello clientHello, ServerHello sh,
            Certificate certificate, ServerKeyExchange ske,
            ServerHelloDone done, ClientKeyExchange cke) {
        this.clientWriteIV = clientWriteIV;
        this.masterSecret = masterSecret;
        this.clientWriteKey = clientWriteKey;
        this.clientWriteMacKey = clientWriteMacKey;
        handshakes.add(clientHello);
        handshakes.add(sh);
        handshakes.add(certificate);
        handshakes.add(ske);
        handshakes.add(done);
        handshakes.add(cke);
    }

    public void writeTo(OutputStream out) throws IOException, NoSuchAlgorithmException, InvalidKeyException, NoSuchPaddingException, InvalidAlgorithmParameterException, IllegalBlockSizeException, BadPaddingException {
        // TODO: create new random IV
        byte[] encryptionIV = {
            0x40, 0x41, 0x42, 0x43, 0x44, 0x45, 0x46, 0x47,
            0x48, 0x49, 0x4a, 0x4b, 0x4c, 0x4d, 0x4e, 0x4f,
        };

        // encrypted handshake message
        // handshake message to encrypt
        // verify data
        // seed = "client finished" + SHA256(all handshake messages)
        byte[] cf = "client finished".getBytes();
        byte[] seed = new byte[cf.length + 32];
        System.arraycopy(cf, 0, seed, 0, cf.length);
        MessageDigest sha256 = MessageDigest.getInstance("SHA-256");
        int hmLen = 0;
        for (HandshakeMessage m : handshakes) hmLen += m.getMessage().length + 4;
        byte[] handshakeMessages = new byte[hmLen];
        int pos = 0;
        for (HandshakeMessage m : handshakes) {
            int[] mes = m.getMessage();
            ByteArrayOutputStream baos = new ByteArrayOutputStream();
            for (int i : mes) baos.write(i);
            byte[] message = baos.toByteArray();
            System.arraycopy(message, 0, handshakeMessages, pos, message.length);
            pos += message.length;
        }
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
        byte[] verifyData = Arrays.copyOf(p1, 12);
        int len = verifyData.length;
        ByteArrayOutputStream message = new ByteArrayOutputStream();
        message.write(getType()); // type finished
        message.write(len >> 16);
        message.write(len >> 8);
        message.write(len);
        message.write(verifyData);

        Mac sha = Mac.getInstance(algorithm);
        sha.init(new SecretKeySpec(clientWriteMacKey, "AES"));
        message.write(sha.doFinal(message.toByteArray()));
        int padLen = message.toByteArray().length % 16;
        if (padLen == 0) padLen = 16;
        int padByte = padLen - 1;
        for (int i = 0; i < padLen; i++) {
            message.write(padByte);
        }

        byte[] finishedMessage = message.toByteArray();
        Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
        GCMParameterSpec gcmSpec = new GCMParameterSpec(16 * 8, encryptionIV);
        cipher.init(Cipher.ENCRYPT_MODE, new SecretKeySpec(clientWriteKey, "AES"), gcmSpec);
        // https://datatracker.ietf.org/doc/html/rfc5246#section-6.2.3.3
        // additional_data = seq_num + TLSCompressed.type + TLSCompressed.version + TLSCompressed.length (uint16);
        // https://datatracker.ietf.org/doc/html/rfc5246#appendix-F.2
        // sequence numbers are 64 bits long
        byte[] additionalData = {
            0,0,0,0,0,0,0,0, // sequence
            0x16, 0x03, 0x03, 0x00, 0x10 // record header
        };
        cipher.updateAAD(additionalData);
        byte[] encryptedData = cipher.doFinal(finishedMessage);

        // Record
        ByteArrayOutputStream record = new ByteArrayOutputStream();
        // record header
        record.write(0x16); // type handshake
        record.write(0x03); // major
        record.write(0x03); // minor
        int recordLen = encryptedData.length + encryptionIV.length;
        record.write(recordLen >> 8);
        record.write(recordLen);
        record.write(encryptionIV);
        record.write(encryptedData);

        out.write(record.toByteArray());
    }

    public List<HandshakeMessage> getHandshakes() {
        return handshakes;
    }

    @Override
    public int getType() {
        return 20;
    }

    @Override
    public int[] getMessageBody() {
        // TODO Auto-generated method stub
        return null;
    }

}
