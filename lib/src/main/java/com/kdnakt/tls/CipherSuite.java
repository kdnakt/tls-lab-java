package com.kdnakt.tls;

public enum CipherSuite {
    TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256(0xc0, 0x2b),
    ;
    private int id;
    CipherSuite(int hex1, int hex2) {
        this.id = hex1 * 16 * 16 + hex2;
    }
    static CipherSuite valueOf(int id) {
        for (CipherSuite c : values()) {
            if (c.id == id) {
                return c;
            }
        }
        throw new IllegalArgumentException("unknown cipher suite id: " + id);
    }
}
