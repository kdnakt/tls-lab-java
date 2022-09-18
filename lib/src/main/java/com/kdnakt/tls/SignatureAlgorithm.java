package com.kdnakt.tls;

public enum SignatureAlgorithm {
    Anonymous(0),
    RSA(1),
    DSA(2),
    ECDSA(3),
    ;

    private int id;

    SignatureAlgorithm(int id) {
        this.id = id;
    }

    public static SignatureAlgorithm valueOf(int id) {
        for (SignatureAlgorithm a : values()) {
            if (a.id == id) {
                return a;
            }
        }
        throw new IllegalArgumentException(String.format("ID %s is not defined for signature algorithm", id));
    }

    public int getId() {
        return id;
    }

}
