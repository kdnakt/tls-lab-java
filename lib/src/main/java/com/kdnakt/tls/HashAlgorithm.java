package com.kdnakt.tls;

public enum HashAlgorithm {
    None(0),
    MD5(1),
    SHA1(2),
    SHA224(3),
    SHA256(4),
    SHA384(5),
    SHA512(6),
    ;

    private int id;

    HashAlgorithm(int id) {
        this.id = id;
    }

    public static HashAlgorithm valueOf(int id) {
        for (HashAlgorithm a : values()) {
            if (a.id == id) {
                return a;
            }
        }
        throw new IllegalArgumentException(String.format("ID %s is not defined for HashAlgorithm", id));
    }

    public int getId() {
        return id;
    }
}