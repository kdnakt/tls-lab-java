package com.kdnakt.tls;

public enum NamedCurve {

    secp256r1(23),
    ;
    private int id;
    NamedCurve(int id) {
        this.id = id;
    }
    public static String of(int namedCurve) {
        for (NamedCurve curve : values()) {
            if (curve.id == namedCurve) {
                return curve.toString();
            }
        }
        throw new IllegalArgumentException("No such curve: " + namedCurve);
    }

}
