package com.kdnakt.tls;

public enum TLSVersion {
    TLS12(3, 3);

    private int major;
    private int minor;
    TLSVersion(int major, int minor) {
        this.major = major;
        this.major = minor;
    }
    public int getMajorVersion() {
        return major;
    }
    public int getMinorVersion() {
        return minor;
    }
}
