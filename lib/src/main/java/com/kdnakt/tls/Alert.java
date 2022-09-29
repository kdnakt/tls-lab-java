package com.kdnakt.tls;

public class Alert {

    int level;
    int description;
    public static Alert valueOf(int[] message) {
        Alert alert = new Alert();
        alert.level = message[0];
        alert.description = message[1];
        return alert;
    }
    public int getLevel() {
        return level;
    }
    public int getDescription() {
        return description;
    }

}
