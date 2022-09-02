package com.kdnakt.tls;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;

public class TLSRecordFactory {

    public static ServerHello readRecord(InputStream in) throws IOException {
        System.out.println("\n---Response---\n");
        int type = in.read();
        System.out.println(type);
        int majorVersion = in.read();
        System.out.println(majorVersion);
        int minorVersion = in.read();
        System.out.println(minorVersion);
        int length1 = in.read();
        System.out.println(length1);
        int length2 = in.read();
        System.out.println(length2);
        int length = (length1 << 8) + length2;
        ByteArrayOutputStream baos = new ByteArrayOutputStream(length);
        for (int i = 0; i < length; i++) {
            int b = in.read();
            baos.write(b);
            System.out.print(b);
            System.out.print(' ');
        }
        System.out.println();
        return new ServerHello(length, baos.toByteArray());
    }

}