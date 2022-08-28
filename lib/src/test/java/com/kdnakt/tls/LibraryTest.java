package com.kdnakt.tls;

import static org.junit.jupiter.api.Assertions.assertEquals;

import java.io.BufferedReader;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.OutputStream;
import java.net.Socket;
import org.junit.jupiter.api.Test;

class LibraryTest {
    @Test void testClientHello() {
        try (Socket socket = new Socket("localhost", 443);
            OutputStream out = socket.getOutputStream();
            BufferedReader in = new BufferedReader(new InputStreamReader(socket.getInputStream()))) {

            final ByteArrayOutputStream baos = new ByteArrayOutputStream();
            System.out.println("\n---Request---\n");
            ClientHello clientHello = new ClientHello();
            for (int i : clientHello.getMessage()) {
                baos.write(i);
                System.out.print(i);
                System.out.print(' ');
            }
            baos.writeTo(out);
            System.out.println();

            System.out.println();
            // Server Hello
            System.out.println("\n---Response---\n");
            int type = in.read();
            System.out.println(type);
            assertEquals(22, type);
            int majorVersion = in.read();
            System.out.println(majorVersion);
            assertEquals(3, majorVersion);
            int minorVersion = in.read();
            System.out.println(minorVersion);
            assertEquals(3, minorVersion);
            int length1 = in.read();
            System.out.println(length1);
            assertEquals(0, length1);
            int length2 = in.read();
            System.out.println(length2);
            assertEquals(55, length2);
            for (int i = 0; i < length2; i++) {
                System.out.print(in.read());
                System.out.print(' ');
            }
            System.out.println();
            System.out.println("Stop reading input stream.");
            // Certificate, Server Key Exchange, Server Hello Done
        } catch (IOException e) {
            e.printStackTrace();
        }
    }
}
