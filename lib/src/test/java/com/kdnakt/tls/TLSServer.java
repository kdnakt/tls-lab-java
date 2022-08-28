package com.kdnakt.tls;

import java.io.InputStream;
import java.net.ServerSocket;
import java.net.Socket;

public class TLSServer {
    public static void main(String[] args) {
        try (
            ServerSocket socket = new ServerSocket(443);
            Socket io = socket.accept();
            InputStream in = io.getInputStream();
        ) {
            byte[] arr = new byte[100];
            in.read(arr);
            for (byte b : arr) {
                System.out.print((int) b);
                System.out.print(' ');
            }
        } catch (Exception e) {
            e.printStackTrace();
        }
    }
}
