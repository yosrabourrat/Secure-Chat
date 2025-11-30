import javax.crypto.spec.SecretKeySpec;
import java.io.*;
import java.net.Socket;
import java.security.PublicKey;
import java.util.Scanner;

public class SecureChatClient {

    private Socket socket;
    private BufferedReader reader;
    private PrintWriter writer;
    private SecretKeySpec aesKey;
    private String nickname;

    public void start(String host, int port) throws Exception {
        socket = new Socket(host, port);
        reader = new BufferedReader(new InputStreamReader(socket.getInputStream(), "UTF-8"));
        writer = new PrintWriter(new OutputStreamWriter(socket.getOutputStream(), "UTF-8"), true);

        // 1) Read server RSA public key (base64)
        String pubBase64 = reader.readLine();
        PublicKey serverPub = CryptoUtils.publicKeyFromBase64(pubBase64);

        // 2) Generate AES key and send it encrypted with server RSA public key
        byte[] aesBytes = CryptoUtils.generateAESKeyBytes(128);
        this.aesKey = CryptoUtils.aesKeyFromBytes(aesBytes);
        byte[] encAes = CryptoUtils.rsaEncrypt(aesBytes, serverPub);
        writer.println(CryptoUtils.toBase64(encAes));

        // 3) Send nickname
        writer.println("NICK|" + nickname);

        // start listener thread
        new Thread(new ServerListener()).start();

        // main input loop
        try (Scanner sc = new Scanner(System.in)) {
            while (true) {
                String line = sc.nextLine();
                if (line == null) continue;
                if (line.equalsIgnoreCase("Bye") || line.equalsIgnoreCase("Goodbye")) {
                    // send encrypted /quit
                    sendEncrypted(line);
                    break;
                }
                sendEncrypted(line);
            }
        }

        close();
    }

    private void sendEncrypted(String plain) {
        try {
            byte[] cipher = CryptoUtils.aesEncrypt(plain.getBytes("UTF-8"), aesKey);
            String b64 = CryptoUtils.toBase64(cipher);
            writer.println(b64);
        } catch (Exception e) {
            System.err.println("Send error: " + e.getMessage());
        }
    }

    private void close() {
        try {
            socket.close();
        } catch (IOException ignored) {}
    }

    private class ServerListener implements Runnable {
        @Override
        public void run() {
            try {
                String incoming;
                while ((incoming = reader.readLine()) != null) {
                    // incoming is base64 of AES-encrypted plaintext for this client
                    try {
                        byte[] cipherBytes = CryptoUtils.fromBase64(incoming);
                        byte[] plainBytes = CryptoUtils.aesDecrypt(cipherBytes, aesKey);
                        String plain = new String(plainBytes, "UTF-8");
                        System.out.println(plain);
                    } catch (Exception e) {
                        System.err.println("Decrypt incoming error: " + e.getMessage());
                    }
                }
            } catch (IOException e) {
                System.out.println("You quit conversation");
            } finally {
                close();
            }
        }
    }

    // Runner
    public static void main(String[] args) {
        Scanner sc = new Scanner(System.in);
        System.out.print("Serveur IP : ");
        String host = sc.nextLine().trim();
        System.out.print("Port : ");
        int port = Integer.parseInt(sc.nextLine().trim());
        System.out.print("Pseudo : ");
        String nick = sc.nextLine().trim();

        SecureChatClient client = new SecureChatClient();
        client.nickname = nick;
        try {
            client.start(host, port);
        } catch (Exception e) {
            System.err.println("Client error: " + e.getMessage());
            e.printStackTrace();
        }
    }
}
