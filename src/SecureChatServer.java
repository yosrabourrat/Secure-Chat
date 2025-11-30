import javax.crypto.spec.SecretKeySpec;
import java.io.*;
import java.net.ServerSocket;
import java.net.Socket;
import java.security.KeyPair;
import java.security.PrivateKey;
import java.util.List;
import java.util.concurrent.CopyOnWriteArrayList;

public class SecureChatServer {

    private final int port;
    private final KeyPair rsaKeyPair;
    private final PrivateKey rsaPrivate;
    // List of handlers (thread-safe)
    private final List<ClientHandler> clients = new CopyOnWriteArrayList<>();

    public SecureChatServer(int port, KeyPair rsaKeyPair) {
        this.port = port;
        this.rsaKeyPair = rsaKeyPair;
        this.rsaPrivate = rsaKeyPair.getPrivate();
    }

    public void start() {
        System.out.println("SecureChatServer starting on port " + port);
        try (ServerSocket serverSocket = new ServerSocket(port)) {
            while (true) {
                Socket s = serverSocket.accept();
                ClientHandler handler = new ClientHandler(s);
                clients.add(handler);
                new Thread(handler).start();
            }
        } catch (IOException e) {
            System.err.println("Server socket error: " + e.getMessage());
        }
    }

    // Broadcast plaintext message to all clients except sender
    private void broadcast(Message message, ClientHandler exclude) {
        String plain = message.toString();
        for (ClientHandler ch : clients) {
            if (ch == exclude) continue;
            ch.sendEncryptedPlaintext(plain);
        }
    }

    // Remove client
    private void removeClient(ClientHandler ch) {
        clients.remove(ch);
        System.out.println("Client removed: " + ch.nickname);
    }

    // Inner handler class
    private class ClientHandler implements Runnable {
        private final Socket socket;
        private BufferedReader reader;
        private PrintWriter writer;
        private SecretKeySpec aesKey; // per-client AES key
        private String nickname;

        ClientHandler(Socket socket) {
            this.socket = socket;
        }

        @Override
        public void run() {
            String remote = socket.getRemoteSocketAddress().toString();
            System.out.println("Accepted connection from " + remote);
            try {
                reader = new BufferedReader(new InputStreamReader(socket.getInputStream(), "UTF-8"));
                writer = new PrintWriter(new OutputStreamWriter(socket.getOutputStream(), "UTF-8"), true);

                // 1) Send server RSA public key (base64) to client
                String pubBase64 = CryptoUtils.publicKeyToBase64(rsaKeyPair.getPublic());
                writer.println(pubBase64);

                // 2) Receive base64 RSA-encrypted AES key from client
                String encAesBase64 = reader.readLine();
                if (encAesBase64 == null) throw new IOException("No AES key received");
                byte[] encAesBytes = CryptoUtils.fromBase64(encAesBase64);
                byte[] aesBytes = CryptoUtils.rsaDecrypt(encAesBytes, rsaPrivate);
                this.aesKey = CryptoUtils.aesKeyFromBytes(aesBytes);

                // 3) Receive nickname line: format "NICK|nickname"
                String nickLine = reader.readLine();
                if (nickLine == null || !nickLine.startsWith("NICK|")) {
                    throw new IOException("Nickname not provided");
                }
                this.nickname = nickLine.substring(5).trim();
                System.out.println("User joined: " + nickname);

                // Notify others
                broadcast(new Message("SERVER", nickname + " joined the chat"), this);

                // Main loop: read encrypted base64 lines from this client
                String incoming;
                while ((incoming = reader.readLine()) != null) {
                    // incoming is base64 of AES-encrypted plaintext
                    byte[] cipherBytes = CryptoUtils.fromBase64(incoming);
                    String plain;
                    try {
                        byte[] plainBytes = CryptoUtils.aesDecrypt(cipherBytes, aesKey);
                        plain = new String(plainBytes, "UTF-8");
                    } catch (Exception ex) {
                        System.err.println("Decrypt error from " + nickname + ": " + ex.getMessage());
                        continue;
                    }

                    if (plain.equalsIgnoreCase("/quit") || plain.equalsIgnoreCase("/exit")) {
                        writer.println(CryptoUtils.toBase64(CryptoUtils.aesEncrypt(("SERVER: Goodbye").getBytes("UTF-8"), aesKey))); // optional
                        break;
                    }

                    Message msg = new Message(nickname, plain);
                    System.out.println("Received from " + nickname + " -> " + plain);
                    broadcast(msg, this);
                    // Optionally persist encrypted message to log here (not implemented)
                }

            } catch (IOException e) {
                System.err.println("IO for client: " + e.getMessage());
            } catch (Exception ex) {
                System.err.println("Error in client handler: " + ex.getMessage());
            } finally {
                try {
                    if (nickname != null) {
                        broadcast(new Message("SERVER", nickname + " left the chat"), this);
                    }
                    removeClient(this);
                    socket.close();
                } catch (IOException ignored) {}
            }
        }

        // Encrypt a plaintext string with this client's AES key and send as base64 line
        void sendEncryptedPlaintext(String plaintext) {
            try {
                byte[] cipher = CryptoUtils.aesEncrypt(plaintext.getBytes("UTF-8"), aesKey);
                String b64 = CryptoUtils.toBase64(cipher);
                writer.println(b64);
            } catch (Exception e) {
                System.err.println("Send error to " + nickname + ": " + e.getMessage());
            }
        }
    }

    // Main
    public static void main(String[] args) {
        int port = 6000;
        if (args.length >= 1) {
            try { port = Integer.parseInt(args[0]); } catch (NumberFormatException ignored) {}
        }
        try {
            KeyPair kp = CryptoUtils.generateRSAKeyPair(2048);
            SecureChatServer server = new SecureChatServer(port, kp);
            server.start();
        } catch (Exception e) {
            System.err.println("Server startup error: " + e.getMessage());
        }
    }
}
