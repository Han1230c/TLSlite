import java.io.*;
import java.math.BigInteger;
import java.net.ServerSocket;
import java.net.Socket;
import java.security.PrivateKey;
import java.security.SecureRandom;
import java.security.cert.Certificate;

public class Server {
    private static Certificate serverCertificate;
    private static BigInteger serverPublicDHKey;
    private static BigInteger serverPrivateDHKey;
    private static byte[] serverDHKeySignature;
    private static ByteArrayOutputStream messageArchive;

    public static void main(String[] args) {
        try {
            new Server().start();
        } catch (Exception e) {
            System.out.println("Failed to initialize the server: " + e.getMessage());
            e.printStackTrace();
        }
    }

    public Server() throws Exception {
        String certificatePath = "resources/CASignedServerCertificate.pem";
        String privateKeyPath = "resources/serverPrivateKey.der";

        serverCertificate = SecurityUtils.fetchCertificate(certificatePath);

        serverPrivateDHKey = new BigInteger(2048, new SecureRandom());
        serverPublicDHKey = SecurityUtils.computeDHPublicKey(serverPrivateDHKey);

        PrivateKey serverPrivateKey = SecurityUtils.retrievePrivateKey(privateKeyPath);
        serverDHKeySignature = SecurityUtils.signDHPublicKey(serverPrivateKey, serverPublicDHKey);

        messageArchive = new ByteArrayOutputStream();
    }

    /**
     * Exchanges messages with the client after a successful handshake.
     *
     * @param in  The input stream to read messages from the client.
     * @param out The output stream to send messages to the client.
     */
    private void exchangeMessages(ObjectInputStream in, ObjectOutputStream out) throws Exception {
        // Send multiple messages to the client
        String[] testMessages = {"Hello from server!", "This is another message", "Final message from server"};
        for (String testMessage : testMessages) {
            byte[] encryptedMessage = SecurityUtils.secureEncrypt(testMessage.getBytes(),
                    SecurityUtils.serverEncryptionKey, SecurityUtils.serverInitializationVector,
                    SecurityUtils.serverAuthKey);
            Message message = new Message(encryptedMessage,
                    SecurityUtils.computeMAC(encryptedMessage, SecurityUtils.serverAuthKey));
            out.writeObject(message);
        }

        // Receive a response message from the client
        Message receivedMessage = (Message) in.readObject();
        byte[] decryptedMessage = SecurityUtils.secureDecrypt(receivedMessage.getData(),
                SecurityUtils.clientEncryptionKey, SecurityUtils.clientInitializationVector,
                SecurityUtils.clientAuthKey);
        if (SecurityUtils.confirmMessageIntegrity(receivedMessage.getMac(), receivedMessage.getData(),
                SecurityUtils.clientAuthKey)) {
            System.out.println("Client says: " + new String(decryptedMessage));
        } else {
            throw new SecurityException("Message integrity verification failed.");
        }
    }

    /**
     * Starts the server and listens for client connections.
     */
    public void start() {
        int port = 8080;
        try (ServerSocket serverSocket = new ServerSocket(port)) {
            System.out.println("Server is listening on port " + port);

            while (true) {
                Socket clientSocket = serverSocket.accept();
                System.out.println("Client connected.");

                try (ObjectOutputStream out = new ObjectOutputStream(clientSocket.getOutputStream());
                     ObjectInputStream in = new ObjectInputStream(clientSocket.getInputStream())) {

                    performHandshake(in, out);
                    exchangeMessages(in, out);
                } catch (Exception e) {
                    System.out.println("An error occurred: " + e.getMessage());
                    e.printStackTrace();
                }
            }
        } catch (IOException e) {
            System.out.println("Server could not start: " + e.getMessage());
            e.printStackTrace();
        }
    }

    /**
     * Performs the handshake process with the client.
     *
     * @param in  The input stream to read handshake messages from the client.
     * @param out The output stream to send handshake messages to the client.
     */
    private void performHandshake(ObjectInputStream in, ObjectOutputStream out) throws Exception {
        byte[] clientNonce = (byte[]) in.readObject();
        messageArchive.write(clientNonce);

        SecurityUtils.dispatchPublicKeyAndCertificate(out, serverCertificate, serverPublicDHKey,
                serverDHKeySignature);
        messageArchive.write(serverCertificate.getEncoded());
        messageArchive.write(serverPublicDHKey.toByteArray());
        messageArchive.write(serverDHKeySignature);

        BigInteger clientPublicDHKey = SecurityUtils.authenticateAndExtractPublicKey(in, messageArchive);

        BigInteger sharedSecret = SecurityUtils.deriveSharedSecret(serverPrivateDHKey, clientPublicDHKey);
        SecurityUtils.generateSessionKeys(clientNonce, sharedSecret.toByteArray());
        System.out.println("Server-side keys have been generated.");

        byte[] handshakeSummary = SecurityUtils.computeMAC(messageArchive.toByteArray(),
                SecurityUtils.serverAuthKey);
        out.writeObject(handshakeSummary);

        byte[] clientHandshakeSummary = (byte[]) in.readObject();
        if (SecurityUtils.confirmMessageIntegrity(clientHandshakeSummary, messageArchive.toByteArray(),
                SecurityUtils.clientAuthKey)) {
            System.out.println("Client handshake verified.");
        } else {
            throw new SecurityException("Client handshake verification failed.");
        }
    }
}