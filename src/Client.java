import java.io.*;
import java.math.BigInteger;
import java.net.Socket;
import java.security.PrivateKey;
import java.security.SecureRandom;
import java.security.cert.Certificate;
import java.util.ArrayList;
import java.util.List;

public class Client {
    private final byte[] nonce;
    private static Certificate clientCertificate;
    private final BigInteger clientPrivateDHKey;
    private static BigInteger clientPublicDHKey;
    private static byte[] clientDHKeySignature;
    private final ByteArrayOutputStream messageArchive;

    public static void main(String[] args) {
        Client client = null;
        try {
            client = new Client();
            client.connectToServer("localhost", 8080);
        } catch (Exception e) {
            System.out.println("Failed to initialize the client: " + e.getMessage());
            e.printStackTrace();
        }
    }

    public Client() throws Exception {
        String certPath = "resources/CASignedClientCertificate.pem";
        String privateKeyPath = "resources/clientPrivateKey.der";

        clientCertificate = SecurityUtils.fetchCertificate(certPath);
        PrivateKey clientPrivateKey = SecurityUtils.retrievePrivateKey(privateKeyPath);

        clientPrivateDHKey = new BigInteger(2048, new SecureRandom());
        clientPublicDHKey = SecurityUtils.computeDHPublicKey(clientPrivateDHKey);
        clientDHKeySignature = SecurityUtils.signDHPublicKey(clientPrivateKey, clientPublicDHKey);

        nonce = generateNonce();
        messageArchive = new ByteArrayOutputStream();
    }

    /**
     * Generates a random nonce.
     *
     * @return The generated nonce.
     */
    private byte[] generateNonce() {
        byte[] newNonce = new byte[32];
        new SecureRandom().nextBytes(newNonce);
        return newNonce;
    }

    /**
     * Exchanges messages with the server after a successful handshake.
     *
     * @param in  The input stream to read messages from the server.
     * @param out The output stream to send messages to the server.
     */
    /**
     * Exchanges messages with the server after a successful handshake.
     *
     * @param in  The input stream to read messages from the server.
     * @param out The output stream to send messages to the server.
     */
    private void exchangeMessages(ObjectInputStream in, ObjectOutputStream out) throws Exception {
        // Receive multiple messages from the server
        List<String> receivedMessages = new ArrayList<>();
        while (true) {
            Message receivedMessage = (Message) in.readObject();
            byte[] decryptedMessage = SecurityUtils.secureDecrypt(receivedMessage.getData(),
                    SecurityUtils.serverEncryptionKey, SecurityUtils.serverInitializationVector,
                    SecurityUtils.serverAuthKey);
            if (SecurityUtils.confirmMessageIntegrity(receivedMessage.getMac(), receivedMessage.getData(),
                    SecurityUtils.serverAuthKey)) {
                receivedMessages.add(new String(decryptedMessage));
            } else {
                throw new SecurityException("Message integrity verification failed.");
            }

            // Check if it was the last message from the server
            if (new String(decryptedMessage).equals("Final message from server")) {
                break;
            }
        }

        // Print all received messages
        for (String message : receivedMessages) {
            System.out.println("Server says: " + message);
        }

        // Send a single response message to the server
        String responseMessage = "Hello back from client!";
        byte[] encryptedResponse = SecurityUtils.secureEncrypt(responseMessage.getBytes(),
                SecurityUtils.clientEncryptionKey, SecurityUtils.clientInitializationVector,
                SecurityUtils.clientAuthKey);
        Message message = new Message(encryptedResponse,
                SecurityUtils.computeMAC(encryptedResponse, SecurityUtils.clientAuthKey));
        out.writeObject(message);
    }


    /**
     * Connects to the server and initiates the handshake and message exchange.
     *
     * @param host The server host.
     * @param port The server port.
     */
    public void connectToServer(String host, int port) {
        try (Socket socket = new Socket(host, port);
             ObjectOutputStream out = new ObjectOutputStream(socket.getOutputStream());
             ObjectInputStream in = new ObjectInputStream(socket.getInputStream())) {

            completeHandshake(in, out);
            exchangeMessages(in, out);
        } catch (Exception e) {
            System.out.println("Client error: " + e.getMessage());
            e.printStackTrace();
        }
    }

    /**
     * Completes the handshake process with the server.
     *
     * @param in  The input stream to read handshake messages from the server.
     * @param out The output stream to send handshake messages to the server.
     */
    private void completeHandshake(ObjectInputStream in, ObjectOutputStream out) throws Exception {
        out.writeObject(nonce);
        messageArchive.write(nonce);

        BigInteger serverPublicDHKey = SecurityUtils.authenticateAndExtractPublicKey(in, messageArchive);

        SecurityUtils.dispatchPublicKeyAndCertificate(out, clientCertificate, clientPublicDHKey,
                clientDHKeySignature);
        messageArchive.write(clientCertificate.getEncoded());
        messageArchive.write(clientPublicDHKey.toByteArray());
        messageArchive.write(clientDHKeySignature);

        BigInteger sharedSecret = SecurityUtils.deriveSharedSecret(clientPrivateDHKey, serverPublicDHKey);
        SecurityUtils.generateSessionKeys(nonce, sharedSecret.toByteArray());
        System.out.println("Client-side keys have been generated.");

        byte[] serverHandshakeSummary = (byte[]) in.readObject();
        if (SecurityUtils.confirmMessageIntegrity(serverHandshakeSummary, messageArchive.toByteArray(),
                SecurityUtils.serverAuthKey)) {
            System.out.println("Server handshake verified.");
        } else {
            throw new SecurityException("Server handshake verification failed.");
        }

        byte[] handshakeSummary = SecurityUtils.computeMAC(messageArchive.toByteArray(),
                SecurityUtils.clientAuthKey);
        out.writeObject(handshakeSummary);
    }
}