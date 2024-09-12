import javax.crypto.*;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.io.*;
import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.security.*;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.util.Arrays;

public class SecurityUtils {
    public static byte[] serverEncryptionKey;
    public static byte[] clientEncryptionKey;
    public static byte[] serverAuthKey;
    public static byte[] clientAuthKey;
    public static byte[] serverInitializationVector;
    public static byte[] clientInitializationVector;

    // RFC 3526 Diffie-Hellman parameters
    private static final BigInteger DH_P = new BigInteger("FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD1" +
            "29024E088A67CC74020BBEA63B139B22514A08798E3404DD" +
            "EF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245" +
            "E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7ED" +
            "EE386BFB5A899FA5AE9F24117C4B1FE649286651ECE45B3D" +
            "C2007CB8A163BF0598DA48361C55D39A69163FA8FD24CF5F" +
            "83655D23DCA3AD961C62F356208552BB9ED529077096966D" +
            "670C354E4ABC9804F1746C08CA237327FFFFFFFFFFFFFFFF", 16);
    private static final BigInteger DH_G = BigInteger.valueOf(2);

    /**
     * Verifies the integrity of a message.
     * @param receivedMac The received message authentication code.
     * @param data The message data.
     * @param key The authentication key.
     * @return true if the integrity is verified, false otherwise.
     */
    public static boolean confirmMessageIntegrity(byte[] receivedMac, byte[] data, byte[] key) throws NoSuchAlgorithmException, InvalidKeyException {
        byte[] computedMac = computeMAC(data, key);
        return Arrays.equals(computedMac, receivedMac);
    }

    /**
     * Encrypts a message.
     * @param data The message data to be encrypted.
     * @param key The encryption key.
     * @param iv The initialization vector.
     * @param macKey The authentication key.
     * @return The encrypted message, including the message data and the authentication code.
     */
    public static byte[] secureEncrypt(byte[] data, byte[] key, byte[] iv, byte[] macKey) throws Exception {
        Mac mac = Mac.getInstance("HmacSHA256");
        mac.init(new SecretKeySpec(macKey, "HmacSHA256"));
        byte[] hmac = mac.doFinal(data);

        ByteArrayOutputStream outputStream = new ByteArrayOutputStream();
        outputStream.write(data);
        outputStream.write(hmac);

        Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
        cipher.init(Cipher.ENCRYPT_MODE, new SecretKeySpec(key, "AES"), new IvParameterSpec(iv));

        return cipher.doFinal(outputStream.toByteArray());
    }

    /**
     * Decrypts a message.
     * @param encryptedData The encrypted message data.
     * @param key The decryption key.
     * @param iv The initialization vector.
     * @param macKey The authentication key.
     * @return The decrypted message data.
     * @throws SecurityException If the integrity verification fails.
     */
    public static byte[] secureDecrypt(byte[] encryptedData, byte[] key, byte[] iv, byte[] macKey) throws Exception {
        Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
        cipher.init(Cipher.DECRYPT_MODE, new SecretKeySpec(key, "AES"), new IvParameterSpec(iv));
        byte[] decryptedData = cipher.doFinal(encryptedData);
        byte[] data = Arrays.copyOfRange(decryptedData, 0, decryptedData.length - 32);
        byte[] hmac = Arrays.copyOfRange(decryptedData, decryptedData.length - 32, decryptedData.length);

        if (Arrays.equals(computeMAC(data, macKey), hmac)) {
            System.out.println("Data integrity confirmed.");
            return data;
        } else {
            throw new SecurityException("Data integrity verification failed.");
        }
    }

    /**
     * HMAC-based Key Derivation Function (HKDF).
     * @param input The input key material.
     * @param info Additional information.
     * @return The derived key.
     */
    private static byte[] hkdf(byte[] input, String info) throws NoSuchAlgorithmException, InvalidKeyException {
        Mac hmacSha256 = Mac.getInstance("HmacSHA256");
        SecretKeySpec keySpec = new SecretKeySpec(input, "HmacSHA256");
        hmacSha256.init(keySpec);
        hmacSha256.update((info + "\1").getBytes());
        byte[] outputKeyMaterial = hmacSha256.doFinal();
        byte[] truncatedOutput = new byte[16];
        System.arraycopy(outputKeyMaterial, 0, truncatedOutput, 0, truncatedOutput.length);
        return truncatedOutput;
    }

    /**
     * Computes the message authentication code (MAC).
     * @param data The message data.
     * @param key The authentication key.
     * @return The computed MAC.
     */
    public static byte[] computeMAC(byte[] data, byte[] key) throws NoSuchAlgorithmException, InvalidKeyException {
        Mac mac = Mac.getInstance("HmacSHA256");
        SecretKeySpec keySpec = new SecretKeySpec(key, "HmacSHA256");
        mac.init(keySpec);
        mac.update(data);
        return mac.doFinal();
    }

    /**
     * Fetches a certificate from a file.
     * @param path The path to the certificate file.
     * @return The X509Certificate object.
     */
    public static X509Certificate fetchCertificate(String path) throws Exception {
        FileInputStream inputStream = new FileInputStream(path);
        CertificateFactory certificateFactory = CertificateFactory.getInstance("X.509");
        X509Certificate certificate = (X509Certificate) certificateFactory.generateCertificate(inputStream);
        inputStream.close();
        return certificate;
    }

    /**
     * Computes the Diffie-Hellman public key.
     * @param privateKey The Diffie-Hellman private key.
     * @return The Diffie-Hellman public key.
     */
    public static BigInteger computeDHPublicKey(BigInteger privateKey) {
        return DH_G.modPow(privateKey, DH_P);
    }

    /**
     * Signs the Diffie-Hellman public key using the RSA private key.
     * @param privateKey The RSA private key.
     * @param publicKey The Diffie-Hellman public key.
     * @return The signature.
     */
    public static byte[] signDHPublicKey(PrivateKey privateKey, BigInteger publicKey) throws NoSuchAlgorithmException, InvalidKeyException, SignatureException {
        Signature signature = Signature.getInstance("SHA256withRSA");
        signature.initSign(privateKey);
        signature.update(publicKey.toByteArray());
        return signature.sign();
    }

    /**
     * Retrieves the RSA private key from a file.
     * @param path The path to the private key file.
     * @return The RSA private key object.
     */
    public static PrivateKey retrievePrivateKey(String path) throws IOException, NoSuchAlgorithmException, InvalidKeySpecException {
        FileInputStream inputStream = new FileInputStream(path);
        byte[] keyBytes = inputStream.readAllBytes();
        PKCS8EncodedKeySpec spec = new PKCS8EncodedKeySpec(keyBytes);
        KeyFactory factory = KeyFactory.getInstance("RSA");
        inputStream.close();
        return factory.generatePrivate(spec);
    }

    /**
     * Verifies if a certificate is issued by the CA.
     * @param certificate The certificate to be verified.
     * @return true if the verification passes, false otherwise.
     */
    public static boolean verifyCertificate(java.security.cert.Certificate certificate) throws Exception {
        String caPath = "resources/CAcertificate.pem";
        X509Certificate caCertificate = fetchCertificate(caPath);
        try {
            certificate.verify(caCertificate.getPublicKey());
            return true;
        } catch (Exception e) {
            e.printStackTrace();
            return false;
        }
    }

    /**
     * Authenticates and extracts the Diffie-Hellman public key from the input stream.
     * @param stream The input stream.
     * @param messageHistory The message history record.
     * @return The Diffie-Hellman public key.
     * @throws SecurityException If the certificate verification fails.
     */
    public static BigInteger authenticateAndExtractPublicKey(ObjectInputStream stream, ByteArrayOutputStream messageHistory) throws Exception {
        java.security.cert.Certificate certificate = (java.security.cert.Certificate) stream.readObject();
        messageHistory.write(certificate.getEncoded());
        BigInteger publicKey = (BigInteger) stream.readObject();
        messageHistory.write(publicKey.toByteArray());
        byte[] signature = (byte[]) stream.readObject();
        messageHistory.write(signature);

        if (verifyCertificate(certificate)) {
            System.out.println("Certificate is authentic.");
        } else {
            throw new SecurityException("Certificate verification failed.");
        }
        return publicKey;
    }

    /**
     * Dispatches the certificate, Diffie-Hellman public key, and signature to the output stream.
     * @param stream The output stream.
     * @param cert The certificate.
     * @param publicKey The Diffie-Hellman public key.
     * @param signedKey The signed Diffie-Hellman public key.
     */
    public static void dispatchPublicKeyAndCertificate(ObjectOutputStream stream, java.security.cert.Certificate cert, BigInteger publicKey, byte[] signedKey) throws IOException {
        stream.writeObject(cert);
        stream.writeObject(publicKey);
        stream.writeObject(signedKey);
        stream.flush();
        System.out.println("Dispatched public key and certificate.");
    }

    /**
     * Derives the Diffie-Hellman shared secret.
     * @param privateKey The local Diffie-Hellman private key.
     * @param publicKey The remote Diffie-Hellman public key.
     * @return The Diffie-Hellman shared secret.
     */
    public static BigInteger deriveSharedSecret(BigInteger privateKey, BigInteger publicKey) {
        return publicKey.modPow(privateKey, DH_P);
    }

    /**
     * Generates the session keys from the Diffie-Hellman shared secret and nonce.
     * @param nonce The client-generated random number.
     * @param sharedSecret The Diffie-Hellman shared secret.
     * @return The initial key material.
     */
    public static byte[] generateSessionKeys(byte[] nonce, byte[] sharedSecret) throws NoSuchAlgorithmException, InvalidKeyException {
        byte[] initialKey = hkdf(sharedSecret, "masterSecret" + new String(nonce, StandardCharsets.UTF_8));
        serverEncryptionKey = hkdf(initialKey, "server encryption");
        clientEncryptionKey = hkdf(serverEncryptionKey, "client encryption");
        serverAuthKey = hkdf(clientEncryptionKey, "server authentication");
        clientAuthKey = hkdf(serverAuthKey, "client authentication");
        serverInitializationVector = hkdf(clientAuthKey, "server IV");
        clientInitializationVector = hkdf(serverInitializationVector, "client IV");
        return initialKey;
    }
}

/**
 * The Message class encapsulates the message data and message authentication code.
 */
class Message implements Serializable {
    private static final long serialVersionUID = 1L;

    private byte[] data;
    private byte[] mac;

    public Message(byte[] data, byte[] mac) {
        this.data = data;
        this.mac = mac;
    }

    public byte[] getData() {
        return data;
    }

    public byte[] getMac() {
        return mac;
    }

    private void writeObject(ObjectOutputStream out) throws IOException {
        out.writeInt(data.length);
        out.write(data);
        out.writeInt(mac.length);
        out.write(mac);
    }

    private void readObject(ObjectInputStream in) throws IOException {
        int dataLen = in.readInt();
        data = new byte[dataLen];
        in.readFully(data);
        int macLen = in.readInt();
        mac = new byte[macLen];
        in.readFully(mac);
    }
}