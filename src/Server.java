import java.io.*;
import java.net.ServerSocket;
import java.net.Socket;
import java.nio.file.Files;
import java.security.*;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;
import javax.crypto.Cipher;
import javax.crypto.spec.SecretKeySpec;

public class Server {
    private static final int PORT = 12345;

    public static void main(String[] args) {
        try (ServerSocket serverSocket = new ServerSocket(PORT)) {
            log("Server started, waiting for a connection...");

            // Обрабатываем только одного клиента
            try (Socket socket = serverSocket.accept()) {
                log("Client connected.");
                handleClient(socket);
            } catch (IOException e) {
                log("Error handling client: " + e.getMessage());
            }

            log("Server shutting down...");
        } catch (IOException e) {
            log("Server failed to start: " + e.getMessage());
        }
    }

    private static void handleClient(Socket socket) {
        try (DataInputStream dis = new DataInputStream(socket.getInputStream());
             DataOutputStream dos = new DataOutputStream(socket.getOutputStream())) {

            // Принятие файлов
            receiveFile(dis, "encrypted_aes_key.bin");
            receiveFile(dis, "file_encrypted.bin");
            receiveFile(dis, "file_signature.sig");

            // Работа с ключами
            PrivateKey serverPrivateKey = loadPrivateKey("server_private.pem");
            PublicKey clientPublicKey = loadPublicKey("client_public.pem");

            // Расшифровка ключа и данных
            byte[] encryptedAESKey = Files.readAllBytes(new File("encrypted_aes_key.bin").toPath());
            byte[] aesKey = decryptRSA(encryptedAESKey, serverPrivateKey);

            byte[] encryptedFile = Files.readAllBytes(new File("file_encrypted.bin").toPath());
            byte[] decryptedFile = decryptAES(encryptedFile, aesKey);
            Files.write(new File("received_secret_data.txt").toPath(), decryptedFile);

            // Проверка подписи
            byte[] signature = Files.readAllBytes(new File("file_signature.sig").toPath());
            boolean isVerified = verifySignature(decryptedFile, signature, clientPublicKey);

            if (isVerified) {
                dos.writeUTF("Файл успешно принят. Повреждений нет.");
                log("File verified successfully.");
            } else {
                dos.writeUTF("Файл был поврежден при передаче.");
                log("File verification failed.");
            }

            // Очистка временных файлов
            cleanupTemporaryFiles();

        } catch (IOException e) {
            log("Client disconnected.");
        } catch (Exception e) {
            log("Error during client communication: " + e.getMessage());
        }
    }

    private static void receiveFile(DataInputStream dis, String fileName) throws IOException {
        int length = dis.readInt();
        byte[] data = new byte[length];
        dis.readFully(data);
        Files.write(new File(fileName).toPath(), data);
        log("File received: " + fileName);
    }

    private static PrivateKey loadPrivateKey(String filePath) throws Exception {
        byte[] keyBytes = Files.readAllBytes(new File(filePath).toPath());
        String keyPem = new String(keyBytes).replaceAll("-----\\w+ PRIVATE KEY-----", "").replaceAll("\\s", "");
        byte[] decodedKey = Base64.getDecoder().decode(keyPem);
        KeyFactory keyFactory = KeyFactory.getInstance("RSA");
        return keyFactory.generatePrivate(new PKCS8EncodedKeySpec(decodedKey));
    }

    private static PublicKey loadPublicKey(String filePath) throws Exception {
        byte[] keyBytes = Files.readAllBytes(new File(filePath).toPath());
        String keyPem = new String(keyBytes).replaceAll("-----\\w+ PUBLIC KEY-----", "").replaceAll("\\s", "");
        byte[] decodedKey = Base64.getDecoder().decode(keyPem);
        KeyFactory keyFactory = KeyFactory.getInstance("RSA");
        return keyFactory.generatePublic(new X509EncodedKeySpec(decodedKey));
    }

    private static byte[] decryptRSA(byte[] data, PrivateKey privateKey) throws Exception {
        Cipher cipher = Cipher.getInstance("RSA");
        cipher.init(Cipher.DECRYPT_MODE, privateKey);
        return cipher.doFinal(data);
    }

    private static byte[] decryptAES(byte[] data, byte[] aesKey) throws Exception {
        Cipher cipher = Cipher.getInstance("AES");
        SecretKeySpec secretKeySpec = new SecretKeySpec(aesKey, "AES");
        cipher.init(Cipher.DECRYPT_MODE, secretKeySpec);
        return cipher.doFinal(data);
    }

    private static boolean verifySignature(byte[] data, byte[] signature, PublicKey publicKey) throws Exception {
        Signature sig = Signature.getInstance("SHA256withRSA");
        sig.initVerify(publicKey);
        sig.update(data);
        return sig.verify(signature);
    }

    private static void cleanupTemporaryFiles() {
        String[] tempFiles = {"encrypted_aes_key.bin", "file_encrypted.bin", "file_signature.sig"};
        for (String fileName : tempFiles) {
            File file = new File(fileName);
            if (file.exists() && file.delete()) {
                log("Temporary file deleted: " + fileName);
            } else {
                log("Failed to delete temporary file: " + fileName);
            }
        }
    }

    private static void log(String message) {
        System.out.println("[Server Log] " + message);
    }
}
