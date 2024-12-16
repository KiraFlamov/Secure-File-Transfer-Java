import java.io.FileOutputStream;
import java.io.IOException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.util.Base64;

public class KeyGeneration {

    private static final int KEY_SIZE = 2048;

    public static void main(String[] args) {
        try {
            KeyPair serverKeys = generateKeyPair();
            saveKeyPair(serverKeys, "server_public.pem", "server_private.pem");

            KeyPair clientKeys = generateKeyPair();
            saveKeyPair(clientKeys, "client_public.pem", "client_private.pem");

            System.out.println("Ключи успешно созданы и сохранены в каталоге проекта.");
        } catch (Exception e) {
            System.err.println("Ошибка при генерации ключей: " + e.getMessage());
            e.printStackTrace();
        }
    }

    private static KeyPair generateKeyPair() throws NoSuchAlgorithmException {
        KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("RSA");
        keyPairGenerator.initialize(KEY_SIZE);
        return keyPairGenerator.generateKeyPair();
    }

    private static void saveKeyPair(KeyPair keyPair, String publicFileName, String privateFileName) throws IOException {
        PublicKey publicKey = keyPair.getPublic();
        PrivateKey privateKey = keyPair.getPrivate();

        saveKeyToFile(publicFileName, "-----BEGIN PUBLIC KEY-----\n" +
                encodeKeyToBase64(publicKey.getEncoded()) + "\n-----END PUBLIC KEY-----\n");

        saveKeyToFile(privateFileName, "-----BEGIN PRIVATE KEY-----\n" +
                encodeKeyToBase64(privateKey.getEncoded()) + "\n-----END PRIVATE KEY-----\n");
    }

    private static String encodeKeyToBase64(byte[] keyBytes) {
        return Base64.getMimeEncoder(64, new byte[]{'\n'}).encodeToString(keyBytes);
    }

    private static void saveKeyToFile(String fileName, String keyContent) throws IOException {
        try (FileOutputStream fos = new FileOutputStream(fileName)) {
            fos.write(keyContent.getBytes());
        }
    }
}
