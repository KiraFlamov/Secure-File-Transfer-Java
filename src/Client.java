import javafx.application.Application;
import javafx.scene.Scene;
import javafx.scene.control.*;
import javafx.scene.layout.*;
import javafx.scene.paint.Color;
import javafx.scene.shape.Circle;
import javafx.stage.FileChooser;
import javafx.stage.Stage;
import java.io.*;
import java.net.Socket;
import java.nio.file.Files;
import java.security.*;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;
import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.spec.SecretKeySpec;

public class Client extends Application {
    private TextArea logArea;
    private Socket socket;
    private File selectedFile;
    private Circle connectionIndicator;

    public static void main(String[] args) {
        launch(args);
    }

    @Override
    public void start(Stage primaryStage) {
        primaryStage.setTitle("Защищенная передача файла");

        connectionIndicator = new Circle(10);
        connectionIndicator.setFill(Color.RED);

        Label connectionLabel = new Label("Нет соединения с сервером");

        Button connectButton = new Button("Подключиться");
        connectButton.setPrefSize(200, 40);
        connectButton.setOnAction(e -> connectToServer(connectionLabel));

        Button selectFileButton = new Button("Выбрать файл");
        selectFileButton.setPrefSize(200, 40);
        selectFileButton.setOnAction(e -> selectFile(primaryStage));

        Button sendButton = new Button("Отправить");
        sendButton.setPrefSize(200, 40);
        sendButton.setOnAction(e -> sendFile(connectionLabel));

        logArea = new TextArea();
        logArea.setEditable(false);
        logArea.setWrapText(true);
        logArea.setPrefHeight(200);

        ScrollPane logScrollPane = new ScrollPane(logArea);
        logScrollPane.setFitToWidth(true);
        logScrollPane.setPrefHeight(200);

        HBox connectionStatusBox = new HBox(10, connectionIndicator, connectionLabel);
        connectionStatusBox.setStyle("-fx-alignment: center;");

        VBox buttonBox = new VBox(15, connectButton, selectFileButton, sendButton);
        buttonBox.setStyle("-fx-alignment: center;");

        VBox layout = new VBox(15, logScrollPane, buttonBox, connectionStatusBox);
        layout.setStyle("-fx-padding: 15px; -fx-alignment: center;");

        primaryStage.setScene(new Scene(layout, 400, 400));
        primaryStage.show();
    }

    private void connectToServer(Label connectionLabel) {
        try {
            if (socket != null && !socket.isClosed()) {
                log("Вы уже подключены к серверу!");
                return;
            }

            socket = new Socket("localhost", 12345);
            connectionLabel.setText("Подключено");
            connectionIndicator.setFill(Color.GREEN);
            log("Вы подключены к серверу.");
        } catch (IOException e) {
            log("Ошибка подключения к серверу.");
        }
    }

    private void selectFile(Stage stage) {
        FileChooser fileChooser = new FileChooser();
        fileChooser.setTitle("Выбрать файл");
        selectedFile = fileChooser.showOpenDialog(stage);

        if (selectedFile != null) {
            log("Выбранный файл: " + selectedFile.getAbsolutePath());
        }
    }

    private void sendFile(Label connectionLabel) {
        if (socket == null || socket.isClosed()) {
            log("Ошибка: Нет соединения с сервером!");
            return;
        }

        if (selectedFile == null) {
            log("Ошибка: Не выбран файл!");
            return;
        }

        try (DataOutputStream dos = new DataOutputStream(socket.getOutputStream())) {
            KeyGenerator keyGen = KeyGenerator.getInstance("AES");
            keyGen.init(128);
            SecretKeySpec aesKey = new SecretKeySpec(keyGen.generateKey().getEncoded(), "AES");

            byte[] fileBytes = Files.readAllBytes(selectedFile.toPath());
            Cipher aesCipher = Cipher.getInstance("AES");
            aesCipher.init(Cipher.ENCRYPT_MODE, aesKey);
            byte[] encryptedFile = aesCipher.doFinal(fileBytes);

            PublicKey serverPublicKey = loadPublicKey("server_public.pem");
            Cipher rsaCipher = Cipher.getInstance("RSA");
            rsaCipher.init(Cipher.ENCRYPT_MODE, serverPublicKey);
            byte[] encryptedAESKey = rsaCipher.doFinal(aesKey.getEncoded());

            PrivateKey clientPrivateKey = loadPrivateKey("client_private.pem");
            Signature signature = Signature.getInstance("SHA256withRSA");
            signature.initSign(clientPrivateKey);
            signature.update(fileBytes);
            byte[] fileSignature = signature.sign();

            sendFileData(dos, encryptedAESKey);
            sendFileData(dos, encryptedFile);
            sendFileData(dos, fileSignature);
            log("Файл успешно отправлен.");
            try (DataInputStream dis = new DataInputStream(socket.getInputStream())) {
                String response = dis.readUTF();
                log(response);
                log("Подключитесь к серверу заново, чтобы отправить новый файл.");
                socket.close();
                connectionLabel.setText("Нет соединения с сервером");
                connectionIndicator.setFill(Color.RED);
            }
        } catch (Exception e) {
            log("Failed to send file: " + e.getMessage());
            e.printStackTrace();
        }
    }

    private void sendFileData(DataOutputStream dos, byte[] data) throws IOException {
        dos.writeInt(data.length);
        dos.write(data);
    }

    private PrivateKey loadPrivateKey(String filePath) throws Exception {
        byte[] keyBytes = Files.readAllBytes(new File(filePath).toPath());
        String keyPem = new String(keyBytes).replaceAll("-----\\w+ PRIVATE KEY-----", "").replaceAll("\\s", "");
        byte[] decodedKey = Base64.getDecoder().decode(keyPem);
        KeyFactory keyFactory = KeyFactory.getInstance("RSA");
        return keyFactory.generatePrivate(new PKCS8EncodedKeySpec(decodedKey));
    }

    private PublicKey loadPublicKey(String filePath) throws Exception {
        byte[] keyBytes = Files.readAllBytes(new File(filePath).toPath());
        String keyPem = new String(keyBytes).replaceAll("-----\\w+ PUBLIC KEY-----", "").replaceAll("\\s", "");
        byte[] decodedKey = Base64.getDecoder().decode(keyPem);
        KeyFactory keyFactory = KeyFactory.getInstance("RSA");
        return keyFactory.generatePublic(new X509EncodedKeySpec(decodedKey));
    }

    private void log(String message) {
        logArea.appendText(message + "\n");
    }
}
