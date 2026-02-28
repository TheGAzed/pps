package org.example;

import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.nio.ByteBuffer;
import java.security.SecureRandom;

public class Main {
    private final int THREAD_COUNT = 2;
    private final int CEILING = THREAD_COUNT * CipherThread.BYTES;

    private byte[] inputBuffer;
    private byte[] encryptBuffer;
    private byte[] decryptBuffer;

    private SecretKey key;
    byte[] nonce = new byte[12];

    void main() throws Exception {
        KeyGenerator keyGen = KeyGenerator.getInstance("AES");
        keyGen.init(128);
        key = keyGen.generateKey();

        SecureRandom random = new SecureRandom();
        random.nextBytes(nonce);

        File inputFile = new File("src/main/resources/input.bmp");

        int length = (int)inputFile.length();
        int ceil = ((length + (CEILING - 1)) / CEILING) * CEILING;
        inputBuffer = ByteBuffer.allocate(ceil).array();
        encryptBuffer = new byte[inputBuffer.length];
        decryptBuffer = new byte[inputBuffer.length];

        File encryptFile = new File("src/main/resources/encrypt.bmp");
        boolean ignoredEncrypt = encryptFile.createNewFile();

        File decryptFile = new File("src/main/resources/decrypt.bmp");
        boolean ignoredDecrypt = decryptFile.createNewFile();

        try (
                FileInputStream inputStream = new FileInputStream(inputFile);
                FileOutputStream encryptStream = new FileOutputStream(encryptFile);
                FileOutputStream decryptStream = new FileOutputStream(decryptFile)
        ) {
            inputStream.readNBytes(inputBuffer, 0, inputBuffer.length);

            this.encrypt();
            encryptStream.write(encryptBuffer, 0, length);

            this.decrypt();
            decryptStream.write(decryptBuffer, 0, length);
        } catch (Exception e) {
            throw new Exception(e);
        }
    }

    void encrypt() throws InterruptedException {
        EncryptThread[] threads = new EncryptThread[THREAD_COUNT];
        for (int i = 0; i < THREAD_COUNT; i++) {
            int count = inputBuffer.length / CEILING;
            int counterStart = i * count;

            threads[i] = new EncryptThread(key, nonce, counterStart, counterStart + count, inputBuffer, encryptBuffer);
            threads[i].start();
        }

        for (int i = 0; i < THREAD_COUNT; i++) {
            threads[i].join();
        }
    }

    void decrypt() throws InterruptedException {
        DecryptThread[] threads = new DecryptThread[THREAD_COUNT];
        for (int i = 0; i < THREAD_COUNT; i++) {
            int count = inputBuffer.length / CEILING;
            int counterStart = i * count;

            threads[i] = new DecryptThread(key, nonce, counterStart, counterStart + count, decryptBuffer, encryptBuffer);
            threads[i].start();
        }

        for (int i = 0; i < THREAD_COUNT; i++) {
            threads[i].join();
        }
    }
}
