package org.example;

import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.nio.ByteBuffer;
import java.security.SecureRandom;

public class Main {
    private final int THREAD_COUNT = 4;

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

        File inputFile = new File("input.txt");

        int ceil = (((int)inputFile.length() + (CipherThread.BYTES - 1)) / CipherThread.BYTES) * CipherThread.BYTES;
        inputBuffer = ByteBuffer.allocate(ceil).array();
        encryptBuffer = new byte[inputBuffer.length];
        decryptBuffer = new byte[inputBuffer.length];

        File encryptFile = new File("encrypt.txt");
        boolean ignoredEncrypt = encryptFile.createNewFile();

        File decryptFile = new File("decrypt.txt");
        boolean ignoredDecrypt = decryptFile.createNewFile();

        try (
                FileInputStream inputStream = new FileInputStream(inputFile);
                FileOutputStream encryptStream = new FileOutputStream(encryptFile);
                FileOutputStream decryptStream = new FileOutputStream(decryptFile)
        ) {
            inputStream.readNBytes(inputBuffer, 0, inputBuffer.length);

            this.encrypt();
            this.decrypt();

            encryptStream.write(encryptBuffer);
            decryptStream.write(decryptBuffer);
        } catch (Exception e) {
            throw new Exception(e);
        }
    }

    void encrypt() throws InterruptedException {
        if (inputBuffer.length < CipherThread.BYTES * THREAD_COUNT) {
            int blockCount = inputBuffer.length / CipherThread.BYTES;

            EncryptThread thread = new EncryptThread(key, nonce, 0, blockCount, inputBuffer, encryptBuffer);
            thread.start();
            thread.join();
            return;
        }

        EncryptThread[] threads = new EncryptThread[THREAD_COUNT];
        for (int i = 0; i < THREAD_COUNT; i++) {
            int count = (inputBuffer.length / THREAD_COUNT) / CipherThread.BYTES;
            int counterStart = i * count;

            threads[i] = new EncryptThread(key, nonce, counterStart, counterStart + count, inputBuffer, encryptBuffer);
            threads[i].start();
        }

        for (int i = 0; i < THREAD_COUNT; i++) {
            threads[i].join();
        }
    }

    void decrypt() throws InterruptedException {
        if (encryptBuffer.length < CipherThread.BYTES * THREAD_COUNT) {
            int blockCount = inputBuffer.length / CipherThread.BYTES;

            DecryptThread thread = new DecryptThread(key, nonce, 0, blockCount, decryptBuffer,  encryptBuffer);
            thread.start();
            thread.join();
            return;
        }

        DecryptThread[] threads = new DecryptThread[THREAD_COUNT];
        for (int i = 0; i < THREAD_COUNT; i++) {
            int count = (inputBuffer.length / THREAD_COUNT) / CipherThread.BYTES;
            int counterStart = i * count;

            threads[i] = new DecryptThread(key, nonce, counterStart, counterStart + count, decryptBuffer,  encryptBuffer);
            threads[i].start();
        }

        for (int i = 0; i < THREAD_COUNT; i++) {
            threads[i].join();
        }
    }
}
