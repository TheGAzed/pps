package org.example;

import org.example.parallel.CipherThread;
import org.example.parallel.DecryptThread;
import org.example.parallel.EncryptThread;
import org.example.sequential.DecryptSequence;
import org.example.sequential.EncryptSequence;

import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.nio.ByteBuffer;
import java.security.SecureRandom;

public class Main {
    private final int THREAD_COUNT = 16;
    private final int CEILING = THREAD_COUNT * CipherThread.BYTES;
    private static final String FILEPATH = "src/main/resources";

    private ByteBuffer[] inputBuffer;
    private ByteBuffer[] encryptBuffer;
    private ByteBuffer[] decryptBuffer;

    private SecretKey key;
    byte[] nonce = new byte[12];

    void main() throws Exception {
        parallel();
        sequential();
    }

    void sequential() throws Exception {
        KeyGenerator keyGen = KeyGenerator.getInstance("AES");
        keyGen.init(128);
        key = keyGen.generateKey();

        SecureRandom random = new SecureRandom();
        random.nextBytes(nonce);

        File inputFile = new File(FILEPATH + "/input.mp4");

        int length = (int)inputFile.length();
        int ceil = ((length + (CEILING - 1)) / CEILING) * CEILING;

        inputBuffer = new ByteBuffer[1];
        encryptBuffer = new ByteBuffer[1];
        decryptBuffer = new ByteBuffer[1];

        inputBuffer[0] = ByteBuffer.allocate(ceil);
        encryptBuffer[0] = ByteBuffer.allocate(ceil);
        decryptBuffer[0] = ByteBuffer.allocate(ceil);

        File encryptFile = new File(FILEPATH + "/encrypt.mp4");
        boolean ignoredEncrypt = encryptFile.createNewFile();

        File decryptFile = new File(FILEPATH + "/decrypt.mp4");
        boolean ignoredDecrypt = decryptFile.createNewFile();

        try (
                FileInputStream inputStream = new FileInputStream(inputFile);
                FileOutputStream encryptStream = new FileOutputStream(encryptFile);
                FileOutputStream decryptStream = new FileOutputStream(decryptFile)
        ) {
            for (int i = 0; i < THREAD_COUNT; i++) {
                inputStream.readNBytes(inputBuffer[i].array(), 0, inputBuffer[i].array().length);
            }

            this.encryptSequence(ceil);
            encryptStream.write(encryptBuffer[0].array(), 0, length);

            this.decryptSequence(ceil);
            decryptStream.write(decryptBuffer[0].array(), 0, length);
        } catch (Exception e) {
            throw new Exception(e);
        }
    }

    void parallel() throws Exception {
        KeyGenerator keyGen = KeyGenerator.getInstance("AES");
        keyGen.init(128);
        key = keyGen.generateKey();

        SecureRandom random = new SecureRandom();
        random.nextBytes(nonce);

        File inputFile = new File(FILEPATH + "/input.mp4");

        int length = (int)inputFile.length();
        int ceil = ((length + (CEILING - 1)) / CEILING) * CEILING;
        int partial = ceil / THREAD_COUNT;

        inputBuffer = new ByteBuffer[THREAD_COUNT];
        encryptBuffer = new ByteBuffer[THREAD_COUNT];
        decryptBuffer = new ByteBuffer[THREAD_COUNT];
        for (int i = 0; i < THREAD_COUNT; i++) {
            inputBuffer[i] = ByteBuffer.allocate(partial);
            encryptBuffer[i] = ByteBuffer.allocate(partial);
            decryptBuffer[i] = ByteBuffer.allocate(partial);
        }

        File encryptFile = new File(FILEPATH + "/encrypt.mp4");
        boolean ignoredEncrypt = encryptFile.createNewFile();

        File decryptFile = new File(FILEPATH + "/decrypt.mp4");
        boolean ignoredDecrypt = decryptFile.createNewFile();

        try (
                FileInputStream inputStream = new FileInputStream(inputFile);
                FileOutputStream encryptStream = new FileOutputStream(encryptFile);
                FileOutputStream decryptStream = new FileOutputStream(decryptFile)
        ) {
            for (int i = 0; i < THREAD_COUNT; i++) {
                inputStream.readNBytes(inputBuffer[i].array(), 0, inputBuffer[i].array().length);
            }

            this.encryptThread(ceil);
            int remaining = length;
            for (int i = 0; i < THREAD_COUNT; i++, remaining -= partial) {
                encryptStream.write(encryptBuffer[i].array(), 0, Math.min(remaining, partial));
            }

            this.decryptThread(ceil);
            remaining = length;
            for (int i = 0; i < THREAD_COUNT; i++, remaining -= partial) {
                decryptStream.write(decryptBuffer[i].array(), 0, Math.min(remaining, partial));
            }
        } catch (Exception e) {
            throw new Exception(e);
        }
    }

    void encryptThread(int length) throws InterruptedException {
        EncryptThread[] threads = new EncryptThread[THREAD_COUNT];
        for (int i = 0; i < THREAD_COUNT; i++) {
            int count = length / CEILING;
            int counterStart = i * count;

            threads[i] = new EncryptThread(key, nonce, counterStart, counterStart + count, inputBuffer[i].array(), encryptBuffer[i].array());
            threads[i].start();
        }

        for (int i = 0; i < THREAD_COUNT; i++) {
            threads[i].join();
        }
    }

    void decryptThread(int length) throws InterruptedException {
        DecryptThread[] threads = new DecryptThread[THREAD_COUNT];
        for (int i = 0; i < THREAD_COUNT; i++) {
            int count = length / CEILING;
            int counterStart = i * count;

            threads[i] = new DecryptThread(key, nonce, counterStart, counterStart + count, decryptBuffer[i].array(), encryptBuffer[i].array());
            threads[i].start();
        }

        for (int i = 0; i < THREAD_COUNT; i++) {
            threads[i].join();
        }
    }

    void encryptSequence(int length) {
        EncryptSequence sequence = new EncryptSequence(key, nonce, 0, length / CEILING, inputBuffer[0].array(), encryptBuffer[0].array());
        sequence.run();
    }

    void decryptSequence(int length) {
        DecryptSequence sequence = new DecryptSequence(key, nonce, 0, length / CEILING, decryptBuffer[0].array(), encryptBuffer[0].array());
        sequence.run();
    }
}
