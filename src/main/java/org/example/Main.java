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
    private final int THREAD_COUNT = 2;
    private final int CEILING = THREAD_COUNT * CipherThread.BYTES;
    private static final String FILEPATH = "src/main/resources";

    private ByteBuffer[] inputBuffer;
    private ByteBuffer[] encryptBuffer;
    private ByteBuffer[] decryptBuffer;

    private SecretKey key;
    byte[] nonce = new byte[12];

    void main() throws Exception {
        parallel();
        //sequential();
    }

    void sequential() throws Exception {
        // create key generator for AES and generate key
        KeyGenerator keyGen = KeyGenerator.getInstance("AES");
        keyGen.init(128);
        key = keyGen.generateKey();

        // generate random nonce value to combine with counter
        SecureRandom random = new SecureRandom();
        random.nextBytes(nonce);

        File inputFile = new File(FILEPATH + "/input.bmp");

        // calculate ceil from length to round for counter bytes and threads
        int length = (int)inputFile.length();
        int ceil = ((length + (CEILING - 1)) / CEILING) * CEILING;

        // create buffers and allocate memory for them
        inputBuffer = new ByteBuffer[1];
        encryptBuffer = new ByteBuffer[1];
        decryptBuffer = new ByteBuffer[1];

        inputBuffer[0] = ByteBuffer.allocate(ceil);
        encryptBuffer[0] = ByteBuffer.allocate(ceil);
        decryptBuffer[0] = ByteBuffer.allocate(ceil);

        // open encrypt and decrypt files to save generated ciphers
        File encryptFile = new File(FILEPATH + "/encrypt.bmp");
        boolean ignoredEncrypt = encryptFile.createNewFile();

        File decryptFile = new File(FILEPATH + "/decrypt.bmp");
        boolean ignoredDecrypt = decryptFile.createNewFile();

        // create input and output file streams to save encrypted and decrypted data into
        try (
                FileInputStream inputStream = new FileInputStream(inputFile);
                FileOutputStream encryptStream = new FileOutputStream(encryptFile);
                FileOutputStream decryptStream = new FileOutputStream(decryptFile)
        ) {
            // read into input buffer input file
            inputStream.readNBytes(inputBuffer[0].array(), 0, inputBuffer[0].array().length);

            // encrypt and write from input buffer into output encrypt buffer and file
            this.encryptSequence(ceil);
            encryptStream.write(encryptBuffer[0].array(), 0, length);

            // decrypt and write from encrypt buffer into output decrypt buffer and file
            this.decryptSequence(ceil);
            decryptStream.write(decryptBuffer[0].array(), 0, length);
        } catch (Exception e) {
            throw new Exception(e);
        }
    }

    void parallel() throws Exception {
        // create key generator for AES and generate key
        KeyGenerator keyGen = KeyGenerator.getInstance("AES");
        keyGen.init(128);
        key = keyGen.generateKey();

        // generate random nonce value to combine with counter
        SecureRandom random = new SecureRandom();
        random.nextBytes(nonce);

        File inputFile = new File(FILEPATH + "/input.bmp");

        // calculate ceil from length to round for counter bytes and threads
        // calculate partial lengths for each thread
        int length = (int)inputFile.length();
        int ceil = ((length + (CEILING - 1)) / CEILING) * CEILING;
        int partial = ceil / THREAD_COUNT;

        // create buffers and allocate memory for them
        inputBuffer = new ByteBuffer[THREAD_COUNT];
        encryptBuffer = new ByteBuffer[THREAD_COUNT];
        decryptBuffer = new ByteBuffer[THREAD_COUNT];
        for (int i = 0; i < THREAD_COUNT; i++) {
            inputBuffer[i] = ByteBuffer.allocate(partial);
            encryptBuffer[i] = ByteBuffer.allocate(partial);
            decryptBuffer[i] = ByteBuffer.allocate(partial);
        }

        // open encrypt and decrypt files to save generated ciphers
        File encryptFile = new File(FILEPATH + "/encrypt.bmp");
        boolean ignoredEncrypt = encryptFile.createNewFile();

        File decryptFile = new File(FILEPATH + "/decrypt.bmp");
        boolean ignoredDecrypt = decryptFile.createNewFile();

        // create input and output file streams to save encrypted and decrypted data into
        try (
                FileInputStream inputStream = new FileInputStream(inputFile);
                FileOutputStream encryptStream = new FileOutputStream(encryptFile);
                FileOutputStream decryptStream = new FileOutputStream(decryptFile)
        ) {
            // read into input buffer input file
            for (int i = 0; i < THREAD_COUNT; i++) {
                inputStream.readNBytes(inputBuffer[i].array(), 0, inputBuffer[i].array().length);
            }

            // encrypt and write from input buffer into output encrypt buffer and file
            // based on remaining length
            this.encryptThread(ceil);
            int remaining = length;
            for (int i = 0; i < THREAD_COUNT; i++, remaining -= partial) {
                encryptStream.write(encryptBuffer[i].array(), 0, Math.min(remaining, partial));
            }

            // decrypt and write from encrypt buffer into output decrypt buffer and file
            // based on remaining length
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
        // make encrypt threads array and create new threads
        EncryptThread[] threads = new EncryptThread[THREAD_COUNT];
        for (int i = 0; i < THREAD_COUNT; i++) {
            int count = length / CEILING;
            int counterStart = i * count;

            threads[i] = new EncryptThread(key, nonce, counterStart, counterStart + count, inputBuffer[i].array(), encryptBuffer[i].array());
            threads[i].start();
        }

        // join threads into main to prevent program termination before finish
        for (int i = 0; i < THREAD_COUNT; i++) {
            threads[i].join();
        }
    }

    void decryptThread(int length) throws InterruptedException {
        // make decrypt threads array and create new threads
        DecryptThread[] threads = new DecryptThread[THREAD_COUNT];
        for (int i = 0; i < THREAD_COUNT; i++) {
            int count = length / CEILING;
            int counterStart = i * count;

            threads[i] = new DecryptThread(key, nonce, counterStart, counterStart + count, decryptBuffer[i].array(), encryptBuffer[i].array());
            threads[i].start();
        }

        // join threads into main to prevent program termination before finish
        for (int i = 0; i < THREAD_COUNT; i++) {
            threads[i].join();
        }
    }

    void encryptSequence(int length) {
        // create encrypt sequence and run it
        EncryptSequence sequence = new EncryptSequence(key, nonce, 0, length / CEILING, inputBuffer[0].array(), encryptBuffer[0].array());
        sequence.run();
    }

    void decryptSequence(int length) {
        // create decrypt sequence and run it
        DecryptSequence sequence = new DecryptSequence(key, nonce, 0, length / CEILING, decryptBuffer[0].array(), encryptBuffer[0].array());
        sequence.run();
    }
}
