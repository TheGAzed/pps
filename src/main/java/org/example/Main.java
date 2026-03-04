package org.example;

import org.example.parallel.CipherThread;
import org.example.parallel.DecryptThread;
import org.example.parallel.EncryptThread;
import org.example.sequential.CipherSequence;
import org.example.sequential.DecryptSequence;
import org.example.sequential.EncryptSequence;

import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.nio.ByteBuffer;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;

public class Main {
    private final int THREAD_COUNT = 2;
    private final int CEILING = THREAD_COUNT * CipherThread.BYTES;
    private static final String FILEPATH = "src/main/resources/";
    private static final long BUFFER_SIZE = 536_870_912 / 2;

    private static final String INPUT_FILE   = FILEPATH + "input.mp4";
    private static final String ENCRYPT_FILE = FILEPATH + "encrypt.mp4";
    private static final String DECRYPT_FILE = FILEPATH + "decrypt.mp4";

    private ByteBuffer[] inputBuffer;
    private ByteBuffer[] encryptBuffer;
    private ByteBuffer[] decryptBuffer;

    private SecretKey key;
    byte[] nonce = new byte[12];

    void main() throws Exception {
        //sequential();
        parallel();
    }

    void sequential() throws Exception {
        File inputFile = new File(INPUT_FILE);

        // open encrypt and decrypt files to save generated ciphers
        File encryptFile = new File(ENCRYPT_FILE);
        boolean ignoredEncrypt = encryptFile.createNewFile();

        File decryptFile = new File(DECRYPT_FILE);
        boolean ignoredDecrypt = decryptFile.createNewFile();

        // create input and output file streams to save encrypted and decrypted data into
        try (
                FileInputStream inputStream = new FileInputStream(inputFile);
                FileOutputStream encryptStream = new FileOutputStream(encryptFile);
                FileOutputStream decryptStream = new FileOutputStream(decryptFile)
        ) {
            // create key generator for AES and generate key
            // generate random nonce value to combine with counter
            keyGenerator();
            nonceGenerator();

            // create buffers and allocate memory for them
            inputBuffer = new ByteBuffer[1];
            encryptBuffer = new ByteBuffer[1];
            decryptBuffer = new ByteBuffer[1];

            int length = (int)Math.min(inputFile.length(), BUFFER_SIZE);
            int ceil = ((length + (CipherThread.BYTES - 1)) / CipherThread.BYTES) * CipherThread.BYTES;

            inputBuffer[0] = ByteBuffer.allocate(ceil);
            encryptBuffer[0] = ByteBuffer.allocate(ceil);
            decryptBuffer[0] = ByteBuffer.allocate(ceil);

            long size = ((inputFile.length() + (BUFFER_SIZE - 1)) / BUFFER_SIZE) * BUFFER_SIZE;
            for (long i = 0, remaining = inputFile.length(); i < size; i += BUFFER_SIZE, remaining -= BUFFER_SIZE) {
                int chunk = (int) Math.min(remaining, BUFFER_SIZE);

                // read into input buffer input file
                inputStream.readNBytes(inputBuffer[0].array(), 0, inputBuffer[0].array().length);

                // encrypt and write from input buffer into output encrypt buffer and file
                this.encryptSequence(ceil);
                encryptStream.write(encryptBuffer[0].array(), 0, chunk);

                // decrypt and write from encrypt buffer into output decrypt buffer and file
                this.decryptSequence(ceil);
                decryptStream.write(decryptBuffer[0].array(), 0, chunk);
            }
        } catch (Exception e) {
            throw new Exception(e);
        }
    }

    void parallel() throws Exception {
        File inputFile = new File(INPUT_FILE);

        // open encrypt and decrypt files to save generated ciphers
        File encryptFile = new File(ENCRYPT_FILE);
        boolean ignoredEncrypt = encryptFile.createNewFile();

        File decryptFile = new File(DECRYPT_FILE);
        boolean ignoredDecrypt = decryptFile.createNewFile();

        // create input and output file streams to save encrypted and decrypted data into
        try (
                FileInputStream inputStream = new FileInputStream(inputFile);
                FileOutputStream encryptStream = new FileOutputStream(encryptFile);
                FileOutputStream decryptStream = new FileOutputStream(decryptFile)
        ) {
            // create key generator for AES and generate key
            // generate random nonce value to combine with counter
            keyGenerator();
            nonceGenerator();

            // calculate ceil from length to round for counter bytes and threads
            // calculate partial lengths for each thread
            int length = (int)Math.min(inputFile.length(), BUFFER_SIZE);
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

            long size = ((inputFile.length() + (BUFFER_SIZE - 1)) / BUFFER_SIZE) * BUFFER_SIZE;
            for (long i = 0, remaining = inputFile.length(); i < size; i += BUFFER_SIZE, remaining -= BUFFER_SIZE) {
                int chunk = (int)Math.min(remaining, BUFFER_SIZE);
                //int partial = chunk / THREAD_COUNT;

                // read into input buffer input file
                for (int j = 0; j < THREAD_COUNT; j++) {
                    inputStream.readNBytes(inputBuffer[j].array(), 0, inputBuffer[j].array().length);
                }

                // encrypt and write from input buffer into output encrypt buffer and file
                // based on remaining length
                this.encryptThread(ceil);
                for (int j = 0, rem = chunk; j < THREAD_COUNT; j++, rem -= partial) {
                    encryptStream.write(encryptBuffer[j].array(), 0, Math.min(rem, partial));
                }

                // decrypt and write from encrypt buffer into output decrypt buffer and file
                // based on remaining length
                this.decryptThread(ceil);
                for (int j = 0, rem = chunk; j < THREAD_COUNT; j++, rem -= partial) {
                    decryptStream.write(decryptBuffer[j].array(), 0, Math.min(rem, partial));
                }
            }
        } catch (Exception e) {
            throw new Exception(e);
        }
    }

    private void keyGenerator() throws NoSuchAlgorithmException {
        // create key generator for AES and generate key
        KeyGenerator keyGen = KeyGenerator.getInstance("AES");
        keyGen.init(128);
        key = keyGen.generateKey();
    }

    private void nonceGenerator() {
        // generate random nonce value to combine with counter
        SecureRandom random = new SecureRandom();
        random.nextBytes(nonce);
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
        EncryptSequence sequence = new EncryptSequence(key, nonce, 0, length / CipherSequence.BYTES, inputBuffer[0].array(), encryptBuffer[0].array());
        sequence.run();
    }

    void decryptSequence(int length) {
        // create decrypt sequence and run it
        DecryptSequence sequence = new DecryptSequence(key, nonce, 0, length / CipherSequence.BYTES, decryptBuffer[0].array(), encryptBuffer[0].array());
        sequence.run();
    }
}
