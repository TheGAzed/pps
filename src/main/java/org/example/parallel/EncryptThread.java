package org.example.parallel;

import javax.crypto.SecretKey;

public class EncryptThread extends CipherThread {
    public EncryptThread(SecretKey key, byte[] nonce, int counterStart, int counterEnd, byte[] plaintext, byte[] ciphertext) {
        super(key, nonce, counterStart, counterEnd, plaintext, ciphertext);
    }

    @Override
    public void run() {
        try {
            byte[] plainByte = new byte[BYTES];
            for (int i = counterStart, index = 0; i < counterEnd; i++, index++) {
                // encipher (nonce + counter) combination with key
                byte[] encryptByte = cipher.doFinal(combine(i));

                // copy cipher text into cipher bytes array
                int start = index * BYTES;
                System.arraycopy(plaintext, start, plainByte, 0, plainByte.length);

                // XOR cipher and bytes with encrypted bytes chunk
                byte[] cipherByte = this.exclusiveOr(plainByte, encryptByte);
                // copy plain bytes array into plain text
                System.arraycopy(cipherByte, 0, ciphertext, start, cipherByte.length);
            }
        } catch (Exception exception) {
            throw new RuntimeException(exception);
        }
    }
}
