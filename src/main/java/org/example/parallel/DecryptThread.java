package org.example.parallel;

import javax.crypto.SecretKey;

public class DecryptThread extends CipherThread{
    public DecryptThread(SecretKey key, byte[] nonce, int counterStart, int counterEnd, byte[] plaintext, byte[] ciphertext) {
        super(key, nonce, counterStart, counterEnd, plaintext, ciphertext);
    }

    @Override
    public void run() {
        try {
            byte[] cipherByte = new byte[BYTES];
            for (int i = counterStart, index = 0; i < counterEnd; i++, index++) {
                // encipher (nonce + counter) combination with key
                byte[] encryptByte = cipher.doFinal(combine(i));

                // copy cipher text into cipher bytes array
                int start = index * BYTES;
                System.arraycopy(ciphertext, start, cipherByte, 0, cipherByte.length);

                // XOR cipher and bytes with encrypted bytes chunk
                byte[] plainByte = this.exclusiveOr(cipherByte, encryptByte);
                // copy plain bytes array into plain text
                System.arraycopy(plainByte, 0, plaintext, start, plainByte.length);
            }
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }
}
