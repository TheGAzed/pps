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
                byte[] encryptByte = cipher.doFinal(combine(i));

                int start = index * BYTES;
                System.arraycopy(plaintext, start, plainByte, 0, plainByte.length);

                byte[] cipherByte = this.exclusiveOr(plainByte, encryptByte);
                System.arraycopy(cipherByte, 0, ciphertext, start, cipherByte.length);
            }
        } catch (Exception exception) {
            throw new RuntimeException(exception);
        }
    }
}
