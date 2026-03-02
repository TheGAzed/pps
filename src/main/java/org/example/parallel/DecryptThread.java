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
                byte[] encryptByte = cipher.doFinal(combine(i));

                int start = index * BYTES;
                System.arraycopy(ciphertext, start, cipherByte, 0, cipherByte.length);

                byte[] plainByte = this.exclusiveOr(cipherByte, encryptByte);
                System.arraycopy(plainByte, 0, plaintext, start, plainByte.length);
            }
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }
}
