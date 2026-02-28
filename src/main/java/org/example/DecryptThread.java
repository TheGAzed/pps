package org.example;

import javax.crypto.SecretKey;
import java.nio.ByteBuffer;

public class DecryptThread extends CipherThread{
    public DecryptThread(SecretKey key, byte[] nonce, int counterStart, int counterEnd, byte[] plaintext, byte[] ciphertext) {
        super(key, nonce, counterStart, counterEnd, plaintext, ciphertext);
    }

    @Override
    public void run() {
        try {
            byte[] cipherByte = ByteBuffer.allocate(BYTES).array();
            for (int i = counterStart; i < counterEnd; i++) {
                byte[] encryptByte = cipher.doFinal(combine(i));

                int start = i * BYTES;
                System.arraycopy(ciphertext, start, cipherByte, 0, cipherByte.length);

                byte[] plainByte = this.exclusiveOr(cipherByte, encryptByte);
                System.arraycopy(plainByte, 0, plaintext, start, plainByte.length);
            }
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }
}
