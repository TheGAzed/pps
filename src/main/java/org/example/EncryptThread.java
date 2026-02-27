package org.example;

import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import java.nio.ByteBuffer;

public class EncryptThread extends CipherThread {
    public EncryptThread(SecretKey key, byte[] nonce, int counterStart, int counterEnd, byte[] plaintext, byte[] ciphertext) {
        super(key, nonce, counterStart, counterEnd, plaintext, ciphertext);
    }

    @Override
    public void run() {
        try {
            Cipher encrypt = Cipher.getInstance("AES/ECB/NoPadding");
            encrypt.init(Cipher.ENCRYPT_MODE, key);

            for (int i = counterStart; i < counterEnd; i++) {
                byte[] encryptByte = encrypt.doFinal(combine(i));

                int start = i * BYTES;
                byte[] plainByte = ByteBuffer.allocate(BYTES).array();
                System.arraycopy(plaintext, start, plainByte, 0, plainByte.length);

                byte[] cipherByte = this.exclusiveOr(plainByte, encryptByte);
                System.arraycopy(cipherByte, 0, ciphertext, start, cipherByte.length);
            }
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }
}
