package org.example;

import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import java.nio.ByteBuffer;

public class DecryptThread extends CipherThread{
    public DecryptThread(SecretKey key, byte[] nonce, int counterStart, int counterEnd, byte[] plaintext, byte[] ciphertext) {
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
                byte[] cipherByte = ByteBuffer.allocate(BYTES).array();
                System.arraycopy(ciphertext, start, cipherByte, 0, cipherByte.length);

                byte[] plainByte = this.exclusiveOr(cipherByte, encryptByte);
                System.arraycopy(plainByte, 0, plaintext, start, plainByte.length);
            }
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }
}
