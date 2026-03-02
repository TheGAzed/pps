package org.example.parallel;

import javax.crypto.Cipher;
import javax.crypto.SecretKey;

public abstract class CipherThread extends Thread {
    public static final int BYTES = 16;

    protected final int counterStart;
    protected final int counterEnd;
    protected byte[] ciphertext;
    protected byte[] plaintext;
    protected final byte[] nonce;
    protected final SecretKey key;
    protected final Cipher cipher;

    public CipherThread(SecretKey key, byte[] nonce, int counterStart, int counterEnd, byte[] plaintext, byte[] ciphertext) {
        this.nonce = nonce;
        this.key = key;

        this.counterStart = counterStart;
        this.counterEnd = counterEnd;

        this.plaintext = plaintext;
        this.ciphertext = ciphertext;

        try {
            this.cipher = Cipher.getInstance("AES/ECB/NoPadding");
            this.cipher.init(Cipher.ENCRYPT_MODE, key);
        } catch (Exception exception) {
            throw new RuntimeException(exception);
        }
    }

    protected byte[] exclusiveOr(byte[] one, byte[] two) {
        if (one.length != two.length) { throw new IllegalArgumentException(); }

        byte[] result = new byte[BYTES];
        for (int i = 0; i < one.length; i++) {
            result[i] = (byte) (one[i] ^ two[i]);
        }

        return result;
    }

    protected byte[] combine(int counter) {
        byte[] combineByte = new byte[BYTES];
        System.arraycopy(nonce, 0, combineByte, 0, Math.min(nonce.length, 12));
        combineByte[12] = (byte)(counter >> 24);
        combineByte[13] = (byte)(counter >> 16);
        combineByte[14] = (byte)(counter >>  8);
        combineByte[15] = (byte)(counter      );

        return combineByte;
    }
}
