package org.example.sequential;

import javax.crypto.SecretKey;

public class CipherSequence {
    public static final int BYTES = 16;

    protected final int counterStart;
    protected final int counterEnd;
    protected byte[] ciphertext;
    protected byte[] plaintext;
    protected final byte[] nonce;
    protected final SecretKey key;
    protected final javax.crypto.Cipher cipher;

    public CipherSequence(SecretKey key, byte[] nonce, int counterStart, int counterEnd, byte[] plaintext, byte[] ciphertext) {
        this.nonce = nonce;
        this.key = key;

        this.counterStart = counterStart;
        this.counterEnd = counterEnd;

        this.plaintext = plaintext;
        this.ciphertext = ciphertext;

        // initialize key cipher
        try {
            this.cipher = javax.crypto.Cipher.getInstance("AES/ECB/NoPadding");
            this.cipher.init(javax.crypto.Cipher.ENCRYPT_MODE, key);
        } catch (Exception exception) {
            throw new RuntimeException(exception);
        }
    }

    protected byte[] exclusiveOr(byte[] one, byte[] two) {
        // exclusive or two byte arrays and return result
        if (one.length != two.length) { throw new IllegalArgumentException(); }

        byte[] result = new byte[BYTES];
        /*result[0] = (byte) (one[0] ^ two[0]);
        result[1] = (byte) (one[1] ^ two[1]);
        result[2] = (byte) (one[2] ^ two[2]);
        result[3] = (byte) (one[3] ^ two[3]);
        result[4] = (byte) (one[4] ^ two[4]);
        result[5] = (byte) (one[5] ^ two[5]);
        result[6] = (byte) (one[6] ^ two[6]);
        result[7] = (byte) (one[7] ^ two[7]);
        result[8] = (byte) (one[8] ^ two[8]);
        result[9] = (byte) (one[9] ^ two[9]);
        result[10] = (byte) (one[10] ^ two[10]);
        result[11] = (byte) (one[11] ^ two[11]);
        result[12] = (byte) (one[12] ^ two[12]);
        result[13] = (byte) (one[13] ^ two[13]);
        result[14] = (byte) (one[14] ^ two[14]);
        result[15] = (byte) (one[15] ^ two[15]);*/
        for (int i = 0; i < BYTES; i++) { result[i] = (byte) (one[i] ^ two[i]); }

        return result;
    }

    protected byte[] combine(int counter) {
        // create nonce + counter combination for AES with CTR
        byte[] combineByte = new byte[BYTES];
        System.arraycopy(nonce, 0, combineByte, 0, Math.min(nonce.length, 12));
        combineByte[12] = (byte)(counter >> 24);
        combineByte[13] = (byte)(counter >> 16);
        combineByte[14] = (byte)(counter >>  8);
        combineByte[15] = (byte)(counter      );

        return combineByte;
    }
}
