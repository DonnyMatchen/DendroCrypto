package com.donny.dendrocrypto.encryption;

import java.security.InvalidParameterException;
import java.security.NoSuchAlgorithmException;

public abstract class HashHandler {
    protected int length;

    public abstract byte[] digest(byte[] input) throws NoSuchAlgorithmException;

    public byte[] truncate(byte[] input, int size) throws NoSuchAlgorithmException {
        if (length > size) {
            byte[] full = digest(input);
            byte[] out = new byte[size];
            System.arraycopy(full, 0, out, 0, size);
            return out;
        } else {
            throw new InvalidParameterException("For truncation, the truncated size must be smaller");
        }

    }
}
