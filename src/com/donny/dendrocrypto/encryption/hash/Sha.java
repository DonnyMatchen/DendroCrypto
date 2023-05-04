package com.donny.dendrocrypto.encryption.hash;

import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;

public class Sha extends HashHandler {
    public Sha(boolean twoFiftySix) {
        if (twoFiftySix) {
            length = 256;
        } else {
            length = 512;
        }
    }

    @Override
    public byte[] digest(byte[] input) throws NoSuchAlgorithmException {
        MessageDigest hash = MessageDigest.getInstance("SHA-" + length);
        return hash.digest(input);
    }
}
