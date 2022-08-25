package com.donny.dendrocrypto.encryption;

import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;

public abstract class EncryptionHandler {
    public final String ALGO;

    public EncryptionHandler(String algo) {
        ALGO = algo;
    }

    public abstract boolean keysInitiated();

    public abstract byte[] encrypt(byte[] bytes) throws NoSuchPaddingException, NoSuchAlgorithmException,
            InvalidKeyException, InvalidAlgorithmParameterException, IllegalBlockSizeException, BadPaddingException,
            KeysNotSetException;

    public abstract byte[] decrypt(byte[] bytes) throws NoSuchPaddingException, NoSuchAlgorithmException,
            InvalidKeyException, InvalidAlgorithmParameterException, IllegalBlockSizeException, BadPaddingException,
            KeysNotSetException;
}
