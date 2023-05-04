package com.donny.dendrocrypto.encryption.symmetric;

import com.donny.dendrocrypto.DendroCrypto;
import com.donny.dendrocrypto.encryption.hash.Sha;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.util.Arrays;

public class Aes extends SKEHandler {
    private static final Sha SHA = new Sha(true);
    private final boolean HAS_IV;
    private int size;

    private SecretKeySpec key;
    private IvParameterSpec iv;

    public Aes(String mode, String padding, boolean iv) {
        super("AES/" + mode + "/" + padding);
        if (mode.equals("CBC")) {
            HAS_IV = true;
        } else if (mode.equals("EBC") || mode.equals("GCM") || mode.equals("KW") || mode.equals("KWP")) {
            HAS_IV = false;
        } else {
            HAS_IV = iv;
        }
    }

    public void changeKey(char[] newKey, int keySize) throws NoSuchAlgorithmException {
        size = keySize;
        byte[] hash = new String(newKey).getBytes(DendroCrypto.CHARSET);
        hash = SHA.digest(hash);
        byte[] rawKey = new byte[size];
        System.arraycopy(hash, 0, rawKey, 0, size);
        Arrays.fill(newKey, (char) 0);
        key = new SecretKeySpec(rawKey, "AES");
        iv = null;
    }

    public void changeKey(byte[] newKey) {
        size = newKey.length;
        byte[] rawKey = new byte[32];
        System.arraycopy(newKey, 0, rawKey, 0, 32);
        Arrays.fill(newKey, (byte) 0);
        key = new SecretKeySpec(rawKey, "AES");
        iv = null;
    }

    public void changeKey(char[] newKey, int keySize, int ivIndex) throws NoSuchAlgorithmException {
        size = keySize;
        if (ivIndex < 0 || ivIndex >= 17) {
            throw new IllegalArgumentException("IV Index out of bounds (0 - 15)");
        }
        byte[] hash = new String(newKey).getBytes(DendroCrypto.CHARSET);
        hash = SHA.digest(hash);
        byte[] rawKey = new byte[size];
        byte[] rawIv = new byte[16];
        System.arraycopy(hash, 0, rawKey, 0, size);
        System.arraycopy(hash, ivIndex, rawIv, 0, 16);
        Arrays.fill(newKey, (char) 0);
        key = new SecretKeySpec(rawKey, "AES");
        iv = new IvParameterSpec(rawIv);
    }

    public void changeKey(char[] newKey, int keySize, byte[] newIV) throws NoSuchAlgorithmException {
        size = keySize;
        byte[] hash = new String(newKey).getBytes(DendroCrypto.CHARSET);
        hash = SHA.digest(hash);
        byte[] rawKey = new byte[size];
        byte[] rawIv = new byte[16];
        System.arraycopy(hash, 0, rawKey, 0, size);
        System.arraycopy(newIV, 0, rawIv, 0, 16);
        Arrays.fill(newKey, (char) 0);
        key = new SecretKeySpec(rawKey, "AES");
        iv = new IvParameterSpec(rawIv);
    }

    public void changeKey(byte[] newKey, byte[] newIV) {
        size = newKey.length;
        byte[] rawKey = new byte[size];
        byte[] rawIv = new byte[16];
        System.arraycopy(newKey, 0, rawKey, 0, size);
        System.arraycopy(newIV, 0, rawIv, 0, 16);
        Arrays.fill(newKey, (byte) 0);
        key = new SecretKeySpec(rawKey, "AES");
        iv = new IvParameterSpec(rawIv);
    }

    @Override
    public boolean keysInitiated() {
        return key != null && (!HAS_IV || iv != null);
    }

    @Override
    public byte[] encrypt(byte[] bytes) throws NoSuchPaddingException, NoSuchAlgorithmException, InvalidKeyException,
            InvalidAlgorithmParameterException, IllegalBlockSizeException, BadPaddingException, KeysNotSetException {
        if (keysInitiated()) {
            Cipher cipher = Cipher.getInstance(ALGO);
            if (HAS_IV) {
                if (iv == null) {
                    throw new InvalidKeyException("IV required, but IV is null");
                } else {
                    cipher.init(Cipher.ENCRYPT_MODE, key, iv);
                }
            } else {
                cipher.init(Cipher.ENCRYPT_MODE, key);
            }
            return cipher.doFinal(bytes);
        }
        throw new KeysNotSetException();
    }

    @Override
    public byte[] decrypt(byte[] bytes) throws NoSuchPaddingException, NoSuchAlgorithmException, InvalidKeyException,
            InvalidAlgorithmParameterException, IllegalBlockSizeException, BadPaddingException, KeysNotSetException {
        if (keysInitiated()) {
            Cipher cipher = Cipher.getInstance(ALGO);
            if (HAS_IV) {
                if (iv == null) {
                    throw new InvalidKeyException("IV requred, but IV is null");
                } else {
                    cipher.init(Cipher.DECRYPT_MODE, key, iv);
                }
            } else {
                cipher.init(Cipher.DECRYPT_MODE, key);
            }
            return cipher.doFinal(bytes);
        }
        throw new KeysNotSetException();
    }

    @Override
    public String toString() {
        String mode = ALGO.split("/")[1];
        if (mode.equals("CBC") || mode.equals("ECB") || mode.equals("GCM") || mode.equals("KW") || mode.equals("KWP")) {
            return ALGO;
        } else {
            return ALGO + (HAS_IV ? " (IV)" : " (No IV)");
        }
    }
}
