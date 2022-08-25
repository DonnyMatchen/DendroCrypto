package com.donny.dendrocrypto;

import com.donny.dendrocrypto.encryption.AesEH;
import com.donny.dendrocrypto.gui.MainGui;
import com.donny.dendrocrypto.gui.customswing.DendroFactory;
import com.donny.dendrocrypto.json.JsonArray;
import com.donny.dendrocrypto.json.JsonFormattingException;
import com.donny.dendrocrypto.json.JsonItem;
import com.donny.dendrocrypto.json.JsonObject;
import com.fasterxml.jackson.core.JsonFactory;

import java.io.IOException;
import java.io.InputStream;
import java.nio.charset.Charset;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;

public class DendroCrypto {
    public static final Charset CHARSET = StandardCharsets.UTF_8;
    public static final ArrayList<AesEH> AES_IV = new ArrayList<>(), AES_NO_IV = new ArrayList<>();

    public static void main(String[] args) {
        JsonArray aes = (JsonArray) getResource("aes.json");
        for (JsonObject mode : aes.getObjectArray()) {
            if (mode.getString("flag").getString().contains("I")) {
                AES_IV.add(new AesEH(mode.getString("name").getString(), "NoPadding", true));
            }
            if (mode.getString("flag").getString().contains("N")) {
                AES_NO_IV.add(new AesEH(mode.getString("name").getString(), "NoPadding", false));
            }
            if (mode.getString("flag").getString().contains("P")) {
                if (mode.getString("flag").getString().contains("I")) {
                    AES_IV.add(new AesEH(mode.getString("name").getString(), "PKCS5Padding", true));
                }
                if (mode.getString("flag").getString().contains("N")) {
                    AES_NO_IV.add(new AesEH(mode.getString("name").getString(), "PKCS5Padding", false));
                }
            }
        }
        DendroFactory.init();
        new MainGui().setVisible(true);
    }

    public static String toHexString(byte[] bytes) {
        StringBuilder builder = new StringBuilder();
        for (byte byt : bytes) {
            if (Byte.toUnsignedInt(byt) < 16) {
                builder.append("0").append(Integer.toHexString(Byte.toUnsignedInt(byt)));
            } else {
                builder.append(Integer.toHexString(Byte.toUnsignedInt(byt)));
            }
        }
        return builder.toString().toUpperCase();
    }

    public static JsonItem getResource(String path) {
        try (InputStream stream = DendroCrypto.class.getResourceAsStream("/com/donny/dendrocrypto/resources/" + path)) {
            JsonItem item = JsonItem.digest(new JsonFactory().createParser(stream));
            System.out.println("Resource loaded: " + path);
            return item;
        } catch (IOException e) {
            System.out.println("Resource not located: " + path);
            return null;
        } catch (NullPointerException e) {
            System.out.println("No such resource: " + path);
            return null;
        } catch (JsonFormattingException e) {
            System.out.println("Malformed resource: " + path);
            return null;
        }
    }
}
