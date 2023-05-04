package com.donny.dendrocrypto;

import com.donny.dendrocrypto.encryption.symmetric.Aes;
import com.donny.dendrocrypto.fileio.ProgramFileHandler;
import com.donny.dendrocrypto.gui.ProgramMainGui;
import com.donny.dendroecc.crypto.DefinedCurve;
import com.donny.dendroecc.crypto.Registry;
import com.donny.dendroecc.curves.*;
import com.donny.dendroecc.util.Loader;
import com.donny.dendroroot.data.LogHandler;
import com.donny.dendroroot.gui.customswing.DendroFactory;
import com.donny.dendroroot.instance.Instance;
import com.donny.dendroroot.json.JsonArray;
import com.donny.dendroroot.json.JsonObject;

import java.io.File;
import java.nio.charset.Charset;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Comparator;

public class DendroCrypto {
    public static final Charset CHARSET = StandardCharsets.UTF_8;
    public static final ArrayList<Aes> AES_IV = new ArrayList<>(), AES_NO_IV = new ArrayList<>();
    public static final ArrayList<String> WEIERSTRASS_PRIME = new ArrayList<>(),
            WEIERSTRASS_BINARY = new ArrayList<>(),
            TWISTED_EDWARDS = new ArrayList<>(),
            MONTGOMERY = new ArrayList<>(),
            EDWARDS = new ArrayList<>();
    public static ProgramFileHandler fileHandler;

    public static void main(String[] args) {
        Instance curInst = new Instance("Singleton", args) {
            @Override
            public void save() {
            }
        };
        curInst.log = true;
        curInst.logLevel = new LogHandler.LogLevel("info");
        File logsFolder = new File(curInst.data.getAbsoluteFile() + File.separator + "Logs");
        if (!new File(curInst.data.getAbsoluteFile() + File.separator + "Logs").exists()) {
            logsFolder.mkdir();
        }
        fileHandler = new ProgramFileHandler(curInst);
        JsonArray aes = (JsonArray) fileHandler.getResource("aes.json");
        for (JsonObject mode : aes.getObjectArray()) {
            if (mode.getString("flag").getString().contains("I")) {
                AES_IV.add(new Aes(mode.getString("name").getString(), "NoPadding", true));
            }
            if (mode.getString("flag").getString().contains("N")) {
                AES_NO_IV.add(new Aes(mode.getString("name").getString(), "NoPadding", false));
            }
            if (mode.getString("flag").getString().contains("P")) {
                if (mode.getString("flag").getString().contains("I")) {
                    AES_IV.add(new Aes(mode.getString("name").getString(), "PKCS5Padding", true));
                }
                if (mode.getString("flag").getString().contains("N")) {
                    AES_NO_IV.add(new Aes(mode.getString("name").getString(), "PKCS5Padding", false));
                }
            }
        }
        Loader loader = new Loader(curInst);
        loader.loadStandardCurves();
        for (String key : Registry.listKeys()) {
            DefinedCurve params = Registry.get(key);
            if (params.E instanceof WeierstrassPrime) {
                WEIERSTRASS_PRIME.add(key);
            }
            if (params.E instanceof WeierstrassBinary) {
                WEIERSTRASS_BINARY.add(key);
            }
            if (params.E instanceof TwistedEdwards) {
                TWISTED_EDWARDS.add(key);
            }
            if (params.E instanceof Montgomery) {
                MONTGOMERY.add(key);
            }
            if (params.E instanceof Edwards) {
                EDWARDS.add(key);
            }
        }
        WEIERSTRASS_PRIME.sort(Comparator.naturalOrder());
        WEIERSTRASS_BINARY.sort(Comparator.naturalOrder());
        TWISTED_EDWARDS.sort(Comparator.naturalOrder());
        MONTGOMERY.sort(Comparator.naturalOrder());
        EDWARDS.sort(Comparator.naturalOrder());
        DendroFactory.init(curInst);
        new ProgramMainGui(curInst).setVisible(true);
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
}
