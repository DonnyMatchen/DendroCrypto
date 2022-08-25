package com.donny.dendrocrypto.json;

import java.io.FileWriter;
import java.io.IOException;

public class JsonBool extends JsonItem {
    public boolean bool;

    public JsonBool(String raw) {
        this(raw.equalsIgnoreCase("true"));
    }

    public JsonBool(boolean bool) {
        super(JsonType.BOOL);
        this.bool = bool;
    }

    public boolean getBool() {
        return bool;
    }

    public void setBool(boolean bool) {
        this.bool = bool;
    }

    @Override
    public String toString() {
        return "" + bool;
    }

    @Override
    public String print(int scope) {
        return toString();
    }

    @Override
    protected void stream(FileWriter writer) throws IOException {
        if (bool) {
            writer.write("true");
        } else {
            writer.write("false");
        }
    }
}
