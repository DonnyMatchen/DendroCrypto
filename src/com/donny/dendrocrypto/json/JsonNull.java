package com.donny.dendrocrypto.json;

import java.io.FileWriter;
import java.io.IOException;

public class JsonNull extends JsonItem {
    public JsonNull() {
        super(JsonType.NULL);
    }

    @Override
    public String toString() {
        return "null";
    }

    @Override
    public String print(int scope) {
        return toString();
    }

    @Override
    protected void stream(FileWriter writer) throws IOException {
        writer.write("null");
    }
}
