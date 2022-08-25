package com.donny.dendrocrypto.json;

import java.io.FileWriter;
import java.io.IOException;

public class JsonString extends JsonItem {
    private String string;

    public JsonString(String raw) throws JsonFormattingException {
        this();
        if (raw.contains("\"")) {
            raw = raw.substring(1, raw.length() - 1);
        }
        if (raw.contains("\"")) {
            throw new JsonFormattingException("Bad String: " + raw);
        }
        string = raw;
    }

    public JsonString() {
        super(JsonType.STRING);
        string = "";
    }

    public boolean setString(String cand) {
        if (!cand.contains("\"")) {
            string = cand;
            return true;
        } else {
            return false;
        }
    }

    public String getString() {
        return string;
    }

    @Override
    public String toString() {
        return "\"" + string + "\"";
    }

    @Override
    public String print(int scope) {
        return toString();
    }

    @Override
    protected void stream(FileWriter writer) throws IOException {
        writer.write('"' + string + '"');
    }
}
