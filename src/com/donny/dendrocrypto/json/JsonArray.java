package com.donny.dendrocrypto.json;

import com.donny.dendrocrypto.DendroCrypto;

import java.io.FileWriter;
import java.io.IOException;
import java.util.ArrayList;
import java.util.Collection;

public class JsonArray extends JsonItem {
    private final ArrayList<JsonItem> ARRAY;

    public JsonArray() {
        super(JsonType.ARRAY);
        ARRAY = new ArrayList<>();
    }

    public JsonArray(ArrayList<? extends JsonItem> list) {
        this();
        ARRAY.addAll(list);
    }

    public JsonArray(ArrayList<? extends ExportableToJson> list, DendroCrypto curInst) {
        this();
        list.forEach(el -> {
            try {
                ARRAY.add(el.export());
            } catch (JsonFormattingException ex) {
                System.out.println("Malformed object: " + ex.getMessage());
            }
        });
    }

    public ArrayList<JsonItem> getArray() {
        return new ArrayList<>(ARRAY);
    }

    public ArrayList<JsonString> getStringArray() {
        ArrayList<JsonString> out = new ArrayList<>();
        for (JsonItem item : ARRAY) {
            out.add((JsonString) item);
        }
        return out;
    }

    public ArrayList<JsonDecimal> getDecimalArray() {
        ArrayList<JsonDecimal> out = new ArrayList<>();
        for (JsonItem item : ARRAY) {
            out.add((JsonDecimal) item);
        }
        return out;
    }

    public ArrayList<JsonBool> getBooleanArray() {
        ArrayList<JsonBool> out = new ArrayList<>();
        for (JsonItem item : ARRAY) {
            out.add((JsonBool) item);
        }
        return out;
    }

    public ArrayList<JsonArray> getArrayArray() {
        ArrayList<JsonArray> out = new ArrayList<>();
        for (JsonItem item : ARRAY) {
            out.add((JsonArray) item);
        }
        return out;
    }

    public ArrayList<JsonObject> getObjectArray() {
        ArrayList<JsonObject> out = new ArrayList<>();
        for (JsonItem item : ARRAY) {
            out.add((JsonObject) item);
        }
        return out;
    }

    public JsonItem get(int index) {
        return ARRAY.get(index);
    }

    public JsonString getString(int index) {
        return (JsonString) get(index);
    }

    public JsonDecimal getDecimal(int index) {
        return (JsonDecimal) get(index);
    }

    public JsonBool getBoolean(int index) {
        return (JsonBool) get(index);
    }

    public JsonArray getArray(int index) {
        return (JsonArray) get(index);
    }

    public JsonObject getObject(int index) {
        return (JsonObject) get(index);
    }

    public boolean add(JsonItem item) {
        return ARRAY.add(item);
    }

    public boolean addAll(Collection<? extends JsonItem> collection) {
        return ARRAY.addAll(collection);
    }

    public JsonItem remove(int index) {
        return ARRAY.remove(index);
    }

    public boolean remove(JsonItem item) {
        return ARRAY.remove(item);
    }

    public int size() {
        return ARRAY.size();
    }

    @Override
    public String toString() {
        if (!ARRAY.isEmpty()) {
            StringBuilder sb = new StringBuilder("[");
            for (JsonItem item : ARRAY) {
                sb.append(item).append(",");
            }
            sb.deleteCharAt(sb.length() - 1);
            return sb.append("]").toString();
        } else {
            return "[]";
        }
    }

    @Override
    public String print(int scope) {
        if (ARRAY.isEmpty()) {
            return "[]";
        } else {
            int internal = scope + 1;
            StringBuilder sb = new StringBuilder("[");
            for (JsonItem item : ARRAY) {
                sb.append("\n").append(indent(internal)).append(item.print(internal)).append(",");
            }
            return sb.deleteCharAt(sb.length() - 1).append("\n").append(indent(scope)).append("]").toString();
        }
    }

    @Override
    protected void stream(FileWriter writer) throws IOException {
        if (ARRAY.size() == 0) {
            writer.write("[]");
        } else {
            writer.write("[");
            int x = ARRAY.size();
            for (int i = 0; i < x; i++) {
                ARRAY.get(i).stream(writer);
                if (i < x - 1) {
                    writer.write(",");
                } else {
                    writer.write("]");
                }
            }
        }
    }
}
