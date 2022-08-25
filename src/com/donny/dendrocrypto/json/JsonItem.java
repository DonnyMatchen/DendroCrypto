package com.donny.dendrocrypto.json;

import com.fasterxml.jackson.core.JsonFactory;
import com.fasterxml.jackson.core.JsonParseException;
import com.fasterxml.jackson.core.JsonParser;
import com.fasterxml.jackson.core.JsonToken;

import java.io.*;

public abstract class JsonItem implements Serializable {
    public final JsonType TYPE;

    public JsonItem(JsonType type) {
        TYPE = type;
    }

    public static JsonItem digest(JsonParser parser) throws JsonFormattingException {
        try {
            JsonToken token = parser.nextToken();
            if (token == null) {
                return null;
            } else {
                switch (token) {
                    case END_ARRAY -> {
                        return null;
                    }
                    case START_OBJECT -> {
                        JsonObject object = new JsonObject();
                        boolean flag = true;
                        while (flag) {
                            JsonToken field = parser.nextToken();
                            if (field == JsonToken.END_OBJECT) {
                                flag = false;
                            } else {
                                if (field != JsonToken.FIELD_NAME || parser.getCurrentName() == null) {
                                    throw new JsonFormattingException("Malformed Object");
                                }
                                object.put(parser.getCurrentName(), JsonItem.digest(parser));
                            }
                        }
                        return object;
                    }
                    case START_ARRAY -> {
                        JsonArray array = new JsonArray();
                        boolean flag = true;
                        while (flag) {
                            JsonItem item = JsonItem.digest(parser);
                            if (item == null) {
                                flag = false;
                            } else {
                                array.add(item);
                            }
                        }
                        return array;
                    }
                    case VALUE_NULL, NOT_AVAILABLE, END_OBJECT, FIELD_NAME -> {
                        return new JsonNull();
                    }
                    case VALUE_TRUE -> {
                        return new JsonBool(true);
                    }
                    case VALUE_FALSE -> {
                        return new JsonBool(false);
                    }
                    case VALUE_NUMBER_FLOAT, VALUE_NUMBER_INT -> {
                        return new JsonDecimal(parser.getDecimalValue());
                    }
                    case VALUE_STRING -> {
                        return new JsonString(parser.getValueAsString());
                    }
                    default -> throw new UnsupportedOperationException();
                }
            }
        } catch (JsonParseException e) {
            e.printStackTrace();
            return null;
        } catch (IOException e) {
            return null;
        }
    }

    public static JsonItem digest(String jsonString) throws JsonFormattingException {
        try {
            return digest(new JsonFactory().createParser(jsonString));
        } catch (IOException e) {
            return null;
        }
    }

    public JsonType getType() {
        return TYPE;
    }

    public String print() {
        return print(0);
    }

    public abstract String print(int scope);

    protected String indent(int scope) {
        if (scope == 0) {
            return "";
        } else {
            return " ".repeat(2 * scope);
        }
    }

    protected abstract void stream(FileWriter writer) throws IOException;

    public static void save(JsonItem item, FileWriter writer) throws IOException {
        item.stream(writer);
    }
}
