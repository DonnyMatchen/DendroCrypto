package com.donny.dendrocrypto.json;

public enum JsonType {
    ARRAY, BOOL, DECIMAL, OBJECT, STRING, NULL;

    @Override
    public String toString() {
        return switch (this) {
            case ARRAY -> "Array";
            case BOOL -> "Boolean";
            case DECIMAL -> "Decimal";
            case OBJECT -> "Object";
            case STRING -> "String";
            case NULL -> "Null";
        };
    }
}
