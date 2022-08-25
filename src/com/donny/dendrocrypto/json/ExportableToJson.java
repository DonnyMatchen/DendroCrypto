package com.donny.dendrocrypto.json;

public interface ExportableToJson {
    JsonItem export() throws JsonFormattingException;
}
