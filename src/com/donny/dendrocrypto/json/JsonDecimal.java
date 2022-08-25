package com.donny.dendrocrypto.json;

import java.io.FileWriter;
import java.io.IOException;
import java.math.BigDecimal;

public class JsonDecimal extends JsonItem {
    public BigDecimal decimal;

    public JsonDecimal(String raw) throws JsonFormattingException {
        super(JsonType.DECIMAL);
        try {
            decimal = new BigDecimal(raw);
        } catch (NumberFormatException | ArithmeticException ex) {
            throw new JsonFormattingException("Bad Number: " + raw);
        }
    }

    public JsonDecimal(BigDecimal dec) {
        super(JsonType.DECIMAL);
        decimal = dec;
    }

    public JsonDecimal(long l) {
        this(BigDecimal.valueOf(l));
    }

    public JsonDecimal(int i) {
        this(BigDecimal.valueOf(i));
    }

    public JsonDecimal(double d) {
        this(BigDecimal.valueOf(d));
    }

    public JsonDecimal(float f) {
        this(BigDecimal.valueOf(f));
    }

    public JsonDecimal(short s) {
        this(BigDecimal.valueOf(s));
    }

    public JsonDecimal(byte b) {
        this(BigDecimal.valueOf(b));
    }

    public JsonDecimal() {
        this(BigDecimal.ZERO);
    }

    @Override
    public String toString() {
        return decimal.toString();
    }

    @Override
    public String print(int scope) {
        return toString();
    }

    @Override
    protected void stream(FileWriter writer) throws IOException {
        writer.write(decimal.toString());
    }
}
