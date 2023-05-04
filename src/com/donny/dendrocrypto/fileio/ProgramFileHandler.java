package com.donny.dendrocrypto.fileio;

import com.donny.dendroroot.fileio.FileHandler;
import com.donny.dendroroot.instance.Instance;
import com.donny.dendroroot.json.JsonFormattingException;
import com.donny.dendroroot.json.JsonItem;
import com.fasterxml.jackson.core.JsonFactory;

import java.io.IOException;
import java.io.InputStream;

public class ProgramFileHandler extends FileHandler {
    public ProgramFileHandler(Instance curInst) {
        super(curInst);
    }

    @Override
    public JsonItem getResource(String path) {
        try (InputStream stream = getClass().getResourceAsStream("/com/donny/dendrocrypto/resources/" + path)) {
            JsonItem item = JsonItem.digest(new JsonFactory().createParser(stream));
            CURRENT_INSTANCE.LOG_HANDLER.debug(getClass(), "Resource loaded: " + path);
            return item;
        } catch (IOException e) {
            CURRENT_INSTANCE.LOG_HANDLER.error(getClass(), "Resource not located: " + path);
            return null;
        } catch (NullPointerException e) {
            CURRENT_INSTANCE.LOG_HANDLER.error(getClass(), "No such resource: " + path);
            return null;
        } catch (JsonFormattingException e) {
            CURRENT_INSTANCE.LOG_HANDLER.error(getClass(), "Malformed resource: " + path);
            return null;
        }
    }
}
