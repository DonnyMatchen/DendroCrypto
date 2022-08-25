package com.donny.dendrocrypto.gui.customswing;

import com.donny.dendrocrypto.DendroCrypto;
import com.donny.dendrocrypto.json.*;

import javax.swing.*;
import javax.swing.border.Border;
import javax.swing.plaf.basic.BasicScrollBarUI;
import javax.swing.table.DefaultTableModel;
import java.awt.*;
import java.io.IOException;
import java.io.InputStream;

public class DendroFactory {
    public static final Color WRONG = new Color(100, 20, 20),
            DISABLED = new Color(75, 75, 75),
            REGULAR = new Color(55, 55, 55),
            BACKDROP = new Color(40, 40, 40),
            CONTENT = new Color(25, 25, 25),
            TEXT = new Color(0, 211, 211),
            SELECTION = new Color(0, 100, 100),
            CARET = new Color(211, 211, 211);

    public static final Border PANEL_BORDER = BorderFactory.createBevelBorder(0),
            CONTENT_BORDER = BorderFactory.createBevelBorder(1);
    public static final int SMALL_GAP = 5;
    public static final int MEDIUM_GAP = 10;
    public static final int LARGE_GAP = 15;
    public static Font unifont, verdana;

    private static void setUI(JsonArray objects) {
        for (JsonObject obj : objects.getObjectArray()) {
            for (JsonObject entry : obj.getArray("contents").getObjectArray()) {
                for (JsonObject subEntry : entry.getArray("contents").getObjectArray()) {
                    if (!subEntry.get("value").getType().equals(JsonType.NULL)) {
                        Object swatch = parse(subEntry.getString("value").getString());
                        UIManager.put(subEntry.getString("key").getString(), swatch);
                    }
                }
            }
        }
    }

    private static Object parse(String value) {
        return switch (value) {
            case "WRONG" -> WRONG;
            case "DISABLED" -> DISABLED;
            case "REGULAR" -> REGULAR;
            case "BACKDROP" -> BACKDROP;
            case "CONTENT" -> CONTENT;
            case "TEXT" -> TEXT;
            case "SELECTION" -> SELECTION;
            case "CARET" -> CARET;
            case "PANEL_BORDER" -> PANEL_BORDER;
            case "CONTENT_BORDER" -> CONTENT_BORDER;
            case "UNIFONT" -> unifont;
            case "VERDANA" -> verdana;
            default -> null;
        };
    }

    public static void init() {
        try {
            GraphicsEnvironment ge = GraphicsEnvironment.getLocalGraphicsEnvironment();
            InputStream file = DendroFactory.class.getResourceAsStream("/com/donny/dendrocrypto/resources/unifont.ttf");
            Font font = Font.createFont(Font.TRUETYPE_FONT, file).deriveFont(15f);
            ge.registerFont(font);
            file = DendroFactory.class.getResourceAsStream("/com/donny/dendrocrypto/resources/verdana.ttf");
            font = Font.createFont(Font.TRUETYPE_FONT, file).deriveFont(15f);
            ge.registerFont(font);
            unifont = new Font("Unifont", Font.PLAIN, 15);
            verdana = new Font("Verdana", Font.PLAIN, 15);
            JsonItem ui = DendroCrypto.getResource("ui.json");
            setUI((JsonArray) ui);
        } catch (FontFormatException | IOException e) {
            e.printStackTrace();
        }
    }

    public static JScrollPane getLongField() {
        JScrollPane pane = getScrollField(true, 1, 20);
        pane.setHorizontalScrollBarPolicy(ScrollPaneConstants.HORIZONTAL_SCROLLBAR_ALWAYS);
        JTextArea textArea = (JTextArea) pane.getViewport().getView();
        textArea.setLineWrap(false);
        textArea.setWrapStyleWord(false);
        return pane;
    }

    public static JScrollPane getScrollField() {
        return getScrollField(true, 5, 20);
    }

    public static JScrollPane getScrollField(boolean edit, int rows, int columns) {
        JTextArea textArea = new JTextArea();
        textArea.setRows(rows);
        textArea.setColumns(columns);
        textArea.setLineWrap(true);
        textArea.setWrapStyleWord(true);
        textArea.setEditable(edit);

        JScrollPane pane = getScrollPane(false, true);
        pane.setViewportView(textArea);
        return pane;
    }

    public static JTable getTableRaw(String[] header, Object[][] contents, boolean tableEdit) {
        JTable table = new JTable();
        table.setModel(new DefaultTableModel(contents, header) {
            @Override
            public boolean isCellEditable(int row, int column) {
                return tableEdit;
            }
        });
        table.setCellSelectionEnabled(true);
        table.setColumnSelectionAllowed(true);
        table.getTableHeader().setReorderingAllowed(false);
        table.getColumnModel().getSelectionModel().setSelectionMode(ListSelectionModel.MULTIPLE_INTERVAL_SELECTION);
        return table;
    }

    public static JScrollPane getTable(String[] header, Object[][] contents, boolean tableEdit) {
        JTable table = getTableRaw(header, contents, tableEdit);

        JScrollPane pane = getScrollPane(false, true);
        pane.setViewportView(table);
        return pane;
    }

    public static JList<String> getList(int selection) {
        JList<String> list = new JList<>(new DefaultListModel<>());
        list.setSelectionMode(selection);
        return list;
    }

    public static JList<String> getList() {
        return getList(ListSelectionModel.SINGLE_SELECTION);
    }

    public static JScrollPane getScrollPane(boolean horizontal, boolean vertical) {
        JScrollPane pane = new JScrollPane();
        pane.getVerticalScrollBar().setUI(new BasicScrollBarUI() {
            @Override
            protected void configureScrollBarColors() {
                this.thumbColor = SELECTION;
            }
        });
        pane.getHorizontalScrollBar().setUI(new BasicScrollBarUI() {
            @Override
            protected void configureScrollBarColors() {
                this.thumbColor = SELECTION;
            }
        });
        if (horizontal) {
            pane.setHorizontalScrollBarPolicy(ScrollPaneConstants.HORIZONTAL_SCROLLBAR_AS_NEEDED);
        } else {
            pane.setHorizontalScrollBarPolicy(ScrollPaneConstants.HORIZONTAL_SCROLLBAR_NEVER);
        }
        if (vertical) {
            pane.setVerticalScrollBarPolicy(ScrollPaneConstants.VERTICAL_SCROLLBAR_AS_NEEDED);
        } else {
            pane.setVerticalScrollBarPolicy(ScrollPaneConstants.VERTICAL_SCROLLBAR_NEVER);
        }
        return pane;
    }

    public static JButton getButton(String text, int padding) {
        JButton button = new JButton(text);
        button.setBorder(BorderFactory.createCompoundBorder(PANEL_BORDER, BorderFactory.createEmptyBorder(padding, padding, padding, padding)));
        return button;
    }

    public static JButton getButton(String text) {
        return getButton(text, 2);
    }
}
