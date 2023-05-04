package com.donny.dendrocrypto.gui.customswing;

import com.donny.dendroroot.gui.customswing.DendroFactory;

import javax.swing.*;
import javax.swing.text.DefaultFormatterFactory;
import javax.swing.text.MaskFormatter;
import java.text.ParseException;

public class HexField extends JPanel {
    public final JFormattedTextField FORMATTED;
    private int fieldSize;

    public HexField(String title, int fieldSize, int min) {
        super();

        this.fieldSize = fieldSize;

        //draw gui
        {
            setBorder(null);
            JLabel a = new JLabel(title);
            FORMATTED = new javax.swing.JFormattedTextField();
            JScrollPane pane = DendroFactory.getScrollPane(true, false);
            pane.setHorizontalScrollBarPolicy(ScrollPaneConstants.HORIZONTAL_SCROLLBAR_ALWAYS);
            pane.setViewportView(FORMATTED);
            try {
                FORMATTED.setFormatterFactory(new DefaultFormatterFactory(new MaskFormatter(getFormat(fieldSize))));
            } catch (ParseException e) {
            }
            //group layout
            {
                GroupLayout main = new GroupLayout(this);
                setLayout(main);
                main.setHorizontalGroup(
                        main.createSequentialGroup().addComponent(
                                a, GroupLayout.PREFERRED_SIZE, GroupLayout.PREFERRED_SIZE, GroupLayout.PREFERRED_SIZE
                        ).addGap(DendroFactory.SMALL_GAP).addComponent(
                                pane, min, min, Short.MAX_VALUE
                        )
                );
                main.setVerticalGroup(
                        main.createParallelGroup(GroupLayout.Alignment.LEADING).addComponent(
                                a, GroupLayout.PREFERRED_SIZE, GroupLayout.PREFERRED_SIZE, GroupLayout.PREFERRED_SIZE
                        ).addComponent(
                                pane, GroupLayout.PREFERRED_SIZE, GroupLayout.PREFERRED_SIZE, GroupLayout.PREFERRED_SIZE
                        )
                );
            }
        }
    }

    public HexField(String title, int fieldSize) {
        this(title, fieldSize, 150);
    }

    private static String getFormat(int size) {
        StringBuilder builder = new StringBuilder("{");
        builder.append("HH|".repeat(Math.max(0, size)));
        builder.deleteCharAt(builder.length() - 1);
        return builder.append("}").toString();
    }

    public void changeSize(int newSize) {
        fieldSize = newSize;
        try {
            FORMATTED.setFormatterFactory(new DefaultFormatterFactory(new MaskFormatter(getFormat(fieldSize))));
        } catch (ParseException e) {
        }
    }

    public byte[] getBytes() {
        String[] hex = FORMATTED.getText().replace("{", "").replace("}", "").split("\\|");
        byte[] out = new byte[fieldSize];
        for (int i = 0; i < hex.length; i++) {
            if (hex[i].contains(" ")) {
                hex[i] = hex[i].replace(" ", "0");
            }
            out[i] = (byte) Integer.parseInt(hex[i], 16);
        }
        return out;
    }
}
