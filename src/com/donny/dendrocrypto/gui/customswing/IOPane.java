package com.donny.dendrocrypto.gui.customswing;

import com.donny.dendroroot.gui.customswing.DendroFactory;

import javax.swing.*;
import java.awt.event.MouseAdapter;
import java.awt.event.MouseEvent;

public class IOPane extends JPanel {
    public final JTextArea CONTENT;

    public IOPane(boolean input) {
        super();

        //draw gui
        {
            setBorder(null);
            JLabel a = new JLabel(input ? "Input" : "Output");
            JScrollPane b = DendroFactory.getScrollField(input, 10, 50);
            CONTENT = (JTextArea) b.getViewport().getView();
            if (!input) {
                CONTENT.setBackground(DendroFactory.DISABLED);
                CONTENT.addMouseListener(new MouseAdapter() {
                    public void mouseClicked(MouseEvent evt) {
                        CONTENT.selectAll();
                    }
                });
            }

            //group layout
            {
                GroupLayout main = new GroupLayout(this);
                setLayout(main);
                main.setHorizontalGroup(
                        main.createParallelGroup(GroupLayout.Alignment.CENTER).addComponent(
                                a, GroupLayout.PREFERRED_SIZE, GroupLayout.PREFERRED_SIZE, GroupLayout.PREFERRED_SIZE
                        ).addComponent(
                                b, GroupLayout.PREFERRED_SIZE, GroupLayout.PREFERRED_SIZE, Short.MAX_VALUE
                        )
                );
                main.setVerticalGroup(
                        main.createSequentialGroup().addComponent(
                                a, GroupLayout.PREFERRED_SIZE, GroupLayout.PREFERRED_SIZE, GroupLayout.PREFERRED_SIZE
                        ).addGap(DendroFactory.SMALL_GAP).addComponent(
                                b, GroupLayout.PREFERRED_SIZE, GroupLayout.PREFERRED_SIZE, Short.MAX_VALUE
                        )
                );
            }
        }
    }
}
