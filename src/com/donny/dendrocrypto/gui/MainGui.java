package com.donny.dendrocrypto.gui;

import com.donny.dendrocrypto.DendroCrypto;
import com.donny.dendrocrypto.encryption.*;
import com.donny.dendrocrypto.gui.customswing.DendroFactory;
import com.donny.dendrocrypto.gui.customswing.components.*;
import com.donny.dendrofactor.DendroFactor;

import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.swing.*;
import java.awt.event.MouseAdapter;
import java.awt.event.MouseEvent;
import java.math.BigInteger;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.util.Base64;

public class MainGui extends JFrame {
    public MainGui() {
        super("Dendrogram Cryptography");

        setDefaultCloseOperation(EXIT_ON_CLOSE);

        //draw gui
        {
            JTabbedPane back = new JTabbedPane();
            //AES
            {
                JTabbedPane aes = new JTabbedPane();
                //AES IV
                {
                    JTabbedPane aesIv = new JTabbedPane();
                    //AES IV PIVI
                    {
                        JPanel pan = new JPanel();
                        JLabel a = new JLabel("SHA-256 Hashed Password With Integrated IV");
                        IOPane in = new IOPane(true);
                        JLabel b = new JLabel("Password");
                        JPasswordField pass = new JPasswordField();
                        JLabel c = new JLabel("IV Index");
                        JComboBox<Integer> ivi = new JComboBox<>();
                        for (int i = 0; i < 17; i++) {
                            ivi.addItem(i);
                        }
                        JLabel d = new JLabel("Mode");
                        JComboBox<AesEH> mode = new JComboBox<>();
                        for (AesEH handler : DendroCrypto.AES_IV) {
                            mode.addItem(handler);
                        }
                        JLabel e = new JLabel("Key Size");
                        JComboBox<Integer> keySize = new JComboBox<>();
                        keySize.addItem(16);
                        keySize.addItem(24);
                        keySize.addItem(32);
                        JComboBox<String> radix = new JComboBox<>();
                        radix.addItem("Base64");
                        radix.addItem("Hexadecimal");
                        JButton enc = DendroFactory.getButton("Encrypt"), dec = DendroFactory.getButton("Decrypt");
                        IOPane out = new IOPane(false);

                        enc.addActionListener(event -> {
                            AesEH handler = (AesEH) mode.getSelectedItem();
                            try {
                                handler.changeKey(pass.getPassword(), (Integer) keySize.getSelectedItem(), (Integer) ivi.getSelectedItem());
                                encrypt(handler, in, out, radix);
                            } catch (NoSuchAlgorithmException ex) {
                                out.CONTENT.setText("It seems like SHA-256 seems not to be supported by your system.");
                            }
                        });
                        dec.addActionListener(event -> {
                            AesEH handler = (AesEH) mode.getSelectedItem();
                            try {
                                handler.changeKey(pass.getPassword(), (Integer) keySize.getSelectedItem(), (Integer) ivi.getSelectedItem());
                                decrypt(handler, in, out, radix);
                            } catch (NoSuchAlgorithmException ex) {
                                out.CONTENT.setText("It seems like SHA-256 seems not to be supported by your system.");
                            }
                        });

                        //Group Layout
                        {
                            GroupLayout main = new GroupLayout(pan);
                            pan.setLayout(main);
                            main.setHorizontalGroup(
                                    main.createSequentialGroup().addContainerGap().addGroup(
                                            main.createParallelGroup(GroupLayout.Alignment.LEADING).addComponent(
                                                    a, GroupLayout.PREFERRED_SIZE, GroupLayout.PREFERRED_SIZE, GroupLayout.PREFERRED_SIZE
                                            ).addComponent(
                                                    in, GroupLayout.PREFERRED_SIZE, GroupLayout.PREFERRED_SIZE, Short.MAX_VALUE
                                            ).addGroup(
                                                    main.createSequentialGroup().addComponent(
                                                            b, GroupLayout.PREFERRED_SIZE, GroupLayout.PREFERRED_SIZE, GroupLayout.PREFERRED_SIZE
                                                    ).addGap(DendroFactory.SMALL_GAP).addComponent(
                                                            pass, GroupLayout.PREFERRED_SIZE, GroupLayout.PREFERRED_SIZE, Short.MAX_VALUE
                                                    ).addGap(DendroFactory.MEDIUM_GAP).addComponent(
                                                            c, GroupLayout.PREFERRED_SIZE, GroupLayout.PREFERRED_SIZE, GroupLayout.PREFERRED_SIZE
                                                    ).addGap(DendroFactory.SMALL_GAP).addComponent(
                                                            ivi, GroupLayout.PREFERRED_SIZE, GroupLayout.PREFERRED_SIZE, GroupLayout.PREFERRED_SIZE
                                                    )
                                            ).addGroup(
                                                    main.createSequentialGroup().addComponent(
                                                            d, GroupLayout.PREFERRED_SIZE, GroupLayout.PREFERRED_SIZE, GroupLayout.PREFERRED_SIZE
                                                    ).addGap(DendroFactory.SMALL_GAP).addComponent(
                                                            mode, GroupLayout.PREFERRED_SIZE, GroupLayout.PREFERRED_SIZE, GroupLayout.PREFERRED_SIZE
                                                    ).addGap(
                                                            DendroFactory.MEDIUM_GAP, DendroFactory.MEDIUM_GAP, Short.MAX_VALUE
                                                    ).addComponent(
                                                            e, GroupLayout.PREFERRED_SIZE, GroupLayout.PREFERRED_SIZE, GroupLayout.PREFERRED_SIZE
                                                    ).addGap(DendroFactory.SMALL_GAP).addComponent(
                                                            keySize, GroupLayout.PREFERRED_SIZE, GroupLayout.PREFERRED_SIZE, GroupLayout.PREFERRED_SIZE
                                                    )
                                            ).addGroup(
                                                    main.createSequentialGroup().addGap(
                                                            DendroFactory.MEDIUM_GAP, DendroFactory.MEDIUM_GAP, Short.MAX_VALUE
                                                    ).addComponent(
                                                            enc, GroupLayout.PREFERRED_SIZE, GroupLayout.PREFERRED_SIZE, GroupLayout.PREFERRED_SIZE
                                                    ).addGap(DendroFactory.SMALL_GAP).addComponent(
                                                            radix, GroupLayout.PREFERRED_SIZE, GroupLayout.PREFERRED_SIZE, GroupLayout.PREFERRED_SIZE
                                                    ).addGap(DendroFactory.SMALL_GAP).addComponent(
                                                            dec, GroupLayout.PREFERRED_SIZE, GroupLayout.PREFERRED_SIZE, GroupLayout.PREFERRED_SIZE
                                                    )
                                            ).addComponent(
                                                    out, GroupLayout.PREFERRED_SIZE, GroupLayout.PREFERRED_SIZE, Short.MAX_VALUE
                                            )
                                    ).addContainerGap()
                            );
                            main.setVerticalGroup(
                                    main.createSequentialGroup().addContainerGap().addComponent(
                                            a, GroupLayout.PREFERRED_SIZE, GroupLayout.PREFERRED_SIZE, GroupLayout.PREFERRED_SIZE
                                    ).addGap(DendroFactory.SMALL_GAP).addComponent(
                                            in, GroupLayout.PREFERRED_SIZE, GroupLayout.PREFERRED_SIZE, Short.MAX_VALUE
                                    ).addGap(DendroFactory.MEDIUM_GAP).addGroup(
                                            main.createParallelGroup(GroupLayout.Alignment.CENTER).addComponent(
                                                    b, GroupLayout.PREFERRED_SIZE, GroupLayout.PREFERRED_SIZE, GroupLayout.PREFERRED_SIZE
                                            ).addComponent(
                                                    pass, GroupLayout.PREFERRED_SIZE, GroupLayout.PREFERRED_SIZE, GroupLayout.PREFERRED_SIZE
                                            ).addComponent(
                                                    c, GroupLayout.PREFERRED_SIZE, GroupLayout.PREFERRED_SIZE, GroupLayout.PREFERRED_SIZE
                                            ).addComponent(
                                                    ivi, GroupLayout.PREFERRED_SIZE, GroupLayout.PREFERRED_SIZE, GroupLayout.PREFERRED_SIZE
                                            )
                                    ).addGap(DendroFactory.MEDIUM_GAP).addGroup(
                                            main.createParallelGroup(GroupLayout.Alignment.CENTER).addComponent(
                                                    d, GroupLayout.PREFERRED_SIZE, GroupLayout.PREFERRED_SIZE, GroupLayout.PREFERRED_SIZE
                                            ).addComponent(
                                                    mode, GroupLayout.PREFERRED_SIZE, GroupLayout.PREFERRED_SIZE, GroupLayout.PREFERRED_SIZE
                                            ).addComponent(
                                                    e, GroupLayout.PREFERRED_SIZE, GroupLayout.PREFERRED_SIZE, GroupLayout.PREFERRED_SIZE
                                            ).addComponent(
                                                    keySize, GroupLayout.PREFERRED_SIZE, GroupLayout.PREFERRED_SIZE, GroupLayout.PREFERRED_SIZE
                                            )
                                    ).addGap(DendroFactory.MEDIUM_GAP).addGroup(
                                            main.createParallelGroup(GroupLayout.Alignment.CENTER).addComponent(
                                                    enc, GroupLayout.PREFERRED_SIZE, GroupLayout.PREFERRED_SIZE, GroupLayout.PREFERRED_SIZE
                                            ).addComponent(
                                                    radix, GroupLayout.PREFERRED_SIZE, GroupLayout.PREFERRED_SIZE, GroupLayout.PREFERRED_SIZE
                                            ).addComponent(
                                                    dec, GroupLayout.PREFERRED_SIZE, GroupLayout.PREFERRED_SIZE, GroupLayout.PREFERRED_SIZE
                                            )
                                    ).addGap(DendroFactory.MEDIUM_GAP).addComponent(
                                            out, GroupLayout.PREFERRED_SIZE, GroupLayout.PREFERRED_SIZE, Short.MAX_VALUE
                                    ).addContainerGap()
                            );
                        }

                        aesIv.addTab("PIVI", pan);
                    }

                    //AES IV PSIV
                    {
                        JPanel pan = new JPanel();
                        JLabel a = new JLabel("SHA-256 Hashed Password With Specified IV");
                        IOPane in = new IOPane(true);
                        JLabel b = new JLabel("Password");
                        JPasswordField pass = new JPasswordField();
                        HexField siv = new HexField("IV", 16);
                        JLabel d = new JLabel("Mode");
                        JComboBox<AesEH> mode = new JComboBox<>();
                        for (AesEH handler : DendroCrypto.AES_IV) {
                            mode.addItem(handler);
                        }
                        JLabel e = new JLabel("Key Size");
                        JComboBox<Integer> keySize = new JComboBox<>();
                        keySize.addItem(16);
                        keySize.addItem(24);
                        keySize.addItem(32);
                        JComboBox<String> radix = new JComboBox<>();
                        radix.addItem("Base64");
                        radix.addItem("Hexadecimal");
                        JButton enc = DendroFactory.getButton("Encrypt"), dec = DendroFactory.getButton("Decrypt");
                        IOPane out = new IOPane(false);

                        enc.addActionListener(event -> {
                            AesEH handler = (AesEH) mode.getSelectedItem();
                            try {
                                handler.changeKey(pass.getPassword(), (Integer) keySize.getSelectedItem(), siv.getBytes());
                                encrypt(handler, in, out, radix);
                            } catch (NoSuchAlgorithmException ex) {
                                out.CONTENT.setText("It seems like SHA-256 seems not to be supported by your system.");
                            }
                        });
                        dec.addActionListener(event -> {
                            AesEH handler = (AesEH) mode.getSelectedItem();
                            try {
                                handler.changeKey(pass.getPassword(), (Integer) keySize.getSelectedItem(), siv.getBytes());
                                decrypt(handler, in, out, radix);
                            } catch (NoSuchAlgorithmException ex) {
                                out.CONTENT.setText("It seems like SHA-256 seems not to be supported by your system.");
                            }
                        });

                        //Group Layout
                        {
                            GroupLayout main = new GroupLayout(pan);
                            pan.setLayout(main);
                            main.setHorizontalGroup(
                                    main.createSequentialGroup().addContainerGap().addGroup(
                                            main.createParallelGroup(GroupLayout.Alignment.LEADING).addComponent(
                                                    a, GroupLayout.PREFERRED_SIZE, GroupLayout.PREFERRED_SIZE, GroupLayout.PREFERRED_SIZE
                                            ).addComponent(
                                                    in, GroupLayout.PREFERRED_SIZE, GroupLayout.PREFERRED_SIZE, Short.MAX_VALUE
                                            ).addGroup(
                                                    main.createSequentialGroup().addComponent(
                                                            b, GroupLayout.PREFERRED_SIZE, GroupLayout.PREFERRED_SIZE, GroupLayout.PREFERRED_SIZE
                                                    ).addGap(DendroFactory.SMALL_GAP).addComponent(
                                                            pass, GroupLayout.PREFERRED_SIZE, GroupLayout.PREFERRED_SIZE, Short.MAX_VALUE
                                                    )
                                            ).addComponent(
                                                    siv, GroupLayout.PREFERRED_SIZE, GroupLayout.PREFERRED_SIZE, Short.MAX_VALUE
                                            ).addGroup(
                                                    main.createSequentialGroup().addComponent(
                                                            d, GroupLayout.PREFERRED_SIZE, GroupLayout.PREFERRED_SIZE, GroupLayout.PREFERRED_SIZE
                                                    ).addGap(DendroFactory.SMALL_GAP).addComponent(
                                                            mode, GroupLayout.PREFERRED_SIZE, GroupLayout.PREFERRED_SIZE, GroupLayout.PREFERRED_SIZE
                                                    ).addGap(
                                                            DendroFactory.MEDIUM_GAP, DendroFactory.MEDIUM_GAP, Short.MAX_VALUE
                                                    ).addComponent(
                                                            e, GroupLayout.PREFERRED_SIZE, GroupLayout.PREFERRED_SIZE, GroupLayout.PREFERRED_SIZE
                                                    ).addGap(DendroFactory.SMALL_GAP).addComponent(
                                                            keySize, GroupLayout.PREFERRED_SIZE, GroupLayout.PREFERRED_SIZE, GroupLayout.PREFERRED_SIZE
                                                    )
                                            ).addGroup(
                                                    main.createSequentialGroup().addGap(
                                                            DendroFactory.MEDIUM_GAP, DendroFactory.MEDIUM_GAP, Short.MAX_VALUE
                                                    ).addComponent(
                                                            enc, GroupLayout.PREFERRED_SIZE, GroupLayout.PREFERRED_SIZE, GroupLayout.PREFERRED_SIZE
                                                    ).addGap(DendroFactory.SMALL_GAP).addComponent(
                                                            radix, GroupLayout.PREFERRED_SIZE, GroupLayout.PREFERRED_SIZE, GroupLayout.PREFERRED_SIZE
                                                    ).addGap(DendroFactory.SMALL_GAP).addComponent(
                                                            dec, GroupLayout.PREFERRED_SIZE, GroupLayout.PREFERRED_SIZE, GroupLayout.PREFERRED_SIZE
                                                    )
                                            ).addComponent(
                                                    out, GroupLayout.PREFERRED_SIZE, GroupLayout.PREFERRED_SIZE, Short.MAX_VALUE
                                            )
                                    ).addContainerGap()
                            );
                            main.setVerticalGroup(
                                    main.createSequentialGroup().addContainerGap().addComponent(
                                            a, GroupLayout.PREFERRED_SIZE, GroupLayout.PREFERRED_SIZE, GroupLayout.PREFERRED_SIZE
                                    ).addGap(DendroFactory.SMALL_GAP).addComponent(
                                            in, GroupLayout.PREFERRED_SIZE, GroupLayout.PREFERRED_SIZE, Short.MAX_VALUE
                                    ).addGap(DendroFactory.MEDIUM_GAP).addGroup(
                                            main.createParallelGroup(GroupLayout.Alignment.CENTER).addComponent(
                                                    b, GroupLayout.PREFERRED_SIZE, GroupLayout.PREFERRED_SIZE, GroupLayout.PREFERRED_SIZE
                                            ).addComponent(
                                                    pass, GroupLayout.PREFERRED_SIZE, GroupLayout.PREFERRED_SIZE, GroupLayout.PREFERRED_SIZE
                                            )
                                    ).addGap(DendroFactory.MEDIUM_GAP).addComponent(
                                            siv, GroupLayout.PREFERRED_SIZE, GroupLayout.PREFERRED_SIZE, GroupLayout.PREFERRED_SIZE
                                    ).addGap(DendroFactory.MEDIUM_GAP).addGroup(
                                            main.createParallelGroup(GroupLayout.Alignment.CENTER).addComponent(
                                                    d, GroupLayout.PREFERRED_SIZE, GroupLayout.PREFERRED_SIZE, GroupLayout.PREFERRED_SIZE
                                            ).addComponent(
                                                    mode, GroupLayout.PREFERRED_SIZE, GroupLayout.PREFERRED_SIZE, GroupLayout.PREFERRED_SIZE
                                            ).addComponent(
                                                    e, GroupLayout.PREFERRED_SIZE, GroupLayout.PREFERRED_SIZE, GroupLayout.PREFERRED_SIZE
                                            ).addComponent(
                                                    keySize, GroupLayout.PREFERRED_SIZE, GroupLayout.PREFERRED_SIZE, GroupLayout.PREFERRED_SIZE
                                            )
                                    ).addGap(DendroFactory.MEDIUM_GAP).addGroup(
                                            main.createParallelGroup(GroupLayout.Alignment.CENTER).addComponent(
                                                    enc, GroupLayout.PREFERRED_SIZE, GroupLayout.PREFERRED_SIZE, GroupLayout.PREFERRED_SIZE
                                            ).addComponent(
                                                    radix, GroupLayout.PREFERRED_SIZE, GroupLayout.PREFERRED_SIZE, GroupLayout.PREFERRED_SIZE
                                            ).addComponent(
                                                    dec, GroupLayout.PREFERRED_SIZE, GroupLayout.PREFERRED_SIZE, GroupLayout.PREFERRED_SIZE
                                            )
                                    ).addGap(DendroFactory.MEDIUM_GAP).addComponent(
                                            out, GroupLayout.PREFERRED_SIZE, GroupLayout.PREFERRED_SIZE, Short.MAX_VALUE
                                    ).addContainerGap()
                            );
                        }

                        aesIv.addTab("PSIV", pan);
                    }

                    //AES IV KSIV
                    {
                        JPanel pan = new JPanel();
                        JLabel a = new JLabel("Specified Key With Specified IV");
                        IOPane in = new IOPane(true);
                        HexField key = new HexField("Key", 16);
                        HexField siv = new HexField("IV", 16);
                        JLabel d = new JLabel("Mode");
                        JComboBox<AesEH> mode = new JComboBox<>();
                        for (AesEH handler : DendroCrypto.AES_IV) {
                            mode.addItem(handler);
                        }
                        JLabel e = new JLabel("Key Size");
                        JComboBox<Integer> keySize = new JComboBox<>();
                        keySize.addItem(16);
                        keySize.addItem(24);
                        keySize.addItem(32);
                        keySize.addItemListener(event -> key.changeSize((Integer) keySize.getSelectedItem()));
                        JComboBox<String> radix = new JComboBox<>();
                        radix.addItem("Base64");
                        radix.addItem("Hexadecimal");
                        JButton enc = DendroFactory.getButton("Encrypt"), dec = DendroFactory.getButton("Decrypt");
                        IOPane out = new IOPane(false);

                        enc.addActionListener(event -> {
                            AesEH handler = (AesEH) mode.getSelectedItem();
                            handler.changeKey(key.getBytes(), siv.getBytes());
                            encrypt(handler, in, out, radix);
                        });
                        dec.addActionListener(event -> {
                            AesEH handler = (AesEH) mode.getSelectedItem();
                            handler.changeKey(key.getBytes(), siv.getBytes());
                            decrypt(handler, in, out, radix);
                        });

                        //Group Layout
                        {
                            GroupLayout main = new GroupLayout(pan);
                            pan.setLayout(main);
                            main.setHorizontalGroup(
                                    main.createSequentialGroup().addContainerGap().addGroup(
                                            main.createParallelGroup(GroupLayout.Alignment.LEADING).addComponent(
                                                    a, GroupLayout.PREFERRED_SIZE, GroupLayout.PREFERRED_SIZE, GroupLayout.PREFERRED_SIZE
                                            ).addComponent(
                                                    in, GroupLayout.PREFERRED_SIZE, GroupLayout.PREFERRED_SIZE, Short.MAX_VALUE
                                            ).addComponent(
                                                    key, GroupLayout.PREFERRED_SIZE, GroupLayout.PREFERRED_SIZE, Short.MAX_VALUE
                                            ).addComponent(
                                                    siv, GroupLayout.PREFERRED_SIZE, GroupLayout.PREFERRED_SIZE, Short.MAX_VALUE
                                            ).addGroup(
                                                    main.createSequentialGroup().addComponent(
                                                            d, GroupLayout.PREFERRED_SIZE, GroupLayout.PREFERRED_SIZE, GroupLayout.PREFERRED_SIZE
                                                    ).addGap(DendroFactory.SMALL_GAP).addComponent(
                                                            mode, GroupLayout.PREFERRED_SIZE, GroupLayout.PREFERRED_SIZE, GroupLayout.PREFERRED_SIZE
                                                    ).addGap(
                                                            DendroFactory.MEDIUM_GAP, DendroFactory.MEDIUM_GAP, Short.MAX_VALUE
                                                    ).addComponent(
                                                            e, GroupLayout.PREFERRED_SIZE, GroupLayout.PREFERRED_SIZE, GroupLayout.PREFERRED_SIZE
                                                    ).addGap(DendroFactory.SMALL_GAP).addComponent(
                                                            keySize, GroupLayout.PREFERRED_SIZE, GroupLayout.PREFERRED_SIZE, GroupLayout.PREFERRED_SIZE
                                                    )
                                            ).addGroup(
                                                    main.createSequentialGroup().addGap(
                                                            DendroFactory.MEDIUM_GAP, DendroFactory.MEDIUM_GAP, Short.MAX_VALUE
                                                    ).addComponent(
                                                            enc, GroupLayout.PREFERRED_SIZE, GroupLayout.PREFERRED_SIZE, GroupLayout.PREFERRED_SIZE
                                                    ).addGap(DendroFactory.SMALL_GAP).addComponent(
                                                            radix, GroupLayout.PREFERRED_SIZE, GroupLayout.PREFERRED_SIZE, GroupLayout.PREFERRED_SIZE
                                                    ).addGap(DendroFactory.SMALL_GAP).addComponent(
                                                            dec, GroupLayout.PREFERRED_SIZE, GroupLayout.PREFERRED_SIZE, GroupLayout.PREFERRED_SIZE
                                                    )
                                            ).addComponent(
                                                    out, GroupLayout.PREFERRED_SIZE, GroupLayout.PREFERRED_SIZE, Short.MAX_VALUE
                                            )
                                    ).addContainerGap()
                            );
                            main.setVerticalGroup(
                                    main.createSequentialGroup().addContainerGap().addComponent(
                                            a, GroupLayout.PREFERRED_SIZE, GroupLayout.PREFERRED_SIZE, GroupLayout.PREFERRED_SIZE
                                    ).addGap(DendroFactory.SMALL_GAP).addComponent(
                                            in, GroupLayout.PREFERRED_SIZE, GroupLayout.PREFERRED_SIZE, Short.MAX_VALUE
                                    ).addGap(DendroFactory.MEDIUM_GAP).addComponent(
                                            key, GroupLayout.PREFERRED_SIZE, GroupLayout.PREFERRED_SIZE, GroupLayout.PREFERRED_SIZE
                                    ).addGap(DendroFactory.MEDIUM_GAP).addComponent(
                                            siv, GroupLayout.PREFERRED_SIZE, GroupLayout.PREFERRED_SIZE, GroupLayout.PREFERRED_SIZE
                                    ).addGap(DendroFactory.MEDIUM_GAP).addGroup(
                                            main.createParallelGroup(GroupLayout.Alignment.CENTER).addComponent(
                                                    d, GroupLayout.PREFERRED_SIZE, GroupLayout.PREFERRED_SIZE, GroupLayout.PREFERRED_SIZE
                                            ).addComponent(
                                                    mode, GroupLayout.PREFERRED_SIZE, GroupLayout.PREFERRED_SIZE, GroupLayout.PREFERRED_SIZE
                                            ).addComponent(
                                                    e, GroupLayout.PREFERRED_SIZE, GroupLayout.PREFERRED_SIZE, GroupLayout.PREFERRED_SIZE
                                            ).addComponent(
                                                    keySize, GroupLayout.PREFERRED_SIZE, GroupLayout.PREFERRED_SIZE, GroupLayout.PREFERRED_SIZE
                                            )
                                    ).addGap(DendroFactory.MEDIUM_GAP).addGroup(
                                            main.createParallelGroup(GroupLayout.Alignment.CENTER).addComponent(
                                                    enc, GroupLayout.PREFERRED_SIZE, GroupLayout.PREFERRED_SIZE, GroupLayout.PREFERRED_SIZE
                                            ).addComponent(
                                                    radix, GroupLayout.PREFERRED_SIZE, GroupLayout.PREFERRED_SIZE, GroupLayout.PREFERRED_SIZE
                                            ).addComponent(
                                                    dec, GroupLayout.PREFERRED_SIZE, GroupLayout.PREFERRED_SIZE, GroupLayout.PREFERRED_SIZE
                                            )
                                    ).addGap(DendroFactory.MEDIUM_GAP).addComponent(
                                            out, GroupLayout.PREFERRED_SIZE, GroupLayout.PREFERRED_SIZE, Short.MAX_VALUE
                                    ).addContainerGap()
                            );
                        }

                        aesIv.addTab("KSIV", pan);
                    }

                    aes.addTab("IV", aesIv);
                }

                //AES No IV
                {
                    JTabbedPane aesNiv = new JTabbedPane();

                    //AES_PASS
                    {
                        JPanel pan = new JPanel();
                        JLabel a = new JLabel("SHA-256 Hashed Password");
                        IOPane in = new IOPane(true);
                        JLabel b = new JLabel("Password");
                        JPasswordField pass = new JPasswordField();
                        JLabel c = new JLabel("Mode");
                        JComboBox<AesEH> mode = new JComboBox<>();
                        for (AesEH handler : DendroCrypto.AES_NO_IV) {
                            mode.addItem(handler);
                        }
                        JLabel d = new JLabel("Key Size");
                        JComboBox<Integer> keySize = new JComboBox<>();
                        keySize.addItem(16);
                        keySize.addItem(24);
                        keySize.addItem(32);
                        JComboBox<String> radix = new JComboBox<>();
                        radix.addItem("Base64");
                        radix.addItem("Hexadecimal");
                        JButton enc = DendroFactory.getButton("Encrypt"), dec = DendroFactory.getButton("Decrypt");
                        IOPane out = new IOPane(false);

                        enc.addActionListener(event -> {
                            AesEH handler = (AesEH) mode.getSelectedItem();
                            try {
                                handler.changeKey(pass.getPassword(), (Integer) keySize.getSelectedItem());
                                encrypt(handler, in, out, radix);
                            } catch (NoSuchAlgorithmException ex) {
                                out.CONTENT.setText("It seems like SHA-256 seems not to be supported by your system.");
                            }
                        });
                        dec.addActionListener(event -> {
                            AesEH handler = (AesEH) mode.getSelectedItem();
                            try {
                                handler.changeKey(pass.getPassword(), (Integer) keySize.getSelectedItem());
                                decrypt(handler, in, out, radix);
                            } catch (NoSuchAlgorithmException ex) {
                                out.CONTENT.setText("It seems like SHA-256 seems not to be supported by your system.");
                            }
                        });

                        //Group Layout
                        {
                            GroupLayout main = new GroupLayout(pan);
                            pan.setLayout(main);
                            main.setHorizontalGroup(
                                    main.createSequentialGroup().addContainerGap().addGroup(
                                            main.createParallelGroup(GroupLayout.Alignment.LEADING).addComponent(
                                                    a, GroupLayout.PREFERRED_SIZE, GroupLayout.PREFERRED_SIZE, GroupLayout.PREFERRED_SIZE
                                            ).addComponent(
                                                    in, GroupLayout.PREFERRED_SIZE, GroupLayout.PREFERRED_SIZE, Short.MAX_VALUE
                                            ).addGroup(
                                                    main.createSequentialGroup().addComponent(
                                                            b, GroupLayout.PREFERRED_SIZE, GroupLayout.PREFERRED_SIZE, GroupLayout.PREFERRED_SIZE
                                                    ).addGap(DendroFactory.SMALL_GAP).addComponent(
                                                            pass, GroupLayout.PREFERRED_SIZE, GroupLayout.PREFERRED_SIZE, Short.MAX_VALUE
                                                    )
                                            ).addGroup(
                                                    main.createSequentialGroup().addComponent(
                                                            c, GroupLayout.PREFERRED_SIZE, GroupLayout.PREFERRED_SIZE, GroupLayout.PREFERRED_SIZE
                                                    ).addGap(DendroFactory.SMALL_GAP).addComponent(
                                                            mode, GroupLayout.PREFERRED_SIZE, GroupLayout.PREFERRED_SIZE, GroupLayout.PREFERRED_SIZE
                                                    ).addGap(
                                                            DendroFactory.MEDIUM_GAP, DendroFactory.MEDIUM_GAP, Short.MAX_VALUE
                                                    ).addComponent(
                                                            d, GroupLayout.PREFERRED_SIZE, GroupLayout.PREFERRED_SIZE, GroupLayout.PREFERRED_SIZE
                                                    ).addGap(DendroFactory.SMALL_GAP).addComponent(
                                                            keySize, GroupLayout.PREFERRED_SIZE, GroupLayout.PREFERRED_SIZE, GroupLayout.PREFERRED_SIZE
                                                    )
                                            ).addGroup(
                                                    main.createSequentialGroup().addGap(
                                                            DendroFactory.MEDIUM_GAP, DendroFactory.MEDIUM_GAP, Short.MAX_VALUE
                                                    ).addComponent(
                                                            enc, GroupLayout.PREFERRED_SIZE, GroupLayout.PREFERRED_SIZE, GroupLayout.PREFERRED_SIZE
                                                    ).addGap(DendroFactory.SMALL_GAP).addComponent(
                                                            radix, GroupLayout.PREFERRED_SIZE, GroupLayout.PREFERRED_SIZE, GroupLayout.PREFERRED_SIZE
                                                    ).addGap(DendroFactory.SMALL_GAP).addComponent(
                                                            dec, GroupLayout.PREFERRED_SIZE, GroupLayout.PREFERRED_SIZE, GroupLayout.PREFERRED_SIZE
                                                    )
                                            ).addComponent(
                                                    out, GroupLayout.PREFERRED_SIZE, GroupLayout.PREFERRED_SIZE, Short.MAX_VALUE
                                            )
                                    ).addContainerGap()
                            );
                            main.setVerticalGroup(
                                    main.createSequentialGroup().addContainerGap().addComponent(
                                            a, GroupLayout.PREFERRED_SIZE, GroupLayout.PREFERRED_SIZE, GroupLayout.PREFERRED_SIZE
                                    ).addGap(DendroFactory.SMALL_GAP).addComponent(
                                            in, GroupLayout.PREFERRED_SIZE, GroupLayout.PREFERRED_SIZE, Short.MAX_VALUE
                                    ).addGap(DendroFactory.MEDIUM_GAP).addGroup(
                                            main.createParallelGroup(GroupLayout.Alignment.CENTER).addComponent(
                                                    b, GroupLayout.PREFERRED_SIZE, GroupLayout.PREFERRED_SIZE, GroupLayout.PREFERRED_SIZE
                                            ).addComponent(
                                                    pass, GroupLayout.PREFERRED_SIZE, GroupLayout.PREFERRED_SIZE, GroupLayout.PREFERRED_SIZE
                                            )
                                    ).addGap(DendroFactory.MEDIUM_GAP).addGroup(
                                            main.createParallelGroup(GroupLayout.Alignment.CENTER).addComponent(
                                                    c, GroupLayout.PREFERRED_SIZE, GroupLayout.PREFERRED_SIZE, GroupLayout.PREFERRED_SIZE
                                            ).addComponent(
                                                    mode, GroupLayout.PREFERRED_SIZE, GroupLayout.PREFERRED_SIZE, GroupLayout.PREFERRED_SIZE
                                            ).addComponent(
                                                    d, GroupLayout.PREFERRED_SIZE, GroupLayout.PREFERRED_SIZE, GroupLayout.PREFERRED_SIZE
                                            ).addComponent(
                                                    keySize, GroupLayout.PREFERRED_SIZE, GroupLayout.PREFERRED_SIZE, GroupLayout.PREFERRED_SIZE
                                            )
                                    ).addGap(DendroFactory.MEDIUM_GAP).addGroup(
                                            main.createParallelGroup(GroupLayout.Alignment.CENTER).addComponent(
                                                    enc, GroupLayout.PREFERRED_SIZE, GroupLayout.PREFERRED_SIZE, GroupLayout.PREFERRED_SIZE
                                            ).addComponent(
                                                    radix, GroupLayout.PREFERRED_SIZE, GroupLayout.PREFERRED_SIZE, GroupLayout.PREFERRED_SIZE
                                            ).addComponent(
                                                    dec, GroupLayout.PREFERRED_SIZE, GroupLayout.PREFERRED_SIZE, GroupLayout.PREFERRED_SIZE
                                            )
                                    ).addGap(DendroFactory.MEDIUM_GAP).addComponent(
                                            out, GroupLayout.PREFERRED_SIZE, GroupLayout.PREFERRED_SIZE, Short.MAX_VALUE
                                    ).addContainerGap()
                            );
                        }
                        aesNiv.addTab("Password", pan);
                    }

                    //AES_KEY
                    {
                        JPanel pan = new JPanel();
                        JLabel a = new JLabel("Specified Key");
                        IOPane in = new IOPane(true);
                        HexField key = new HexField("Key", 16);
                        JLabel b = new JLabel("Mode");
                        JComboBox<AesEH> mode = new JComboBox<>();
                        for (AesEH handler : DendroCrypto.AES_NO_IV) {
                            mode.addItem(handler);
                        }
                        JLabel c = new JLabel("Key Size");
                        JComboBox<Integer> keySize = new JComboBox<>();
                        keySize.addItem(16);
                        keySize.addItem(24);
                        keySize.addItem(32);
                        keySize.addItemListener(event -> key.changeSize((Integer) keySize.getSelectedItem()));
                        JComboBox<String> radix = new JComboBox<>();
                        radix.addItem("Base64");
                        radix.addItem("Hexadecimal");
                        JButton enc = DendroFactory.getButton("Encrypt"), dec = DendroFactory.getButton("Decrypt");
                        IOPane out = new IOPane(false);

                        enc.addActionListener(event -> {
                            AesEH handler = (AesEH) mode.getSelectedItem();
                            handler.changeKey(key.getBytes());
                            encrypt(handler, in, out, radix);
                        });
                        dec.addActionListener(event -> {
                            AesEH handler = (AesEH) mode.getSelectedItem();
                            handler.changeKey(key.getBytes());
                            decrypt(handler, in, out, radix);
                        });

                        //Group Layout
                        {
                            GroupLayout main = new GroupLayout(pan);
                            pan.setLayout(main);
                            main.setHorizontalGroup(
                                    main.createSequentialGroup().addContainerGap().addGroup(
                                            main.createParallelGroup(GroupLayout.Alignment.LEADING).addComponent(
                                                    a, GroupLayout.PREFERRED_SIZE, GroupLayout.PREFERRED_SIZE, GroupLayout.PREFERRED_SIZE
                                            ).addComponent(
                                                    in, GroupLayout.PREFERRED_SIZE, GroupLayout.PREFERRED_SIZE, Short.MAX_VALUE
                                            ).addComponent(
                                                    key, GroupLayout.PREFERRED_SIZE, GroupLayout.PREFERRED_SIZE, Short.MAX_VALUE
                                            ).addGroup(
                                                    main.createSequentialGroup().addComponent(
                                                            b, GroupLayout.PREFERRED_SIZE, GroupLayout.PREFERRED_SIZE, GroupLayout.PREFERRED_SIZE
                                                    ).addGap(DendroFactory.SMALL_GAP).addComponent(
                                                            mode, GroupLayout.PREFERRED_SIZE, GroupLayout.PREFERRED_SIZE, GroupLayout.PREFERRED_SIZE
                                                    ).addGap(
                                                            DendroFactory.MEDIUM_GAP, DendroFactory.MEDIUM_GAP, Short.MAX_VALUE
                                                    ).addComponent(
                                                            c, GroupLayout.PREFERRED_SIZE, GroupLayout.PREFERRED_SIZE, GroupLayout.PREFERRED_SIZE
                                                    ).addGap(DendroFactory.SMALL_GAP).addComponent(
                                                            keySize, GroupLayout.PREFERRED_SIZE, GroupLayout.PREFERRED_SIZE, GroupLayout.PREFERRED_SIZE
                                                    )
                                            ).addGroup(
                                                    main.createSequentialGroup().addGap(
                                                            DendroFactory.MEDIUM_GAP, DendroFactory.MEDIUM_GAP, Short.MAX_VALUE
                                                    ).addComponent(
                                                            enc, GroupLayout.PREFERRED_SIZE, GroupLayout.PREFERRED_SIZE, GroupLayout.PREFERRED_SIZE
                                                    ).addGap(DendroFactory.SMALL_GAP).addComponent(
                                                            radix, GroupLayout.PREFERRED_SIZE, GroupLayout.PREFERRED_SIZE, GroupLayout.PREFERRED_SIZE
                                                    ).addGap(DendroFactory.SMALL_GAP).addComponent(
                                                            dec, GroupLayout.PREFERRED_SIZE, GroupLayout.PREFERRED_SIZE, GroupLayout.PREFERRED_SIZE
                                                    )
                                            ).addComponent(
                                                    out, GroupLayout.PREFERRED_SIZE, GroupLayout.PREFERRED_SIZE, Short.MAX_VALUE
                                            )
                                    ).addContainerGap()
                            );
                            main.setVerticalGroup(
                                    main.createSequentialGroup().addContainerGap().addComponent(
                                            a, GroupLayout.PREFERRED_SIZE, GroupLayout.PREFERRED_SIZE, GroupLayout.PREFERRED_SIZE
                                    ).addGap(DendroFactory.SMALL_GAP).addComponent(
                                            in, GroupLayout.PREFERRED_SIZE, GroupLayout.PREFERRED_SIZE, Short.MAX_VALUE
                                    ).addGap(DendroFactory.MEDIUM_GAP).addComponent(
                                            key, GroupLayout.PREFERRED_SIZE, GroupLayout.PREFERRED_SIZE, GroupLayout.PREFERRED_SIZE
                                    ).addGap(DendroFactory.MEDIUM_GAP).addGroup(
                                            main.createParallelGroup(GroupLayout.Alignment.CENTER).addComponent(
                                                    b, GroupLayout.PREFERRED_SIZE, GroupLayout.PREFERRED_SIZE, GroupLayout.PREFERRED_SIZE
                                            ).addComponent(
                                                    mode, GroupLayout.PREFERRED_SIZE, GroupLayout.PREFERRED_SIZE, GroupLayout.PREFERRED_SIZE
                                            ).addComponent(
                                                    c, GroupLayout.PREFERRED_SIZE, GroupLayout.PREFERRED_SIZE, GroupLayout.PREFERRED_SIZE
                                            ).addComponent(
                                                    keySize, GroupLayout.PREFERRED_SIZE, GroupLayout.PREFERRED_SIZE, GroupLayout.PREFERRED_SIZE
                                            )
                                    ).addGap(DendroFactory.MEDIUM_GAP).addGroup(
                                            main.createParallelGroup(GroupLayout.Alignment.CENTER).addComponent(
                                                    enc, GroupLayout.PREFERRED_SIZE, GroupLayout.PREFERRED_SIZE, GroupLayout.PREFERRED_SIZE
                                            ).addComponent(
                                                    radix, GroupLayout.PREFERRED_SIZE, GroupLayout.PREFERRED_SIZE, GroupLayout.PREFERRED_SIZE
                                            ).addComponent(
                                                    dec, GroupLayout.PREFERRED_SIZE, GroupLayout.PREFERRED_SIZE, GroupLayout.PREFERRED_SIZE
                                            )
                                    ).addGap(DendroFactory.MEDIUM_GAP).addComponent(
                                            out, GroupLayout.PREFERRED_SIZE, GroupLayout.PREFERRED_SIZE, Short.MAX_VALUE
                                    ).addContainerGap()
                            );
                        }

                        aesNiv.addTab("Key", pan);
                    }

                    aes.addTab("No IV", aesNiv);
                }

                back.addTab("AES", aes);
            }

            //UTIL
            {
                JTabbedPane util = new JTabbedPane();
                //MOD EXP
                {
                    JPanel pan = new JPanel();
                    JLabel a = new JLabel("Base");
                    JScrollPane basePane = DendroFactory.getLongField();
                    JTextArea base = (JTextArea) basePane.getViewport().getView();
                    JLabel b = new JLabel("Exponent");
                    JScrollPane expPane = DendroFactory.getLongField();
                    JTextArea exp = (JTextArea) expPane.getViewport().getView();
                    JLabel c = new JLabel("Modulus");
                    JScrollPane modPane = DendroFactory.getLongField();
                    JTextArea mod = (JTextArea) modPane.getViewport().getView();
                    JLabel d = new JLabel("Result");
                    JScrollPane outPane = DendroFactory.getLongField();
                    JTextArea out = (JTextArea) outPane.getViewport().getView();
                    out.setEditable(false);
                    out.setBackground(DendroFactory.DISABLED);
                    out.addMouseListener(new MouseAdapter() {
                        public void mouseClicked(MouseEvent evt) {
                            out.selectAll();
                        }
                    });
                    JButton button = DendroFactory.getButton("Calculate");
                    button.addActionListener(event -> out.setText(
                            DendroFactor.bigModularExponentiation(
                                    new BigInteger(base.getText()),
                                    new BigInteger(exp.getText()),
                                    new BigInteger(mod.getText())
                            ).toString()
                    ));

                    //Group Layout
                    {
                        GroupLayout main = new GroupLayout(pan);
                        pan.setLayout(main);
                        main.setHorizontalGroup(
                                main.createSequentialGroup().addContainerGap().addGroup(
                                        main.createParallelGroup(GroupLayout.Alignment.TRAILING).addComponent(
                                                a, GroupLayout.PREFERRED_SIZE, GroupLayout.PREFERRED_SIZE, GroupLayout.PREFERRED_SIZE
                                        ).addComponent(
                                                b, GroupLayout.PREFERRED_SIZE, GroupLayout.PREFERRED_SIZE, GroupLayout.PREFERRED_SIZE
                                        ).addComponent(
                                                c, GroupLayout.PREFERRED_SIZE, GroupLayout.PREFERRED_SIZE, GroupLayout.PREFERRED_SIZE
                                        ).addComponent(
                                                button, GroupLayout.PREFERRED_SIZE, GroupLayout.PREFERRED_SIZE, GroupLayout.PREFERRED_SIZE
                                        ).addComponent(
                                                d, GroupLayout.PREFERRED_SIZE, GroupLayout.PREFERRED_SIZE, GroupLayout.PREFERRED_SIZE
                                        )
                                ).addGap(DendroFactory.MEDIUM_GAP).addGroup(
                                        main.createParallelGroup(GroupLayout.Alignment.LEADING).addComponent(
                                                basePane, 200, 200, Short.MAX_VALUE
                                        ).addComponent(
                                                expPane, 200, 200, Short.MAX_VALUE
                                        ).addComponent(
                                                modPane, 200, 200, Short.MAX_VALUE
                                        ).addComponent(
                                                outPane, 200, 200, Short.MAX_VALUE
                                        )
                                ).addContainerGap()
                        );
                        main.setVerticalGroup(
                                main.createSequentialGroup().addContainerGap().addGroup(
                                        main.createParallelGroup(GroupLayout.Alignment.LEADING).addComponent(
                                                a, GroupLayout.PREFERRED_SIZE, GroupLayout.PREFERRED_SIZE, GroupLayout.PREFERRED_SIZE
                                        ).addComponent(
                                                basePane, GroupLayout.PREFERRED_SIZE, GroupLayout.PREFERRED_SIZE, GroupLayout.PREFERRED_SIZE
                                        )
                                ).addGap(DendroFactory.MEDIUM_GAP).addGroup(
                                        main.createParallelGroup(GroupLayout.Alignment.LEADING).addComponent(
                                                b, GroupLayout.PREFERRED_SIZE, GroupLayout.PREFERRED_SIZE, GroupLayout.PREFERRED_SIZE
                                        ).addComponent(
                                                expPane, GroupLayout.PREFERRED_SIZE, GroupLayout.PREFERRED_SIZE, GroupLayout.PREFERRED_SIZE
                                        )
                                ).addGap(DendroFactory.MEDIUM_GAP).addGroup(
                                        main.createParallelGroup(GroupLayout.Alignment.LEADING).addComponent(
                                                c, GroupLayout.PREFERRED_SIZE, GroupLayout.PREFERRED_SIZE, GroupLayout.PREFERRED_SIZE
                                        ).addComponent(
                                                modPane, GroupLayout.PREFERRED_SIZE, GroupLayout.PREFERRED_SIZE, GroupLayout.PREFERRED_SIZE
                                        )
                                ).addGap(DendroFactory.MEDIUM_GAP).addComponent(
                                        button, GroupLayout.PREFERRED_SIZE, GroupLayout.PREFERRED_SIZE, GroupLayout.PREFERRED_SIZE
                                ).addGap(DendroFactory.MEDIUM_GAP).addGroup(
                                        main.createParallelGroup(GroupLayout.Alignment.LEADING).addComponent(
                                                d, GroupLayout.PREFERRED_SIZE, GroupLayout.PREFERRED_SIZE, GroupLayout.PREFERRED_SIZE
                                        ).addComponent(
                                                outPane, GroupLayout.PREFERRED_SIZE, GroupLayout.PREFERRED_SIZE, GroupLayout.PREFERRED_SIZE
                                        )
                                ).addContainerGap()
                        );
                    }

                    util.addTab("Modular Exponentiation", pan);
                }

                //RAND
                {
                    JPanel pan = new JPanel();
                    JComboBox<Integer> byteLength = new JComboBox<>();
                    int x = 1;
                    while (x < 1025) {
                        byteLength.addItem(x);
                        x *= 2;
                    }
                    JLabel a = new JLabel("Decimal");
                    JScrollPane decPane = DendroFactory.getLongField();
                    JTextArea dec = (JTextArea) decPane.getViewport().getView();
                    dec.setEditable(false);
                    dec.setBackground(DendroFactory.DISABLED);
                    dec.addMouseListener(new MouseAdapter() {
                        public void mouseClicked(MouseEvent evt) {
                            dec.selectAll();
                        }
                    });
                    JLabel b = new JLabel("Base 64");
                    JScrollPane b64Pane = DendroFactory.getLongField();
                    JTextArea b64 = (JTextArea) b64Pane.getViewport().getView();
                    b64.setEditable(false);
                    b64.setBackground(DendroFactory.DISABLED);
                    b64.addMouseListener(new MouseAdapter() {
                        public void mouseClicked(MouseEvent evt) {
                            b64.selectAll();
                        }
                    });
                    JLabel c = new JLabel("Hexadecimal");
                    JScrollPane hexPane = DendroFactory.getLongField();
                    JTextArea hex = (JTextArea) hexPane.getViewport().getView();
                    hex.setEditable(false);
                    hex.setBackground(DendroFactory.DISABLED);
                    hex.addMouseListener(new MouseAdapter() {
                        public void mouseClicked(MouseEvent evt) {
                            hex.selectAll();
                        }
                    });

                    JButton button = DendroFactory.getButton("New Number");
                    button.addActionListener(event -> {
                        int s = (Integer) byteLength.getSelectedItem();
                        byte[] res = new byte[s];
                        SecureRandom r = new SecureRandom();
                        r.nextBytes(res);
                        dec.setText(new BigInteger(res).toString());
                        b64.setText(Base64.getEncoder().encodeToString(res));
                        hex.setText(DendroCrypto.toHexString(res));
                    });

                    //Group Layout
                    {
                        GroupLayout main = new GroupLayout(pan);
                        pan.setLayout(main);
                        main.setHorizontalGroup(
                                main.createSequentialGroup().addContainerGap().addGroup(
                                        main.createParallelGroup(GroupLayout.Alignment.CENTER).addGroup(
                                                main.createSequentialGroup().addGap(
                                                        DendroFactory.SMALL_GAP, DendroFactory.SMALL_GAP, Short.MAX_VALUE
                                                ).addComponent(
                                                        button, GroupLayout.PREFERRED_SIZE, GroupLayout.PREFERRED_SIZE, GroupLayout.PREFERRED_SIZE
                                                ).addGap(DendroFactory.MEDIUM_GAP).addComponent(
                                                        byteLength, GroupLayout.PREFERRED_SIZE, GroupLayout.PREFERRED_SIZE, GroupLayout.PREFERRED_SIZE
                                                )
                                        ).addGroup(
                                                main.createSequentialGroup().addGroup(
                                                        main.createParallelGroup(GroupLayout.Alignment.TRAILING).addComponent(
                                                                a, GroupLayout.PREFERRED_SIZE, GroupLayout.PREFERRED_SIZE, GroupLayout.PREFERRED_SIZE
                                                        ).addComponent(
                                                                b, GroupLayout.PREFERRED_SIZE, GroupLayout.PREFERRED_SIZE, GroupLayout.PREFERRED_SIZE
                                                        ).addComponent(
                                                                c, GroupLayout.PREFERRED_SIZE, GroupLayout.PREFERRED_SIZE, GroupLayout.PREFERRED_SIZE
                                                        )
                                                ).addGap(DendroFactory.MEDIUM_GAP).addGroup(
                                                        main.createParallelGroup(GroupLayout.Alignment.LEADING).addComponent(
                                                                decPane, 200, 200, Short.MAX_VALUE
                                                        ).addComponent(
                                                                b64Pane, 200, 200, Short.MAX_VALUE
                                                        ).addComponent(
                                                                hexPane, 200, 200, Short.MAX_VALUE
                                                        )

                                                )
                                        )
                                ).addContainerGap()
                        );
                        main.setVerticalGroup(
                                main.createSequentialGroup().addContainerGap().addGroup(
                                        main.createParallelGroup(GroupLayout.Alignment.CENTER).addComponent(
                                                button, GroupLayout.PREFERRED_SIZE, GroupLayout.PREFERRED_SIZE, GroupLayout.PREFERRED_SIZE
                                        ).addComponent(
                                                byteLength, GroupLayout.PREFERRED_SIZE, GroupLayout.PREFERRED_SIZE, GroupLayout.PREFERRED_SIZE
                                        )
                                ).addGap(DendroFactory.MEDIUM_GAP).addGroup(
                                        main.createParallelGroup(GroupLayout.Alignment.LEADING).addComponent(
                                                a, GroupLayout.PREFERRED_SIZE, GroupLayout.PREFERRED_SIZE, GroupLayout.PREFERRED_SIZE
                                        ).addComponent(
                                                decPane, GroupLayout.PREFERRED_SIZE, GroupLayout.PREFERRED_SIZE, GroupLayout.PREFERRED_SIZE
                                        )
                                ).addGap(DendroFactory.MEDIUM_GAP).addGroup(
                                        main.createParallelGroup(GroupLayout.Alignment.LEADING).addComponent(
                                                b, GroupLayout.PREFERRED_SIZE, GroupLayout.PREFERRED_SIZE, GroupLayout.PREFERRED_SIZE
                                        ).addComponent(
                                                b64Pane, GroupLayout.PREFERRED_SIZE, GroupLayout.PREFERRED_SIZE, GroupLayout.PREFERRED_SIZE
                                        )
                                ).addGap(DendroFactory.MEDIUM_GAP).addGroup(
                                        main.createParallelGroup(GroupLayout.Alignment.LEADING).addComponent(
                                                c, GroupLayout.PREFERRED_SIZE, GroupLayout.PREFERRED_SIZE, GroupLayout.PREFERRED_SIZE
                                        ).addComponent(
                                                hexPane, GroupLayout.PREFERRED_SIZE, GroupLayout.PREFERRED_SIZE, GroupLayout.PREFERRED_SIZE
                                        )
                                ).addContainerGap()
                        );
                    }

                    util.addTab("Random Number", pan);
                }

                //HASH
                {
                    JPanel pan = new JPanel();
                    IOPane in = new IOPane(true);
                    JLabel a = new JLabel("SHA 256");
                    JScrollPane twoPane = DendroFactory.getLongField();
                    JTextArea two = (JTextArea) twoPane.getViewport().getView();
                    two.setEditable(false);
                    two.setBackground(DendroFactory.DISABLED);
                    two.addMouseListener(new MouseAdapter() {
                        public void mouseClicked(MouseEvent evt) {
                            two.selectAll();
                        }
                    });
                    JLabel b = new JLabel("SHA 512");
                    JScrollPane fivePane = DendroFactory.getLongField();
                    JTextArea five = (JTextArea) fivePane.getViewport().getView();
                    five.setEditable(false);
                    five.setBackground(DendroFactory.DISABLED);
                    five.addMouseListener(new MouseAdapter() {
                        public void mouseClicked(MouseEvent evt) {
                            five.selectAll();
                        }
                    });

                    JButton button = DendroFactory.getButton("Calculate");
                    button.addActionListener(event -> {
                        ShaHH t = new ShaHH(true), f = new ShaHH(false);
                        try {
                            two.setText(DendroCrypto.toHexString(t.digest(in.CONTENT.getText().getBytes(DendroCrypto.CHARSET))));
                        } catch (NoSuchAlgorithmException e) {
                            two.setText("Your system doesn't seem to support SHA-256");
                        }
                        try {
                            five.setText(DendroCrypto.toHexString(f.digest(in.CONTENT.getText().getBytes(DendroCrypto.CHARSET))));
                        } catch (NoSuchAlgorithmException e) {
                            two.setText("Your system doesn't seem to support SHA-512");
                        }
                    });

                    //Group Layout
                    {
                        GroupLayout main = new GroupLayout(pan);
                        pan.setLayout(main);
                        main.setHorizontalGroup(
                                main.createSequentialGroup().addContainerGap().addGroup(
                                        main.createParallelGroup(GroupLayout.Alignment.CENTER).addComponent(
                                                in, GroupLayout.PREFERRED_SIZE, GroupLayout.PREFERRED_SIZE, Short.MAX_VALUE
                                        ).addGroup(
                                                main.createSequentialGroup().addComponent(
                                                        button, GroupLayout.PREFERRED_SIZE, GroupLayout.PREFERRED_SIZE, GroupLayout.PREFERRED_SIZE
                                                ).addGap(
                                                        DendroFactory.SMALL_GAP, DendroFactory.SMALL_GAP, Short.MAX_VALUE
                                                )
                                        ).addGroup(
                                                main.createSequentialGroup().addGroup(
                                                        main.createParallelGroup(GroupLayout.Alignment.TRAILING).addComponent(
                                                                a, GroupLayout.PREFERRED_SIZE, GroupLayout.PREFERRED_SIZE, GroupLayout.PREFERRED_SIZE
                                                        ).addComponent(
                                                                b, GroupLayout.PREFERRED_SIZE, GroupLayout.PREFERRED_SIZE, GroupLayout.PREFERRED_SIZE
                                                        )
                                                ).addGap(DendroFactory.MEDIUM_GAP).addGroup(
                                                        main.createParallelGroup(GroupLayout.Alignment.LEADING).addComponent(
                                                                twoPane, 200, 200, Short.MAX_VALUE
                                                        ).addComponent(
                                                                fivePane, 200, 200, Short.MAX_VALUE
                                                        )

                                                )
                                        )
                                ).addContainerGap()
                        );
                        main.setVerticalGroup(
                                main.createSequentialGroup().addContainerGap().addComponent(
                                        in, GroupLayout.PREFERRED_SIZE, GroupLayout.PREFERRED_SIZE, Short.MAX_VALUE
                                ).addGap(DendroFactory.MEDIUM_GAP).addComponent(
                                        button, GroupLayout.PREFERRED_SIZE, GroupLayout.PREFERRED_SIZE, GroupLayout.PREFERRED_SIZE
                                ).addGap(DendroFactory.MEDIUM_GAP).addGroup(
                                        main.createParallelGroup(GroupLayout.Alignment.LEADING).addComponent(
                                                a, GroupLayout.PREFERRED_SIZE, GroupLayout.PREFERRED_SIZE, GroupLayout.PREFERRED_SIZE
                                        ).addComponent(
                                                twoPane, GroupLayout.PREFERRED_SIZE, GroupLayout.PREFERRED_SIZE, GroupLayout.PREFERRED_SIZE
                                        )
                                ).addGap(DendroFactory.MEDIUM_GAP).addGroup(
                                        main.createParallelGroup(GroupLayout.Alignment.LEADING).addComponent(
                                                b, GroupLayout.PREFERRED_SIZE, GroupLayout.PREFERRED_SIZE, GroupLayout.PREFERRED_SIZE
                                        ).addComponent(
                                                fivePane, GroupLayout.PREFERRED_SIZE, GroupLayout.PREFERRED_SIZE, GroupLayout.PREFERRED_SIZE
                                        )
                                ).addContainerGap()
                        );
                    }

                    util.addTab("Hash Calculator", pan);
                }

                back.addTab("Utilities", util);
            }

            add(back);
            pack();
        }
    }

    public void encrypt(EncryptionHandler handler, IOPane in, IOPane out, JComboBox<String> radix) {
        try {
            byte[] crypt = handler.encrypt(in.CONTENT.getText().getBytes(DendroCrypto.CHARSET));
            if (radix.getSelectedIndex() == 0) {
                out.CONTENT.setText(Base64.getEncoder().encodeToString(crypt));
            } else {
                out.CONTENT.setText(DendroCrypto.toHexString(crypt));
            }
        } catch (NoSuchPaddingException | NoSuchAlgorithmException e) {
            out.CONTENT.setText("The algorithm, mode, or padding seem not to be supported by your system.");
        } catch (InvalidAlgorithmParameterException e) {
            out.CONTENT.setText("The parameter(s) is(are) invalid.");
        } catch (InvalidKeyException e) {
            out.CONTENT.setText("The key is invalid.");
        } catch (KeysNotSetException e) {
            out.CONTENT.setText("The key (and parameter(s)) is(are) invalid.");
        } catch (IllegalBlockSizeException e) {
            out.CONTENT.setText("Incorrect input size.  Try using padding.");
        } catch (BadPaddingException e) {
            out.CONTENT.setText("The key seems to be incorrect.");
        }
    }

    public void decrypt(EncryptionHandler handler, IOPane in, IOPane out, JComboBox<String> radix) {
        try {
            if (radix.getSelectedIndex() == 0) {
                out.CONTENT.setText(
                        new String(
                                handler.decrypt(
                                        Base64.getDecoder().decode(in.CONTENT.getText())
                                ),
                                DendroCrypto.CHARSET)
                );
            } else {
                String[] bytes = in.CONTENT.getText().split("(?<=\\G..)");
                byte[] input = new byte[bytes.length];
                for (int i = 0; i < bytes.length; i++) {
                    input[i] = (byte) Integer.parseInt(bytes[i], 16);
                }
                out.CONTENT.setText(new String(handler.decrypt(input), DendroCrypto.CHARSET));
            }
        } catch (NoSuchPaddingException | NoSuchAlgorithmException e) {
            out.CONTENT.setText("The algorithm, mode, or padding seem not to be supported by your system.");
        } catch (InvalidAlgorithmParameterException e) {
            out.CONTENT.setText("The parameter(s) is(are) invalid.");
        } catch (InvalidKeyException e) {
            out.CONTENT.setText("The key is invalid.");
        } catch (KeysNotSetException e) {
            out.CONTENT.setText("The key (and parameter(s)) is(are) invalid.");
        } catch (IllegalBlockSizeException e) {
            out.CONTENT.setText("Incorrect input size.  Check to make sure you have typed/copied ciphertext correctly.");
        } catch (BadPaddingException e) {
            out.CONTENT.setText("The key seems to be incorrect.");
        } catch (NumberFormatException e) {
            out.CONTENT.setText("Malformed Hexadecimal input.");
        } catch (IllegalArgumentException e) {
            out.CONTENT.setText("Malformed Base64 input.");
        }
    }
}
