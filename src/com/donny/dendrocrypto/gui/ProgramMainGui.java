package com.donny.dendrocrypto.gui;

import com.donny.dendrocrypto.DendroCrypto;
import com.donny.dendrocrypto.encryption.hash.Sha;
import com.donny.dendrocrypto.encryption.symmetric.Aes;
import com.donny.dendrocrypto.encryption.symmetric.KeysNotSetException;
import com.donny.dendrocrypto.encryption.symmetric.SKEHandler;
import com.donny.dendrocrypto.gui.customswing.HexField;
import com.donny.dendrocrypto.gui.customswing.IOPane;
import com.donny.dendroecc.crypto.DefinedCurve;
import com.donny.dendroecc.crypto.ECCKeyPair;
import com.donny.dendroecc.crypto.Registry;
import com.donny.dendroecc.crypto.Signature;
import com.donny.dendroecc.curves.*;
import com.donny.dendroecc.points.*;
import com.donny.dendroroot.gui.MainGui;
import com.donny.dendroroot.gui.customswing.AlertGui;
import com.donny.dendroroot.gui.customswing.DendroFactory;
import com.donny.dendroroot.gui.form.Validation;
import com.donny.dendroroot.gui.form.ValidationFailedException;
import com.donny.dendroroot.instance.Instance;

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
import java.util.Enumeration;

public class ProgramMainGui extends MainGui {
    private final Instance CURRENT_INSTANCE;
    private final ButtonGroup AES_GROUP = new ButtonGroup();
    private final JPanel AES_CONTENT;
    private final IOPane AES_IN, AES_OUT;
    private final JPasswordField AES_PASS;
    private final HexField AES_KEY, AES_IV;
    private final JComboBox<Integer> AES_KEYSIZE, AES_IV_INDEX;
    private final JComboBox<String> AES_RADIX;
    private final JComboBox<Aes> AES_MODE_IV, AES_MODE_NIV;

    public ProgramMainGui(Instance curInst) {
        super("Dendrogram Cryptography", curInst);

        CURRENT_INSTANCE = curInst;

        setDefaultCloseOperation(DISPOSE_ON_CLOSE);

        //draw gui
        {
            //initialize persistent elements
            {
                AES_IN = new IOPane(true);
                AES_OUT = new IOPane(false);
                AES_PASS = new JPasswordField();
                AES_KEY = new HexField("Key", 16);
                AES_IV = new HexField("Key", 16);
                AES_KEYSIZE = new JComboBox<>();
                AES_KEYSIZE.addItem(16);
                AES_KEYSIZE.addItem(24);
                AES_KEYSIZE.addItem(32);
                AES_IV_INDEX = new JComboBox<>();
                for (int i = 0; i < 17; i++) {
                    AES_IV_INDEX.addItem(i);
                }
                AES_KEYSIZE.addItemListener(event -> AES_KEY.changeSize((Integer) AES_KEYSIZE.getSelectedItem()));
                AES_RADIX = new JComboBox<>();
                AES_RADIX.addItem("Base64");
                AES_RADIX.addItem("Hexadecimal");
                AES_MODE_IV = new JComboBox<>();
                for (Aes handler : DendroCrypto.AES_IV) {
                    AES_MODE_IV.addItem(handler);
                }
                AES_MODE_NIV = new JComboBox<>();
                for (Aes handler : DendroCrypto.AES_NO_IV) {
                    AES_MODE_NIV.addItem(handler);
                }


            }

            JTabbedPane back = new JTabbedPane();
            //AES
            {
                JPanel aes = new JPanel();
                AES_CONTENT = new JPanel();
                AES_CONTENT.setBorder(null);
                JRadioButton pivfh = new JRadioButton("Password, IV From Hash"),
                        piv = new JRadioButton("Password, IV"),
                        kiv = new JRadioButton("Key, IV"),
                        pniv = new JRadioButton("Password, No IV"),
                        kniv = new JRadioButton("Key, No IV");
                AES_GROUP.add(pivfh);
                AES_GROUP.add(piv);
                AES_GROUP.add(kiv);
                AES_GROUP.add(pniv);
                AES_GROUP.add(kniv);

                Enumeration<AbstractButton> radio = AES_GROUP.getElements();
                while (radio.hasMoreElements()) {
                    radio.nextElement().addActionListener(event -> aesButtonChanged());
                }

                pivfh.setSelected(true);
                aesButtonChanged();

                JSeparator sep = new JSeparator();

                //Group Layout
                {
                    GroupLayout main = new GroupLayout(aes);
                    aes.setLayout(main);
                    main.setHorizontalGroup(
                            main.createSequentialGroup().addContainerGap().addGroup(
                                    main.createParallelGroup(GroupLayout.Alignment.LEADING).addComponent(
                                            pivfh, GroupLayout.PREFERRED_SIZE, GroupLayout.PREFERRED_SIZE, GroupLayout.PREFERRED_SIZE
                                    ).addComponent(
                                            piv, GroupLayout.PREFERRED_SIZE, GroupLayout.PREFERRED_SIZE, GroupLayout.PREFERRED_SIZE
                                    ).addComponent(
                                            kiv, GroupLayout.PREFERRED_SIZE, GroupLayout.PREFERRED_SIZE, GroupLayout.PREFERRED_SIZE
                                    ).addComponent(
                                            pniv, GroupLayout.PREFERRED_SIZE, GroupLayout.PREFERRED_SIZE, GroupLayout.PREFERRED_SIZE
                                    ).addComponent(
                                            kniv, GroupLayout.PREFERRED_SIZE, GroupLayout.PREFERRED_SIZE, GroupLayout.PREFERRED_SIZE
                                    ).addComponent(
                                            sep
                                    ).addComponent(
                                            AES_CONTENT, GroupLayout.PREFERRED_SIZE, GroupLayout.PREFERRED_SIZE, Short.MAX_VALUE
                                    )
                            ).addContainerGap()
                    );
                    main.setVerticalGroup(
                            main.createSequentialGroup().addContainerGap().addComponent(
                                    pivfh, GroupLayout.PREFERRED_SIZE, GroupLayout.PREFERRED_SIZE, GroupLayout.PREFERRED_SIZE
                            ).addGap(DendroFactory.SMALL_GAP).addComponent(
                                    piv, GroupLayout.PREFERRED_SIZE, GroupLayout.PREFERRED_SIZE, GroupLayout.PREFERRED_SIZE
                            ).addGap(DendroFactory.SMALL_GAP).addComponent(
                                    kiv, GroupLayout.PREFERRED_SIZE, GroupLayout.PREFERRED_SIZE, GroupLayout.PREFERRED_SIZE
                            ).addGap(DendroFactory.SMALL_GAP).addComponent(
                                    pniv, GroupLayout.PREFERRED_SIZE, GroupLayout.PREFERRED_SIZE, GroupLayout.PREFERRED_SIZE
                            ).addGap(DendroFactory.SMALL_GAP).addComponent(
                                    kniv, GroupLayout.PREFERRED_SIZE, GroupLayout.PREFERRED_SIZE, GroupLayout.PREFERRED_SIZE
                            ).addGap(DendroFactory.SMALL_GAP).addComponent(
                                    sep
                            ).addGap(DendroFactory.SMALL_GAP).addComponent(
                                    AES_CONTENT, GroupLayout.PREFERRED_SIZE, GroupLayout.PREFERRED_SIZE, Short.MAX_VALUE
                            ).addContainerGap()
                    );
                }
                back.addTab("AES", aes);
            }

            //SHA
            {
                JPanel sha = new JPanel();
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
                    Sha t = new Sha(true), f = new Sha(false);
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
                    GroupLayout main = new GroupLayout(sha);
                    sha.setLayout(main);
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
                back.addTab("SHA Hash", sha);
            }

            //ECC
            {
                JPanel ecc = new JPanel();
                JLabel a = new JLabel("Curve Form");
                JLabel b = new JLabel("Defined Curve");
                JLabel c = new JLabel("Radix");
                JLabel d = new JLabel("message");
                JLabel e = new JLabel("Private Key");
                JLabel f = new JLabel("Public Key (X)");
                JLabel g = new JLabel("Public Key (Y)");
                JLabel h = new JLabel("Signature (R)");
                JLabel i = new JLabel("Signature (S)");

                JComboBox<String> form = new JComboBox<>();
                form.addItem("Weierstrass Prime");
                form.addItem("Weierstrass Binary");
                form.addItem("Twisted Edwards");
                form.addItem("Montgomery");
                form.addItem("Edwards");
                JComboBox<String> defCurve = new JComboBox<>();
                form.addActionListener(event -> {
                    switch ((String) form.getSelectedItem()) {
                        case "Weierstrass Prime" -> {
                            defCurve.removeAllItems();
                            for (String curve : DendroCrypto.WEIERSTRASS_PRIME) {
                                defCurve.addItem(curve);
                            }
                        }
                        case "Weierstrass Binary" -> {
                            defCurve.removeAllItems();
                            for (String curve : DendroCrypto.WEIERSTRASS_BINARY) {
                                defCurve.addItem(curve);
                            }
                        }
                        case "Twisted Edwards" -> {
                            defCurve.removeAllItems();
                            for (String curve : DendroCrypto.TWISTED_EDWARDS) {
                                defCurve.addItem(curve);
                            }
                        }
                        case "Montgomery" -> {
                            defCurve.removeAllItems();
                            for (String curve : DendroCrypto.MONTGOMERY) {
                                defCurve.addItem(curve);
                            }
                        }
                        case "Edwards" -> {
                            defCurve.removeAllItems();
                            for (String curve : DendroCrypto.EDWARDS) {
                                defCurve.addItem(curve);
                            }
                        }
                    }
                });
                defCurve.removeAllItems();
                for (String curve : DendroCrypto.WEIERSTRASS_PRIME) {
                    defCurve.addItem(curve);
                }
                JComboBox<String> radix = new JComboBox<>();
                radix.addItem("Base64");
                radix.addItem("Hexadecimal");
                radix.addItem("Decimal");
                JScrollPane messageScroll = DendroFactory.getScrollField();
                JTextArea message = (JTextArea) messageScroll.getViewport().getView();
                JScrollPane privateScroll = DendroFactory.getLongField();
                JTextArea privateKey = (JTextArea) privateScroll.getViewport().getView();
                JScrollPane publicXScroll = DendroFactory.getLongField();
                JTextArea publicX = (JTextArea) publicXScroll.getViewport().getView();
                JScrollPane publicYScroll = DendroFactory.getLongField();
                JTextArea publicY = (JTextArea) publicYScroll.getViewport().getView();
                JScrollPane sigRScroll = DendroFactory.getLongField();
                JTextArea sigR = (JTextArea) sigRScroll.getViewport().getView();
                JScrollPane sigSScroll = DendroFactory.getLongField();
                JTextArea sigS = (JTextArea) sigSScroll.getViewport().getView();

                JButton sign = DendroFactory.getButton("Sign");
                sign.addActionListener(event -> {
                    BigInteger priv = null;
                    try {
                        String privateRaw = Validation.validateString(privateKey);
                        switch ((String) radix.getSelectedItem()) {
                            case "Base64" -> priv = new BigInteger(Base64.getDecoder().decode(privateRaw));
                            case "Hexadecimal" -> priv = new BigInteger(privateRaw, 16);
                            case "Decimal" -> priv = new BigInteger(privateRaw);
                        }
                    } catch (ValidationFailedException ex) {
                        CURRENT_INSTANCE.LOG_HANDLER.error(getClass(), "Private Key must be a number matching the radix");
                    } catch (IllegalArgumentException ex) {
                        CURRENT_INSTANCE.LOG_HANDLER.error(getClass(), "Private Key must be a number matching the radix");
                        privateKey.setBackground(DendroFactory.WRONG);
                    }

                    if (priv != null) {
                        try {
                            Signature sig = Registry.get((String) defCurve.getSelectedItem()).sign(
                                    message.getText().getBytes(DendroCrypto.CHARSET),
                                    priv
                            );
                            String r = "", s = "";
                            switch ((String) radix.getSelectedItem()) {
                                case "Base64" -> {
                                    r = new String(Base64.getEncoder().encode(sig.R.toByteArray()), DendroCrypto.CHARSET);
                                    s = new String(Base64.getEncoder().encode(sig.S.toByteArray()), DendroCrypto.CHARSET);
                                }
                                case "Hexadecimal" -> {
                                    r = sig.R.toString(16);
                                    s = sig.S.toString(16);
                                }
                                case "Decimal" -> {
                                    r = sig.R.toString();
                                    s = sig.S.toString();
                                }
                            }
                            sigR.setText(r);
                            sigS.setText(s);
                        } catch (NoSuchAlgorithmException ex) {
                            CURRENT_INSTANCE.LOG_HANDLER.error(getClass(), "Your system does not support SHA-256");
                            new AlertGui(this, "Your system does not support SHA-256", CURRENT_INSTANCE).setVisible(true);
                        }
                    }
                });
                JButton verify = DendroFactory.getButton("Verify");
                verify.addActionListener(event -> {
                    BigInteger x = null, y = null;
                    String xRaw = null, yRaw;
                    try {
                        xRaw = Validation.validateString(publicX);
                        yRaw = Validation.validateString(publicY);
                        switch ((String) radix.getSelectedItem()) {
                            case "Base64" -> {
                                x = new BigInteger(Base64.getDecoder().decode(xRaw));
                                y = new BigInteger(Base64.getDecoder().decode(yRaw));
                            }
                            case "Hexadecimal" -> {
                                x = new BigInteger(xRaw, 16);
                                y = new BigInteger(yRaw, 16);
                            }
                            case "Decimal" -> {
                                x = new BigInteger(xRaw);
                                y = new BigInteger(yRaw);
                            }
                        }
                    } catch (ValidationFailedException ex) {
                        CURRENT_INSTANCE.LOG_HANDLER.error(getClass(), "Public Key must be a number matching the radix");
                    } catch (IllegalArgumentException ex) {
                        CURRENT_INSTANCE.LOG_HANDLER.error(getClass(), "Public Key must be a number matching the radix");
                        if (xRaw == null) {
                            publicX.setBackground(DendroFactory.WRONG);
                        } else {
                            publicY.setBackground(DendroFactory.WRONG);
                        }
                    }

                    BigInteger r = null, s = null;
                    String rRaw = null, sRaw;
                    try {
                        rRaw = Validation.validateString(sigR);
                        sRaw = Validation.validateString(sigS);
                        switch ((String) radix.getSelectedItem()) {
                            case "Base64" -> {
                                r = new BigInteger(Base64.getDecoder().decode(rRaw));
                                s = new BigInteger(Base64.getDecoder().decode(sRaw));
                            }
                            case "Hexadecimal" -> {
                                r = new BigInteger(rRaw, 16);
                                s = new BigInteger(sRaw, 16);
                            }
                            case "Decimal" -> {
                                r = new BigInteger(rRaw);
                                s = new BigInteger(sRaw);
                            }
                        }
                    } catch (ValidationFailedException ex) {
                        CURRENT_INSTANCE.LOG_HANDLER.error(getClass(), "Signature must be a number matching the radix");
                    } catch (IllegalArgumentException ex) {
                        CURRENT_INSTANCE.LOG_HANDLER.error(getClass(), "Signature must be a number matching the radix");
                        if (rRaw == null) {
                            sigR.setBackground(DendroFactory.WRONG);
                        } else {
                            sigS.setBackground(DendroFactory.WRONG);
                        }
                    }

                    DefinedCurve curve = Registry.get((String) defCurve.getSelectedItem());
                    ECPoint pub = null;
                    if (curve.E instanceof WeierstrassPrime) {
                        pub = new WpECPoint(x, y, (WeierstrassPrime) curve.E);
                    } else if (curve.E instanceof WeierstrassBinary) {
                        pub = new WbECPoint(x, y, (WeierstrassBinary) curve.E);
                    } else if (curve.E instanceof TwistedEdwards) {
                        pub = new TeECPoint(x, y, (TwistedEdwards) curve.E);
                    } else if (curve.E instanceof Montgomery) {
                        pub = new MECPoint(x, y, (Montgomery) curve.E);
                    } else if (curve.E instanceof Edwards) {
                        pub = new EdECPoint(x, y, (Edwards) curve.E);
                    }
                    if (pub != null) {
                        try {
                            boolean cor = curve.verifySignature(
                                    message.getText().getBytes(DendroCrypto.CHARSET),
                                    new Signature(r, s),
                                    pub
                            );
                            new AlertGui(this, "Signature " + (cor ? "is Valid" : "is not Valid"), CURRENT_INSTANCE).setVisible(true);
                        } catch (NoSuchAlgorithmException ex) {
                            CURRENT_INSTANCE.LOG_HANDLER.error(getClass(), "Your system does not support SHA-256");
                            new AlertGui(this, "Your system does not support SHA-256", CURRENT_INSTANCE).setVisible(true);
                        }
                    }
                });
                JButton gen = DendroFactory.getButton("Generate Keypair");
                gen.addActionListener(event -> {
                    ECCKeyPair pair = Registry.get((String) defCurve.getSelectedItem()).generateKeyPair();
                    switch ((String) radix.getSelectedItem()) {
                        case "Base64" -> {
                            privateKey.setText(new String(Base64.getEncoder().encode(pair.PRIVATE.toByteArray()), DendroCrypto.CHARSET));
                            publicX.setText(new String(Base64.getEncoder().encode(pair.PUBLIC.X.toByteArray()), DendroCrypto.CHARSET));
                            publicY.setText(new String(Base64.getEncoder().encode(pair.PUBLIC.Y.toByteArray()), DendroCrypto.CHARSET));
                        }
                        case "Hexadecimal" -> {
                            privateKey.setText(pair.PRIVATE.toString(16));
                            publicX.setText(pair.PUBLIC.X.toString(16));
                            publicY.setText(pair.PUBLIC.Y.toString(16));
                        }
                        case "Decimal" -> {
                            privateKey.setText(pair.PRIVATE.toString());
                            publicX.setText(pair.PUBLIC.X.toString());
                            publicY.setText(pair.PUBLIC.Y.toString());
                        }
                    }
                });

                //Group Layout
                {
                    GroupLayout main = new GroupLayout(ecc);
                    ecc.setLayout(main);
                    main.setHorizontalGroup(
                            main.createSequentialGroup().addContainerGap().addGroup(
                                    main.createParallelGroup(GroupLayout.Alignment.CENTER).addGroup(
                                            main.createSequentialGroup().addGroup(
                                                    main.createParallelGroup(GroupLayout.Alignment.TRAILING).addComponent(
                                                            a, GroupLayout.PREFERRED_SIZE, GroupLayout.PREFERRED_SIZE, GroupLayout.PREFERRED_SIZE
                                                    ).addComponent(
                                                            b, GroupLayout.PREFERRED_SIZE, GroupLayout.PREFERRED_SIZE, GroupLayout.PREFERRED_SIZE
                                                    ).addComponent(
                                                            c, GroupLayout.PREFERRED_SIZE, GroupLayout.PREFERRED_SIZE, GroupLayout.PREFERRED_SIZE
                                                    ).addComponent(
                                                            d, GroupLayout.PREFERRED_SIZE, GroupLayout.PREFERRED_SIZE, GroupLayout.PREFERRED_SIZE
                                                    ).addComponent(
                                                            e, GroupLayout.PREFERRED_SIZE, GroupLayout.PREFERRED_SIZE, GroupLayout.PREFERRED_SIZE
                                                    ).addComponent(
                                                            f, GroupLayout.PREFERRED_SIZE, GroupLayout.PREFERRED_SIZE, GroupLayout.PREFERRED_SIZE
                                                    ).addComponent(
                                                            g, GroupLayout.PREFERRED_SIZE, GroupLayout.PREFERRED_SIZE, GroupLayout.PREFERRED_SIZE
                                                    ).addComponent(
                                                            h, GroupLayout.PREFERRED_SIZE, GroupLayout.PREFERRED_SIZE, GroupLayout.PREFERRED_SIZE
                                                    ).addComponent(
                                                            i, GroupLayout.PREFERRED_SIZE, GroupLayout.PREFERRED_SIZE, GroupLayout.PREFERRED_SIZE
                                                    )
                                            ).addGap(DendroFactory.SMALL_GAP).addGroup(
                                                    main.createParallelGroup(GroupLayout.Alignment.LEADING).addComponent(
                                                            form, GroupLayout.PREFERRED_SIZE, GroupLayout.PREFERRED_SIZE, Short.MAX_VALUE
                                                    ).addComponent(
                                                            defCurve, GroupLayout.PREFERRED_SIZE, GroupLayout.PREFERRED_SIZE, Short.MAX_VALUE
                                                    ).addComponent(
                                                            radix, GroupLayout.PREFERRED_SIZE, GroupLayout.PREFERRED_SIZE, Short.MAX_VALUE
                                                    ).addComponent(
                                                            messageScroll, GroupLayout.PREFERRED_SIZE, GroupLayout.PREFERRED_SIZE, Short.MAX_VALUE
                                                    ).addComponent(
                                                            privateScroll, GroupLayout.PREFERRED_SIZE, GroupLayout.PREFERRED_SIZE, Short.MAX_VALUE
                                                    ).addComponent(
                                                            publicXScroll, GroupLayout.PREFERRED_SIZE, GroupLayout.PREFERRED_SIZE, Short.MAX_VALUE
                                                    ).addComponent(
                                                            publicYScroll, GroupLayout.PREFERRED_SIZE, GroupLayout.PREFERRED_SIZE, Short.MAX_VALUE
                                                    ).addComponent(
                                                            sigRScroll, GroupLayout.PREFERRED_SIZE, GroupLayout.PREFERRED_SIZE, Short.MAX_VALUE
                                                    ).addComponent(
                                                            sigSScroll, GroupLayout.PREFERRED_SIZE, GroupLayout.PREFERRED_SIZE, Short.MAX_VALUE
                                                    )
                                            )
                                    ).addGroup(
                                            main.createSequentialGroup().addComponent(
                                                    gen, GroupLayout.PREFERRED_SIZE, GroupLayout.PREFERRED_SIZE, GroupLayout.PREFERRED_SIZE
                                            ).addGap(
                                                    DendroFactory.SMALL_GAP, DendroFactory.SMALL_GAP, Short.MAX_VALUE
                                            ).addComponent(
                                                    sign, GroupLayout.PREFERRED_SIZE, GroupLayout.PREFERRED_SIZE, GroupLayout.PREFERRED_SIZE
                                            ).addGap(
                                                    DendroFactory.SMALL_GAP, DendroFactory.SMALL_GAP, Short.MAX_VALUE
                                            ).addComponent(
                                                    verify, GroupLayout.PREFERRED_SIZE, GroupLayout.PREFERRED_SIZE, GroupLayout.PREFERRED_SIZE
                                            )
                                    )
                            ).addContainerGap()
                    );
                    main.setVerticalGroup(
                            main.createSequentialGroup().addContainerGap().addGroup(
                                    main.createParallelGroup(GroupLayout.Alignment.CENTER).addComponent(
                                            a, GroupLayout.PREFERRED_SIZE, GroupLayout.PREFERRED_SIZE, GroupLayout.PREFERRED_SIZE
                                    ).addComponent(
                                            form, GroupLayout.PREFERRED_SIZE, GroupLayout.PREFERRED_SIZE, GroupLayout.PREFERRED_SIZE
                                    )
                            ).addGap(DendroFactory.SMALL_GAP).addGroup(
                                    main.createParallelGroup(GroupLayout.Alignment.CENTER).addComponent(
                                            b, GroupLayout.PREFERRED_SIZE, GroupLayout.PREFERRED_SIZE, GroupLayout.PREFERRED_SIZE
                                    ).addComponent(
                                            defCurve, GroupLayout.PREFERRED_SIZE, GroupLayout.PREFERRED_SIZE, GroupLayout.PREFERRED_SIZE
                                    )
                            ).addGap(DendroFactory.SMALL_GAP).addGroup(
                                    main.createParallelGroup(GroupLayout.Alignment.CENTER).addComponent(
                                            c, GroupLayout.PREFERRED_SIZE, GroupLayout.PREFERRED_SIZE, GroupLayout.PREFERRED_SIZE
                                    ).addComponent(
                                            radix, GroupLayout.PREFERRED_SIZE, GroupLayout.PREFERRED_SIZE, GroupLayout.PREFERRED_SIZE
                                    )
                            ).addGap(DendroFactory.SMALL_GAP).addGroup(
                                    main.createParallelGroup(GroupLayout.Alignment.LEADING).addComponent(
                                            d, GroupLayout.PREFERRED_SIZE, GroupLayout.PREFERRED_SIZE, GroupLayout.PREFERRED_SIZE
                                    ).addComponent(
                                            messageScroll, GroupLayout.PREFERRED_SIZE, GroupLayout.PREFERRED_SIZE, Short.MAX_VALUE
                                    )
                            ).addGap(DendroFactory.SMALL_GAP).addGroup(
                                    main.createParallelGroup(GroupLayout.Alignment.LEADING).addComponent(
                                            e, GroupLayout.PREFERRED_SIZE, GroupLayout.PREFERRED_SIZE, GroupLayout.PREFERRED_SIZE
                                    ).addComponent(
                                            privateScroll, GroupLayout.PREFERRED_SIZE, GroupLayout.PREFERRED_SIZE, GroupLayout.PREFERRED_SIZE
                                    )
                            ).addGap(DendroFactory.SMALL_GAP).addGroup(
                                    main.createParallelGroup(GroupLayout.Alignment.LEADING).addComponent(
                                            f, GroupLayout.PREFERRED_SIZE, GroupLayout.PREFERRED_SIZE, GroupLayout.PREFERRED_SIZE
                                    ).addComponent(
                                            publicXScroll, GroupLayout.PREFERRED_SIZE, GroupLayout.PREFERRED_SIZE, GroupLayout.PREFERRED_SIZE
                                    )
                            ).addGap(DendroFactory.SMALL_GAP).addGroup(
                                    main.createParallelGroup(GroupLayout.Alignment.LEADING).addComponent(
                                            g, GroupLayout.PREFERRED_SIZE, GroupLayout.PREFERRED_SIZE, GroupLayout.PREFERRED_SIZE
                                    ).addComponent(
                                            publicYScroll, GroupLayout.PREFERRED_SIZE, GroupLayout.PREFERRED_SIZE, GroupLayout.PREFERRED_SIZE
                                    )
                            ).addGap(DendroFactory.SMALL_GAP).addGroup(
                                    main.createParallelGroup(GroupLayout.Alignment.LEADING).addComponent(
                                            h, GroupLayout.PREFERRED_SIZE, GroupLayout.PREFERRED_SIZE, GroupLayout.PREFERRED_SIZE
                                    ).addComponent(
                                            sigRScroll, GroupLayout.PREFERRED_SIZE, GroupLayout.PREFERRED_SIZE, GroupLayout.PREFERRED_SIZE
                                    )
                            ).addGap(DendroFactory.SMALL_GAP).addGroup(
                                    main.createParallelGroup(GroupLayout.Alignment.LEADING).addComponent(
                                            i, GroupLayout.PREFERRED_SIZE, GroupLayout.PREFERRED_SIZE, GroupLayout.PREFERRED_SIZE
                                    ).addComponent(
                                            sigSScroll, GroupLayout.PREFERRED_SIZE, GroupLayout.PREFERRED_SIZE, GroupLayout.PREFERRED_SIZE
                                    )
                            ).addGap(DendroFactory.MEDIUM_GAP).addGroup(
                                    main.createParallelGroup(GroupLayout.Alignment.CENTER).addComponent(
                                            gen, GroupLayout.PREFERRED_SIZE, GroupLayout.PREFERRED_SIZE, GroupLayout.PREFERRED_SIZE
                                    ).addComponent(
                                            sign, GroupLayout.PREFERRED_SIZE, GroupLayout.PREFERRED_SIZE, GroupLayout.PREFERRED_SIZE
                                    ).addComponent(
                                            verify, GroupLayout.PREFERRED_SIZE, GroupLayout.PREFERRED_SIZE, GroupLayout.PREFERRED_SIZE
                                    )
                            ).addContainerGap()
                    );
                }
                back.add("ECDSA", ecc);
            }

            //Rand
            {
                JPanel rand = new JPanel();
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
                    GroupLayout main = new GroupLayout(rand);
                    rand.setLayout(main);
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

                back.addTab("Random", rand);
            }

            add(back);
            pack();
        }
    }

    private void aesButtonChanged() {
        int x = getLocation().x + getWidth() / 2, y = getLocation().y + getHeight() / 2;
        switch (getSelectedRadio()) {
            case "Password, IV From Hash" -> setAesPIVfH();
            case "Password, IV" -> setAesPIV();
            case "Key, IV" -> setAesKIV();
            case "Password, No IV" -> setAesPnIV();
            case "Key, No IV" -> setAesKnIV();
        }
        pack();
        setLocation(x - getWidth() / 2, y - getHeight() / 2);
    }

    private String getSelectedRadio() {
        Enumeration<AbstractButton> radio = AES_GROUP.getElements();
        while (radio.hasMoreElements()) {
            AbstractButton button = radio.nextElement();

            if (button.isSelected()) {
                return button.getText();
            }
        }
        return "";
    }

    public void encrypt(SKEHandler handler, IOPane in, IOPane out, JComboBox<String> radix) {
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

    public void decrypt(SKEHandler handler, IOPane in, IOPane out, JComboBox<String> radix) {
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

    private void setAesPIVfH() {
        JLabel a = new JLabel("SHA-256 Hashed Password With Integrated IV");
        JLabel b = new JLabel("Password");
        JLabel c = new JLabel("IV Index");
        JLabel d = new JLabel("Mode");
        JLabel e = new JLabel("Key Size");
        JButton enc = DendroFactory.getButton("Encrypt"), dec = DendroFactory.getButton("Decrypt");

        enc.addActionListener(event -> {
            Aes handler = (Aes) AES_MODE_IV.getSelectedItem();
            try {
                handler.changeKey(AES_PASS.getPassword(), (Integer) AES_KEYSIZE.getSelectedItem(), (Integer) AES_IV_INDEX.getSelectedItem());
                encrypt(handler, AES_IN, AES_OUT, AES_RADIX);
            } catch (NoSuchAlgorithmException ex) {
                AES_OUT.CONTENT.setText("SHA-256 seems not to be supported by your system.");
            }
        });
        dec.addActionListener(event -> {
            Aes handler = (Aes) AES_MODE_IV.getSelectedItem();
            try {
                handler.changeKey(AES_PASS.getPassword(), (Integer) AES_KEYSIZE.getSelectedItem(), (Integer) AES_IV_INDEX.getSelectedItem());
                decrypt(handler, AES_IN, AES_OUT, AES_RADIX);
            } catch (NoSuchAlgorithmException ex) {
                AES_OUT.CONTENT.setText("SHA-256 seems not to be supported by your system.");
            }
        });

        //Group Layout
        {
            JSeparator sep = new JSeparator();

            AES_CONTENT.removeAll();
            GroupLayout main = new GroupLayout(AES_CONTENT);
            AES_CONTENT.setLayout(main);
            main.setHorizontalGroup(
                    main.createSequentialGroup().addGroup(
                            main.createParallelGroup(GroupLayout.Alignment.LEADING).addComponent(
                                    a, GroupLayout.PREFERRED_SIZE, GroupLayout.PREFERRED_SIZE, GroupLayout.PREFERRED_SIZE
                            ).addComponent(
                                    sep
                            ).addComponent(
                                    AES_IN, GroupLayout.PREFERRED_SIZE, GroupLayout.PREFERRED_SIZE, Short.MAX_VALUE
                            ).addGroup(
                                    main.createSequentialGroup().addComponent(
                                            b, GroupLayout.PREFERRED_SIZE, GroupLayout.PREFERRED_SIZE, GroupLayout.PREFERRED_SIZE
                                    ).addGap(DendroFactory.SMALL_GAP).addComponent(
                                            AES_PASS, GroupLayout.PREFERRED_SIZE, GroupLayout.PREFERRED_SIZE, Short.MAX_VALUE
                                    ).addGap(DendroFactory.MEDIUM_GAP).addComponent(
                                            c, GroupLayout.PREFERRED_SIZE, GroupLayout.PREFERRED_SIZE, GroupLayout.PREFERRED_SIZE
                                    ).addGap(DendroFactory.SMALL_GAP).addComponent(
                                            AES_IV_INDEX, GroupLayout.PREFERRED_SIZE, GroupLayout.PREFERRED_SIZE, GroupLayout.PREFERRED_SIZE
                                    )
                            ).addGroup(
                                    main.createSequentialGroup().addComponent(
                                            d, GroupLayout.PREFERRED_SIZE, GroupLayout.PREFERRED_SIZE, GroupLayout.PREFERRED_SIZE
                                    ).addGap(DendroFactory.SMALL_GAP).addComponent(
                                            AES_MODE_IV, GroupLayout.PREFERRED_SIZE, GroupLayout.PREFERRED_SIZE, GroupLayout.PREFERRED_SIZE
                                    ).addGap(
                                            DendroFactory.MEDIUM_GAP, DendroFactory.MEDIUM_GAP, Short.MAX_VALUE
                                    ).addComponent(
                                            e, GroupLayout.PREFERRED_SIZE, GroupLayout.PREFERRED_SIZE, GroupLayout.PREFERRED_SIZE
                                    ).addGap(DendroFactory.SMALL_GAP).addComponent(
                                            AES_KEYSIZE, GroupLayout.PREFERRED_SIZE, GroupLayout.PREFERRED_SIZE, GroupLayout.PREFERRED_SIZE
                                    )
                            ).addGroup(
                                    main.createSequentialGroup().addGap(
                                            DendroFactory.MEDIUM_GAP, DendroFactory.MEDIUM_GAP, Short.MAX_VALUE
                                    ).addComponent(
                                            enc, GroupLayout.PREFERRED_SIZE, GroupLayout.PREFERRED_SIZE, GroupLayout.PREFERRED_SIZE
                                    ).addGap(DendroFactory.SMALL_GAP).addComponent(
                                            AES_RADIX, GroupLayout.PREFERRED_SIZE, GroupLayout.PREFERRED_SIZE, GroupLayout.PREFERRED_SIZE
                                    ).addGap(DendroFactory.SMALL_GAP).addComponent(
                                            dec, GroupLayout.PREFERRED_SIZE, GroupLayout.PREFERRED_SIZE, GroupLayout.PREFERRED_SIZE
                                    )
                            ).addComponent(
                                    AES_OUT, GroupLayout.PREFERRED_SIZE, GroupLayout.PREFERRED_SIZE, Short.MAX_VALUE
                            )
                    )
            );
            main.setVerticalGroup(
                    main.createSequentialGroup().addComponent(
                            a, GroupLayout.PREFERRED_SIZE, GroupLayout.PREFERRED_SIZE, GroupLayout.PREFERRED_SIZE
                    ).addGap(DendroFactory.SMALL_GAP).addComponent(
                            sep
                    ).addGap(DendroFactory.SMALL_GAP).addComponent(
                            AES_IN, GroupLayout.PREFERRED_SIZE, GroupLayout.PREFERRED_SIZE, Short.MAX_VALUE
                    ).addGap(DendroFactory.MEDIUM_GAP).addGroup(
                            main.createParallelGroup(GroupLayout.Alignment.CENTER).addComponent(
                                    b, GroupLayout.PREFERRED_SIZE, GroupLayout.PREFERRED_SIZE, GroupLayout.PREFERRED_SIZE
                            ).addComponent(
                                    AES_PASS, GroupLayout.PREFERRED_SIZE, GroupLayout.PREFERRED_SIZE, GroupLayout.PREFERRED_SIZE
                            ).addComponent(
                                    c, GroupLayout.PREFERRED_SIZE, GroupLayout.PREFERRED_SIZE, GroupLayout.PREFERRED_SIZE
                            ).addComponent(
                                    AES_IV_INDEX, GroupLayout.PREFERRED_SIZE, GroupLayout.PREFERRED_SIZE, GroupLayout.PREFERRED_SIZE
                            )
                    ).addGap(DendroFactory.MEDIUM_GAP).addGroup(
                            main.createParallelGroup(GroupLayout.Alignment.CENTER).addComponent(
                                    d, GroupLayout.PREFERRED_SIZE, GroupLayout.PREFERRED_SIZE, GroupLayout.PREFERRED_SIZE
                            ).addComponent(
                                    AES_MODE_IV, GroupLayout.PREFERRED_SIZE, GroupLayout.PREFERRED_SIZE, GroupLayout.PREFERRED_SIZE
                            ).addComponent(
                                    e, GroupLayout.PREFERRED_SIZE, GroupLayout.PREFERRED_SIZE, GroupLayout.PREFERRED_SIZE
                            ).addComponent(
                                    AES_KEYSIZE, GroupLayout.PREFERRED_SIZE, GroupLayout.PREFERRED_SIZE, GroupLayout.PREFERRED_SIZE
                            )
                    ).addGap(DendroFactory.MEDIUM_GAP).addGroup(
                            main.createParallelGroup(GroupLayout.Alignment.CENTER).addComponent(
                                    enc, GroupLayout.PREFERRED_SIZE, GroupLayout.PREFERRED_SIZE, GroupLayout.PREFERRED_SIZE
                            ).addComponent(
                                    AES_RADIX, GroupLayout.PREFERRED_SIZE, GroupLayout.PREFERRED_SIZE, GroupLayout.PREFERRED_SIZE
                            ).addComponent(
                                    dec, GroupLayout.PREFERRED_SIZE, GroupLayout.PREFERRED_SIZE, GroupLayout.PREFERRED_SIZE
                            )
                    ).addGap(DendroFactory.MEDIUM_GAP).addComponent(
                            AES_OUT, GroupLayout.PREFERRED_SIZE, GroupLayout.PREFERRED_SIZE, Short.MAX_VALUE
                    )
            );
        }
    }

    private void setAesPIV() {
        JLabel a = new JLabel("SHA-256 Hashed Password With Specified IV");
        JLabel b = new JLabel("Password");
        JLabel d = new JLabel("Mode");
        JLabel e = new JLabel("Key Size");
        JButton enc = DendroFactory.getButton("Encrypt"), dec = DendroFactory.getButton("Decrypt");

        enc.addActionListener(event -> {
            Aes handler = (Aes) AES_MODE_IV.getSelectedItem();
            try {
                handler.changeKey(AES_PASS.getPassword(), (Integer) AES_KEYSIZE.getSelectedItem(), AES_IV.getBytes());
                encrypt(handler, AES_IN, AES_OUT, AES_RADIX);
            } catch (NoSuchAlgorithmException ex) {
                AES_OUT.CONTENT.setText("SHA-256 seems not to be supported by your system.");
            }
        });
        dec.addActionListener(event -> {
            Aes handler = (Aes) AES_MODE_IV.getSelectedItem();
            try {
                handler.changeKey(AES_PASS.getPassword(), (Integer) AES_KEYSIZE.getSelectedItem(), AES_IV.getBytes());
                decrypt(handler, AES_IN, AES_OUT, AES_RADIX);
            } catch (NoSuchAlgorithmException ex) {
                AES_OUT.CONTENT.setText("SHA-256 seems not to be supported by your system.");
            }
        });

        //Group Layout
        {
            JSeparator sep = new JSeparator();

            AES_CONTENT.removeAll();
            GroupLayout main = new GroupLayout(AES_CONTENT);
            AES_CONTENT.setLayout(main);
            main.setHorizontalGroup(
                    main.createSequentialGroup().addGroup(
                            main.createParallelGroup(GroupLayout.Alignment.LEADING).addComponent(
                                    a, GroupLayout.PREFERRED_SIZE, GroupLayout.PREFERRED_SIZE, GroupLayout.PREFERRED_SIZE
                            ).addComponent(
                                    sep
                            ).addComponent(
                                    AES_IN, GroupLayout.PREFERRED_SIZE, GroupLayout.PREFERRED_SIZE, Short.MAX_VALUE
                            ).addGroup(
                                    main.createSequentialGroup().addComponent(
                                            b, GroupLayout.PREFERRED_SIZE, GroupLayout.PREFERRED_SIZE, GroupLayout.PREFERRED_SIZE
                                    ).addGap(DendroFactory.SMALL_GAP).addComponent(
                                            AES_PASS, GroupLayout.PREFERRED_SIZE, GroupLayout.PREFERRED_SIZE, Short.MAX_VALUE
                                    )
                            ).addComponent(
                                    AES_IV, GroupLayout.PREFERRED_SIZE, GroupLayout.PREFERRED_SIZE, Short.MAX_VALUE
                            ).addGroup(
                                    main.createSequentialGroup().addComponent(
                                            d, GroupLayout.PREFERRED_SIZE, GroupLayout.PREFERRED_SIZE, GroupLayout.PREFERRED_SIZE
                                    ).addGap(DendroFactory.SMALL_GAP).addComponent(
                                            AES_MODE_IV, GroupLayout.PREFERRED_SIZE, GroupLayout.PREFERRED_SIZE, GroupLayout.PREFERRED_SIZE
                                    ).addGap(
                                            DendroFactory.MEDIUM_GAP, DendroFactory.MEDIUM_GAP, Short.MAX_VALUE
                                    ).addComponent(
                                            e, GroupLayout.PREFERRED_SIZE, GroupLayout.PREFERRED_SIZE, GroupLayout.PREFERRED_SIZE
                                    ).addGap(DendroFactory.SMALL_GAP).addComponent(
                                            AES_KEYSIZE, GroupLayout.PREFERRED_SIZE, GroupLayout.PREFERRED_SIZE, GroupLayout.PREFERRED_SIZE
                                    )
                            ).addGroup(
                                    main.createSequentialGroup().addGap(
                                            DendroFactory.MEDIUM_GAP, DendroFactory.MEDIUM_GAP, Short.MAX_VALUE
                                    ).addComponent(
                                            enc, GroupLayout.PREFERRED_SIZE, GroupLayout.PREFERRED_SIZE, GroupLayout.PREFERRED_SIZE
                                    ).addGap(DendroFactory.SMALL_GAP).addComponent(
                                            AES_RADIX, GroupLayout.PREFERRED_SIZE, GroupLayout.PREFERRED_SIZE, GroupLayout.PREFERRED_SIZE
                                    ).addGap(DendroFactory.SMALL_GAP).addComponent(
                                            dec, GroupLayout.PREFERRED_SIZE, GroupLayout.PREFERRED_SIZE, GroupLayout.PREFERRED_SIZE
                                    )
                            ).addComponent(
                                    AES_OUT, GroupLayout.PREFERRED_SIZE, GroupLayout.PREFERRED_SIZE, Short.MAX_VALUE
                            )
                    )
            );
            main.setVerticalGroup(
                    main.createSequentialGroup().addComponent(
                            a, GroupLayout.PREFERRED_SIZE, GroupLayout.PREFERRED_SIZE, GroupLayout.PREFERRED_SIZE
                    ).addGap(DendroFactory.SMALL_GAP).addComponent(
                            sep
                    ).addGap(DendroFactory.SMALL_GAP).addComponent(
                            AES_IN, GroupLayout.PREFERRED_SIZE, GroupLayout.PREFERRED_SIZE, Short.MAX_VALUE
                    ).addGap(DendroFactory.MEDIUM_GAP).addGroup(
                            main.createParallelGroup(GroupLayout.Alignment.CENTER).addComponent(
                                    b, GroupLayout.PREFERRED_SIZE, GroupLayout.PREFERRED_SIZE, GroupLayout.PREFERRED_SIZE
                            ).addComponent(
                                    AES_PASS, GroupLayout.PREFERRED_SIZE, GroupLayout.PREFERRED_SIZE, GroupLayout.PREFERRED_SIZE
                            )
                    ).addGap(DendroFactory.MEDIUM_GAP).addComponent(
                            AES_IV, GroupLayout.PREFERRED_SIZE, GroupLayout.PREFERRED_SIZE, GroupLayout.PREFERRED_SIZE
                    ).addGap(DendroFactory.MEDIUM_GAP).addGroup(
                            main.createParallelGroup(GroupLayout.Alignment.CENTER).addComponent(
                                    d, GroupLayout.PREFERRED_SIZE, GroupLayout.PREFERRED_SIZE, GroupLayout.PREFERRED_SIZE
                            ).addComponent(
                                    AES_MODE_IV, GroupLayout.PREFERRED_SIZE, GroupLayout.PREFERRED_SIZE, GroupLayout.PREFERRED_SIZE
                            ).addComponent(
                                    e, GroupLayout.PREFERRED_SIZE, GroupLayout.PREFERRED_SIZE, GroupLayout.PREFERRED_SIZE
                            ).addComponent(
                                    AES_KEYSIZE, GroupLayout.PREFERRED_SIZE, GroupLayout.PREFERRED_SIZE, GroupLayout.PREFERRED_SIZE
                            )
                    ).addGap(DendroFactory.MEDIUM_GAP).addGroup(
                            main.createParallelGroup(GroupLayout.Alignment.CENTER).addComponent(
                                    enc, GroupLayout.PREFERRED_SIZE, GroupLayout.PREFERRED_SIZE, GroupLayout.PREFERRED_SIZE
                            ).addComponent(
                                    AES_RADIX, GroupLayout.PREFERRED_SIZE, GroupLayout.PREFERRED_SIZE, GroupLayout.PREFERRED_SIZE
                            ).addComponent(
                                    dec, GroupLayout.PREFERRED_SIZE, GroupLayout.PREFERRED_SIZE, GroupLayout.PREFERRED_SIZE
                            )
                    ).addGap(DendroFactory.MEDIUM_GAP).addComponent(
                            AES_OUT, GroupLayout.PREFERRED_SIZE, GroupLayout.PREFERRED_SIZE, Short.MAX_VALUE
                    )
            );
        }
    }

    private void setAesKIV() {
        JLabel a = new JLabel("Specified Key With Specified IV");
        JLabel d = new JLabel("Mode");
        JLabel e = new JLabel("Key Size");
        JButton enc = DendroFactory.getButton("Encrypt"), dec = DendroFactory.getButton("Decrypt");

        enc.addActionListener(event -> {
            Aes handler = (Aes) AES_MODE_IV.getSelectedItem();
            handler.changeKey(AES_KEY.getBytes(), AES_IV.getBytes());
            encrypt(handler, AES_IN, AES_OUT, AES_RADIX);
        });
        dec.addActionListener(event -> {
            Aes handler = (Aes) AES_MODE_IV.getSelectedItem();
            handler.changeKey(AES_KEY.getBytes(), AES_IV.getBytes());
            decrypt(handler, AES_IN, AES_OUT, AES_RADIX);
        });

        //Group Layout
        {
            JSeparator sep = new JSeparator();

            AES_CONTENT.removeAll();
            GroupLayout main = new GroupLayout(AES_CONTENT);
            AES_CONTENT.setLayout(main);
            main.setHorizontalGroup(
                    main.createSequentialGroup().addGroup(
                            main.createParallelGroup(GroupLayout.Alignment.LEADING).addComponent(
                                    a, GroupLayout.PREFERRED_SIZE, GroupLayout.PREFERRED_SIZE, GroupLayout.PREFERRED_SIZE
                            ).addComponent(
                                    sep
                            ).addComponent(
                                    AES_IN, GroupLayout.PREFERRED_SIZE, GroupLayout.PREFERRED_SIZE, Short.MAX_VALUE
                            ).addComponent(
                                    AES_KEY, GroupLayout.PREFERRED_SIZE, GroupLayout.PREFERRED_SIZE, Short.MAX_VALUE
                            ).addComponent(
                                    AES_IV, GroupLayout.PREFERRED_SIZE, GroupLayout.PREFERRED_SIZE, Short.MAX_VALUE
                            ).addGroup(
                                    main.createSequentialGroup().addComponent(
                                            d, GroupLayout.PREFERRED_SIZE, GroupLayout.PREFERRED_SIZE, GroupLayout.PREFERRED_SIZE
                                    ).addGap(DendroFactory.SMALL_GAP).addComponent(
                                            AES_MODE_IV, GroupLayout.PREFERRED_SIZE, GroupLayout.PREFERRED_SIZE, GroupLayout.PREFERRED_SIZE
                                    ).addGap(
                                            DendroFactory.MEDIUM_GAP, DendroFactory.MEDIUM_GAP, Short.MAX_VALUE
                                    ).addComponent(
                                            e, GroupLayout.PREFERRED_SIZE, GroupLayout.PREFERRED_SIZE, GroupLayout.PREFERRED_SIZE
                                    ).addGap(DendroFactory.SMALL_GAP).addComponent(
                                            AES_KEYSIZE, GroupLayout.PREFERRED_SIZE, GroupLayout.PREFERRED_SIZE, GroupLayout.PREFERRED_SIZE
                                    )
                            ).addGroup(
                                    main.createSequentialGroup().addGap(
                                            DendroFactory.MEDIUM_GAP, DendroFactory.MEDIUM_GAP, Short.MAX_VALUE
                                    ).addComponent(
                                            enc, GroupLayout.PREFERRED_SIZE, GroupLayout.PREFERRED_SIZE, GroupLayout.PREFERRED_SIZE
                                    ).addGap(DendroFactory.SMALL_GAP).addComponent(
                                            AES_RADIX, GroupLayout.PREFERRED_SIZE, GroupLayout.PREFERRED_SIZE, GroupLayout.PREFERRED_SIZE
                                    ).addGap(DendroFactory.SMALL_GAP).addComponent(
                                            dec, GroupLayout.PREFERRED_SIZE, GroupLayout.PREFERRED_SIZE, GroupLayout.PREFERRED_SIZE
                                    )
                            ).addComponent(
                                    AES_OUT, GroupLayout.PREFERRED_SIZE, GroupLayout.PREFERRED_SIZE, Short.MAX_VALUE
                            )
                    )
            );
            main.setVerticalGroup(
                    main.createSequentialGroup().addComponent(
                            a, GroupLayout.PREFERRED_SIZE, GroupLayout.PREFERRED_SIZE, GroupLayout.PREFERRED_SIZE
                    ).addGap(DendroFactory.SMALL_GAP).addComponent(
                            sep
                    ).addGap(DendroFactory.SMALL_GAP).addComponent(
                            AES_IN, GroupLayout.PREFERRED_SIZE, GroupLayout.PREFERRED_SIZE, Short.MAX_VALUE
                    ).addGap(DendroFactory.MEDIUM_GAP).addComponent(
                            AES_KEY, GroupLayout.PREFERRED_SIZE, GroupLayout.PREFERRED_SIZE, GroupLayout.PREFERRED_SIZE
                    ).addGap(DendroFactory.MEDIUM_GAP).addComponent(
                            AES_IV, GroupLayout.PREFERRED_SIZE, GroupLayout.PREFERRED_SIZE, GroupLayout.PREFERRED_SIZE
                    ).addGap(DendroFactory.MEDIUM_GAP).addGroup(
                            main.createParallelGroup(GroupLayout.Alignment.CENTER).addComponent(
                                    d, GroupLayout.PREFERRED_SIZE, GroupLayout.PREFERRED_SIZE, GroupLayout.PREFERRED_SIZE
                            ).addComponent(
                                    AES_MODE_IV, GroupLayout.PREFERRED_SIZE, GroupLayout.PREFERRED_SIZE, GroupLayout.PREFERRED_SIZE
                            ).addComponent(
                                    e, GroupLayout.PREFERRED_SIZE, GroupLayout.PREFERRED_SIZE, GroupLayout.PREFERRED_SIZE
                            ).addComponent(
                                    AES_KEYSIZE, GroupLayout.PREFERRED_SIZE, GroupLayout.PREFERRED_SIZE, GroupLayout.PREFERRED_SIZE
                            )
                    ).addGap(DendroFactory.MEDIUM_GAP).addGroup(
                            main.createParallelGroup(GroupLayout.Alignment.CENTER).addComponent(
                                    enc, GroupLayout.PREFERRED_SIZE, GroupLayout.PREFERRED_SIZE, GroupLayout.PREFERRED_SIZE
                            ).addComponent(
                                    AES_RADIX, GroupLayout.PREFERRED_SIZE, GroupLayout.PREFERRED_SIZE, GroupLayout.PREFERRED_SIZE
                            ).addComponent(
                                    dec, GroupLayout.PREFERRED_SIZE, GroupLayout.PREFERRED_SIZE, GroupLayout.PREFERRED_SIZE
                            )
                    ).addGap(DendroFactory.MEDIUM_GAP).addComponent(
                            AES_OUT, GroupLayout.PREFERRED_SIZE, GroupLayout.PREFERRED_SIZE, Short.MAX_VALUE
                    )
            );
        }
    }

    private void setAesPnIV() {
        JLabel a = new JLabel("SHA-256 Hashed Password");
        JLabel b = new JLabel("Password");
        JLabel c = new JLabel("Mode");
        JLabel d = new JLabel("Key Size");
        JButton enc = DendroFactory.getButton("Encrypt"), dec = DendroFactory.getButton("Decrypt");

        enc.addActionListener(event -> {
            Aes handler = (Aes) AES_MODE_NIV.getSelectedItem();
            try {
                handler.changeKey(AES_PASS.getPassword(), (Integer) AES_KEYSIZE.getSelectedItem());
                encrypt(handler, AES_IN, AES_OUT, AES_RADIX);
            } catch (NoSuchAlgorithmException ex) {
                AES_OUT.CONTENT.setText("SHA-256 seems not to be supported by your system.");
            }
        });
        dec.addActionListener(event -> {
            Aes handler = (Aes) AES_MODE_NIV.getSelectedItem();
            try {
                handler.changeKey(AES_PASS.getPassword(), (Integer) AES_KEYSIZE.getSelectedItem());
                decrypt(handler, AES_IN, AES_OUT, AES_RADIX);
            } catch (NoSuchAlgorithmException ex) {
                AES_OUT.CONTENT.setText("SHA-256 seems not to be supported by your system.");
            }
        });

        //Group Layout
        {
            JSeparator sep = new JSeparator();

            AES_CONTENT.removeAll();
            GroupLayout main = new GroupLayout(AES_CONTENT);
            AES_CONTENT.setLayout(main);
            main.setHorizontalGroup(
                    main.createSequentialGroup().addGroup(
                            main.createParallelGroup(GroupLayout.Alignment.LEADING).addComponent(
                                    a, GroupLayout.PREFERRED_SIZE, GroupLayout.PREFERRED_SIZE, GroupLayout.PREFERRED_SIZE
                            ).addComponent(
                                    sep
                            ).addComponent(
                                    AES_IN, GroupLayout.PREFERRED_SIZE, GroupLayout.PREFERRED_SIZE, Short.MAX_VALUE
                            ).addGroup(
                                    main.createSequentialGroup().addComponent(
                                            b, GroupLayout.PREFERRED_SIZE, GroupLayout.PREFERRED_SIZE, GroupLayout.PREFERRED_SIZE
                                    ).addGap(DendroFactory.SMALL_GAP).addComponent(
                                            AES_PASS, GroupLayout.PREFERRED_SIZE, GroupLayout.PREFERRED_SIZE, Short.MAX_VALUE
                                    )
                            ).addGroup(
                                    main.createSequentialGroup().addComponent(
                                            c, GroupLayout.PREFERRED_SIZE, GroupLayout.PREFERRED_SIZE, GroupLayout.PREFERRED_SIZE
                                    ).addGap(DendroFactory.SMALL_GAP).addComponent(
                                            AES_MODE_NIV, GroupLayout.PREFERRED_SIZE, GroupLayout.PREFERRED_SIZE, GroupLayout.PREFERRED_SIZE
                                    ).addGap(
                                            DendroFactory.MEDIUM_GAP, DendroFactory.MEDIUM_GAP, Short.MAX_VALUE
                                    ).addComponent(
                                            d, GroupLayout.PREFERRED_SIZE, GroupLayout.PREFERRED_SIZE, GroupLayout.PREFERRED_SIZE
                                    ).addGap(DendroFactory.SMALL_GAP).addComponent(
                                            AES_KEYSIZE, GroupLayout.PREFERRED_SIZE, GroupLayout.PREFERRED_SIZE, GroupLayout.PREFERRED_SIZE
                                    )
                            ).addGroup(
                                    main.createSequentialGroup().addGap(
                                            DendroFactory.MEDIUM_GAP, DendroFactory.MEDIUM_GAP, Short.MAX_VALUE
                                    ).addComponent(
                                            enc, GroupLayout.PREFERRED_SIZE, GroupLayout.PREFERRED_SIZE, GroupLayout.PREFERRED_SIZE
                                    ).addGap(DendroFactory.SMALL_GAP).addComponent(
                                            AES_RADIX, GroupLayout.PREFERRED_SIZE, GroupLayout.PREFERRED_SIZE, GroupLayout.PREFERRED_SIZE
                                    ).addGap(DendroFactory.SMALL_GAP).addComponent(
                                            dec, GroupLayout.PREFERRED_SIZE, GroupLayout.PREFERRED_SIZE, GroupLayout.PREFERRED_SIZE
                                    )
                            ).addComponent(
                                    AES_OUT, GroupLayout.PREFERRED_SIZE, GroupLayout.PREFERRED_SIZE, Short.MAX_VALUE
                            )
                    )
            );
            main.setVerticalGroup(
                    main.createSequentialGroup().addComponent(
                            a, GroupLayout.PREFERRED_SIZE, GroupLayout.PREFERRED_SIZE, GroupLayout.PREFERRED_SIZE
                    ).addGap(DendroFactory.SMALL_GAP).addComponent(
                            sep
                    ).addGap(DendroFactory.SMALL_GAP).addComponent(
                            AES_IN, GroupLayout.PREFERRED_SIZE, GroupLayout.PREFERRED_SIZE, Short.MAX_VALUE
                    ).addGap(DendroFactory.MEDIUM_GAP).addGroup(
                            main.createParallelGroup(GroupLayout.Alignment.CENTER).addComponent(
                                    b, GroupLayout.PREFERRED_SIZE, GroupLayout.PREFERRED_SIZE, GroupLayout.PREFERRED_SIZE
                            ).addComponent(
                                    AES_PASS, GroupLayout.PREFERRED_SIZE, GroupLayout.PREFERRED_SIZE, GroupLayout.PREFERRED_SIZE
                            )
                    ).addGap(DendroFactory.MEDIUM_GAP).addGroup(
                            main.createParallelGroup(GroupLayout.Alignment.CENTER).addComponent(
                                    c, GroupLayout.PREFERRED_SIZE, GroupLayout.PREFERRED_SIZE, GroupLayout.PREFERRED_SIZE
                            ).addComponent(
                                    AES_MODE_NIV, GroupLayout.PREFERRED_SIZE, GroupLayout.PREFERRED_SIZE, GroupLayout.PREFERRED_SIZE
                            ).addComponent(
                                    d, GroupLayout.PREFERRED_SIZE, GroupLayout.PREFERRED_SIZE, GroupLayout.PREFERRED_SIZE
                            ).addComponent(
                                    AES_KEYSIZE, GroupLayout.PREFERRED_SIZE, GroupLayout.PREFERRED_SIZE, GroupLayout.PREFERRED_SIZE
                            )
                    ).addGap(DendroFactory.MEDIUM_GAP).addGroup(
                            main.createParallelGroup(GroupLayout.Alignment.CENTER).addComponent(
                                    enc, GroupLayout.PREFERRED_SIZE, GroupLayout.PREFERRED_SIZE, GroupLayout.PREFERRED_SIZE
                            ).addComponent(
                                    AES_RADIX, GroupLayout.PREFERRED_SIZE, GroupLayout.PREFERRED_SIZE, GroupLayout.PREFERRED_SIZE
                            ).addComponent(
                                    dec, GroupLayout.PREFERRED_SIZE, GroupLayout.PREFERRED_SIZE, GroupLayout.PREFERRED_SIZE
                            )
                    ).addGap(DendroFactory.MEDIUM_GAP).addComponent(
                            AES_OUT, GroupLayout.PREFERRED_SIZE, GroupLayout.PREFERRED_SIZE, Short.MAX_VALUE
                    )
            );
        }
    }

    private void setAesKnIV() {
        JLabel a = new JLabel("Specified Key");
        JLabel b = new JLabel("Mode");
        JLabel c = new JLabel("Key Size");
        JButton enc = DendroFactory.getButton("Encrypt"), dec = DendroFactory.getButton("Decrypt");

        enc.addActionListener(event -> {
            Aes handler = (Aes) AES_MODE_NIV.getSelectedItem();
            handler.changeKey(AES_KEY.getBytes());
            encrypt(handler, AES_IN, AES_OUT, AES_RADIX);
        });
        dec.addActionListener(event -> {
            Aes handler = (Aes) AES_MODE_NIV.getSelectedItem();
            handler.changeKey(AES_KEY.getBytes());
            decrypt(handler, AES_IN, AES_OUT, AES_RADIX);
        });

        //Group Layout
        {
            JSeparator sep = new JSeparator();

            AES_CONTENT.removeAll();
            GroupLayout main = new GroupLayout(AES_CONTENT);
            AES_CONTENT.setLayout(main);
            main.setHorizontalGroup(
                    main.createSequentialGroup().addGroup(
                            main.createParallelGroup(GroupLayout.Alignment.LEADING).addComponent(
                                    a, GroupLayout.PREFERRED_SIZE, GroupLayout.PREFERRED_SIZE, GroupLayout.PREFERRED_SIZE
                            ).addComponent(
                                    sep
                            ).addComponent(
                                    AES_IN, GroupLayout.PREFERRED_SIZE, GroupLayout.PREFERRED_SIZE, Short.MAX_VALUE
                            ).addComponent(
                                    AES_KEY, GroupLayout.PREFERRED_SIZE, GroupLayout.PREFERRED_SIZE, Short.MAX_VALUE
                            ).addGroup(
                                    main.createSequentialGroup().addComponent(
                                            b, GroupLayout.PREFERRED_SIZE, GroupLayout.PREFERRED_SIZE, GroupLayout.PREFERRED_SIZE
                                    ).addGap(DendroFactory.SMALL_GAP).addComponent(
                                            AES_MODE_NIV, GroupLayout.PREFERRED_SIZE, GroupLayout.PREFERRED_SIZE, GroupLayout.PREFERRED_SIZE
                                    ).addGap(
                                            DendroFactory.MEDIUM_GAP, DendroFactory.MEDIUM_GAP, Short.MAX_VALUE
                                    ).addComponent(
                                            c, GroupLayout.PREFERRED_SIZE, GroupLayout.PREFERRED_SIZE, GroupLayout.PREFERRED_SIZE
                                    ).addGap(DendroFactory.SMALL_GAP).addComponent(
                                            AES_KEYSIZE, GroupLayout.PREFERRED_SIZE, GroupLayout.PREFERRED_SIZE, GroupLayout.PREFERRED_SIZE
                                    )
                            ).addGroup(
                                    main.createSequentialGroup().addGap(
                                            DendroFactory.MEDIUM_GAP, DendroFactory.MEDIUM_GAP, Short.MAX_VALUE
                                    ).addComponent(
                                            enc, GroupLayout.PREFERRED_SIZE, GroupLayout.PREFERRED_SIZE, GroupLayout.PREFERRED_SIZE
                                    ).addGap(DendroFactory.SMALL_GAP).addComponent(
                                            AES_RADIX, GroupLayout.PREFERRED_SIZE, GroupLayout.PREFERRED_SIZE, GroupLayout.PREFERRED_SIZE
                                    ).addGap(DendroFactory.SMALL_GAP).addComponent(
                                            dec, GroupLayout.PREFERRED_SIZE, GroupLayout.PREFERRED_SIZE, GroupLayout.PREFERRED_SIZE
                                    )
                            ).addComponent(
                                    AES_OUT, GroupLayout.PREFERRED_SIZE, GroupLayout.PREFERRED_SIZE, Short.MAX_VALUE
                            )
                    )
            );
            main.setVerticalGroup(
                    main.createSequentialGroup().addComponent(
                            a, GroupLayout.PREFERRED_SIZE, GroupLayout.PREFERRED_SIZE, GroupLayout.PREFERRED_SIZE
                    ).addGap(DendroFactory.SMALL_GAP).addComponent(
                            sep
                    ).addGap(DendroFactory.SMALL_GAP).addComponent(
                            AES_IN, GroupLayout.PREFERRED_SIZE, GroupLayout.PREFERRED_SIZE, Short.MAX_VALUE
                    ).addGap(DendroFactory.MEDIUM_GAP).addComponent(
                            AES_KEY, GroupLayout.PREFERRED_SIZE, GroupLayout.PREFERRED_SIZE, GroupLayout.PREFERRED_SIZE
                    ).addGap(DendroFactory.MEDIUM_GAP).addGroup(
                            main.createParallelGroup(GroupLayout.Alignment.CENTER).addComponent(
                                    b, GroupLayout.PREFERRED_SIZE, GroupLayout.PREFERRED_SIZE, GroupLayout.PREFERRED_SIZE
                            ).addComponent(
                                    AES_MODE_NIV, GroupLayout.PREFERRED_SIZE, GroupLayout.PREFERRED_SIZE, GroupLayout.PREFERRED_SIZE
                            ).addComponent(
                                    c, GroupLayout.PREFERRED_SIZE, GroupLayout.PREFERRED_SIZE, GroupLayout.PREFERRED_SIZE
                            ).addComponent(
                                    AES_KEYSIZE, GroupLayout.PREFERRED_SIZE, GroupLayout.PREFERRED_SIZE, GroupLayout.PREFERRED_SIZE
                            )
                    ).addGap(DendroFactory.MEDIUM_GAP).addGroup(
                            main.createParallelGroup(GroupLayout.Alignment.CENTER).addComponent(
                                    enc, GroupLayout.PREFERRED_SIZE, GroupLayout.PREFERRED_SIZE, GroupLayout.PREFERRED_SIZE
                            ).addComponent(
                                    AES_RADIX, GroupLayout.PREFERRED_SIZE, GroupLayout.PREFERRED_SIZE, GroupLayout.PREFERRED_SIZE
                            ).addComponent(
                                    dec, GroupLayout.PREFERRED_SIZE, GroupLayout.PREFERRED_SIZE, GroupLayout.PREFERRED_SIZE
                            )
                    ).addGap(DendroFactory.MEDIUM_GAP).addComponent(
                            AES_OUT, GroupLayout.PREFERRED_SIZE, GroupLayout.PREFERRED_SIZE, Short.MAX_VALUE
                    )
            );
        }
    }

    @Override
    public void dispose() {
        conclude(true, true);
    }
}
