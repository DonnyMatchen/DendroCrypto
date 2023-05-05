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
import com.donny.dendroecc.util.Functions;
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
    private final ButtonGroup AES_GROUP = new ButtonGroup(), ECC_GROUP = new ButtonGroup();
    private final JPanel AES_CONTENT, ECC_CONTENT;
    private final IOPane AES_IN, AES_OUT;
    private final JPasswordField AES_PASS;
    private final HexField AES_KEY, AES_IV;
    private final JComboBox<Integer> AES_KEYSIZE, AES_IV_INDEX;
    private final JComboBox<String> AES_RADIX, ECC_FORM, ECC_DC, ECC_RADIX;
    private final JComboBox<Aes> AES_MODE_IV, AES_MODE_NIV;
    private final JScrollPane ECC_X_SCROLL, ECC_Y_SCROLL, ECC_Z_SCROLL,
            ECC_M_SCROLL, ECC_R_SCROLL, ECC_S_SCROLL,
            ECC_X2_SCROLL, ECC_Y2_SCROLL,
            ECC_P_SCROLL;
    private final JTextArea ECC_X, ECC_Y, ECC_Z,
            ECC_M, ECC_R, ECC_S,
            ECC_X2, ECC_Y2,
            ECC_P;

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

                ECC_FORM = new JComboBox<>();
                ECC_FORM.addItem("Weierstrass Prime");
                ECC_FORM.addItem("Weierstrass Binary");
                ECC_FORM.addItem("Twisted Edwards");
                ECC_FORM.addItem("Montgomery");
                ECC_FORM.addItem("Edwards");
                ECC_DC = new JComboBox<>();
                ECC_FORM.addActionListener(event -> setEccDefCrv());
                setEccDefCrv();
                ECC_RADIX = new JComboBox<>();
                ECC_RADIX.addItem("Base64");
                ECC_RADIX.addItem("Hexadecimal");
                ECC_RADIX.addItem("Decimal");

                ECC_X_SCROLL = DendroFactory.getLongField();
                ECC_X = (JTextArea) ECC_X_SCROLL.getViewport().getView();
                ECC_Y_SCROLL = DendroFactory.getLongField();
                ECC_Y = (JTextArea) ECC_Y_SCROLL.getViewport().getView();
                ECC_Z_SCROLL = DendroFactory.getLongField();
                ECC_Z = (JTextArea) ECC_Z_SCROLL.getViewport().getView();
                ECC_M_SCROLL = DendroFactory.getScrollField();
                ECC_M = (JTextArea) ECC_M_SCROLL.getViewport().getView();
                ECC_R_SCROLL = DendroFactory.getLongField();
                ECC_R = (JTextArea) ECC_R_SCROLL.getViewport().getView();
                ECC_S_SCROLL = DendroFactory.getLongField();
                ECC_S = (JTextArea) ECC_S_SCROLL.getViewport().getView();
                ECC_X2_SCROLL = DendroFactory.getLongField();
                ECC_X2 = (JTextArea) ECC_X2_SCROLL.getViewport().getView();
                ECC_Y2_SCROLL = DendroFactory.getLongField();
                ECC_Y2 = (JTextArea) ECC_Y2_SCROLL.getViewport().getView();
                ECC_P_SCROLL = DendroFactory.getLongField();
                ECC_P = (JTextArea) ECC_P_SCROLL.getViewport().getView();
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
                            ).addGap(DendroFactory.LARGE_GAP).addComponent(
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

                ECC_CONTENT = new JPanel();
                ECC_CONTENT.setBorder(null);

                JRadioButton ecdsa = new JRadioButton("ECDSA"),
                        ecdh = new JRadioButton("ECDH"),
                        pack = new JRadioButton("Unpacking");
                ECC_GROUP.add(ecdsa);
                ECC_GROUP.add(ecdh);
                ECC_GROUP.add(pack);

                Enumeration<AbstractButton> radio = ECC_GROUP.getElements();
                while (radio.hasMoreElements()) {
                    radio.nextElement().addActionListener(event -> eccButtonChanged());
                }

                ecdsa.setSelected(true);
                eccButtonChanged();

                //Group Layout
                {
                    GroupLayout main = new GroupLayout(ecc);
                    ecc.setLayout(main);
                    main.setHorizontalGroup(
                            main.createSequentialGroup().addContainerGap().addGroup(
                                    main.createParallelGroup(GroupLayout.Alignment.LEADING).addGroup(
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
                                                            ECC_FORM, GroupLayout.PREFERRED_SIZE, GroupLayout.PREFERRED_SIZE, Short.MAX_VALUE
                                                    ).addComponent(
                                                            ECC_DC, GroupLayout.PREFERRED_SIZE, GroupLayout.PREFERRED_SIZE, Short.MAX_VALUE
                                                    ).addComponent(
                                                            ECC_RADIX, GroupLayout.PREFERRED_SIZE, GroupLayout.PREFERRED_SIZE, Short.MAX_VALUE
                                                    )
                                            )
                                    ).addComponent(
                                            ecdsa, GroupLayout.PREFERRED_SIZE, GroupLayout.PREFERRED_SIZE, GroupLayout.PREFERRED_SIZE
                                    ).addComponent(
                                            ecdh, GroupLayout.PREFERRED_SIZE, GroupLayout.PREFERRED_SIZE, GroupLayout.PREFERRED_SIZE
                                    ).addComponent(
                                            pack, GroupLayout.PREFERRED_SIZE, GroupLayout.PREFERRED_SIZE, GroupLayout.PREFERRED_SIZE
                                    ).addComponent(
                                            ECC_CONTENT, GroupLayout.PREFERRED_SIZE, GroupLayout.PREFERRED_SIZE, Short.MAX_VALUE
                                    )
                            ).addContainerGap()
                    );
                    main.setVerticalGroup(
                            main.createSequentialGroup().addContainerGap().addGroup(
                                    main.createParallelGroup(GroupLayout.Alignment.CENTER).addComponent(
                                            a, GroupLayout.PREFERRED_SIZE, GroupLayout.PREFERRED_SIZE, GroupLayout.PREFERRED_SIZE
                                    ).addComponent(
                                            ECC_FORM, GroupLayout.PREFERRED_SIZE, GroupLayout.PREFERRED_SIZE, GroupLayout.PREFERRED_SIZE
                                    )
                            ).addGap(DendroFactory.SMALL_GAP).addGroup(
                                    main.createParallelGroup(GroupLayout.Alignment.CENTER).addComponent(
                                            b, GroupLayout.PREFERRED_SIZE, GroupLayout.PREFERRED_SIZE, GroupLayout.PREFERRED_SIZE
                                    ).addComponent(
                                            ECC_DC, GroupLayout.PREFERRED_SIZE, GroupLayout.PREFERRED_SIZE, GroupLayout.PREFERRED_SIZE
                                    )
                            ).addGap(DendroFactory.SMALL_GAP).addGroup(
                                    main.createParallelGroup(GroupLayout.Alignment.CENTER).addComponent(
                                            c, GroupLayout.PREFERRED_SIZE, GroupLayout.PREFERRED_SIZE, GroupLayout.PREFERRED_SIZE
                                    ).addComponent(
                                            ECC_RADIX, GroupLayout.PREFERRED_SIZE, GroupLayout.PREFERRED_SIZE, GroupLayout.PREFERRED_SIZE
                                    )
                            ).addGap(DendroFactory.MEDIUM_GAP).addComponent(
                                    ecdsa, GroupLayout.PREFERRED_SIZE, GroupLayout.PREFERRED_SIZE, GroupLayout.PREFERRED_SIZE
                            ).addGap(DendroFactory.SMALL_GAP).addComponent(
                                    ecdh, GroupLayout.PREFERRED_SIZE, GroupLayout.PREFERRED_SIZE, GroupLayout.PREFERRED_SIZE
                            ).addGap(DendroFactory.SMALL_GAP).addComponent(
                                    pack, GroupLayout.PREFERRED_SIZE, GroupLayout.PREFERRED_SIZE, GroupLayout.PREFERRED_SIZE
                            ).addGap(DendroFactory.LARGE_GAP).addComponent(
                                    ECC_CONTENT, GroupLayout.PREFERRED_SIZE, GroupLayout.PREFERRED_SIZE, Short.MAX_VALUE
                            ).addContainerGap()
                    );
                }

                back.add("ECC", ecc);
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

            //ModExp
            {
                JPanel modExp = new JPanel();
                JLabel a = new JLabel("Radix");
                JLabel b = new JLabel("Base");
                JLabel c = new JLabel("Exponent");
                JLabel d = new JLabel("Modulus");
                JLabel e = new JLabel("Result");

                JComboBox<String> radix = new JComboBox<>();
                radix.addItem("Base64");
                radix.addItem("Hexadecimal");
                radix.addItem("Decimal");
                JScrollPane baseScroll = DendroFactory.getLongField();
                JTextArea base = (JTextArea) baseScroll.getViewport().getView();
                JScrollPane exponentScroll = DendroFactory.getLongField();
                JTextArea exponent = (JTextArea) exponentScroll.getViewport().getView();
                JScrollPane modulusScroll = DendroFactory.getLongField();
                JTextArea modulus = (JTextArea) modulusScroll.getViewport().getView();
                JScrollPane resultScroll = DendroFactory.getLongField();
                JTextArea result = (JTextArea) resultScroll.getViewport().getView();
                result.setEditable(false);
                result.setBackground(DendroFactory.DISABLED);
                result.addMouseListener(new MouseAdapter() {
                    public void mouseClicked(MouseEvent evt) {
                        result.selectAll();
                    }
                });
                JButton calc = new JButton("Calculate");
                calc.addActionListener(event -> {
                    BigInteger bN = null, eN = null, nN = null;
                    String bS = null, eS = null, nS = null;
                    try {
                        bS = Validation.validateString(base);
                        eS = Validation.validateString(exponent);
                        nS = Validation.validateString(modulus);
                    } catch (ValidationFailedException ex) {
                        CURRENT_INSTANCE.LOG_HANDLER.error(getClass(), "Fields cannot be empty");
                    }
                    if (bS != null && eS != null && nS != null) {
                        try {
                            switch ((String) radix.getSelectedItem()) {
                                case "Base64" -> {
                                    bN = new BigInteger(Base64.getDecoder().decode(bS));
                                    eN = new BigInteger(Base64.getDecoder().decode(eS));
                                    nN = new BigInteger(Base64.getDecoder().decode(nS));
                                }
                                case "Hexadecimal" -> {
                                    bN = new BigInteger(bS, 16);
                                    eN = new BigInteger(eS, 16);
                                    nN = new BigInteger(nS, 16);
                                }
                                case "Decimal" -> {
                                    bN = new BigInteger(bS);
                                    eN = new BigInteger(eS);
                                    nN = new BigInteger(nS);
                                }
                            }
                            BigInteger res = Functions.modExp(bN, eN, nN);
                            switch ((String) radix.getSelectedItem()) {
                                case "Base64" -> result.setText(Base64.getEncoder().encodeToString(res.toByteArray()));
                                case "Hexadecimal" -> result.setText(res.toString(16));
                                case "Decimal" -> result.setText(res.toString());
                            }
                        } catch (IllegalArgumentException ex) {
                            CURRENT_INSTANCE.LOG_HANDLER.error(getClass(), "Fields must be a number matching the radix");
                            if (bN == null) {
                                base.setBackground(DendroFactory.WRONG);
                            } else if (eN == null) {
                                exponent.setBackground(DendroFactory.WRONG);
                            } else {
                                modulus.setBackground(DendroFactory.WRONG);
                            }
                        }
                    }
                });
                //Group Layout
                {
                    GroupLayout main = new GroupLayout(modExp);
                    modExp.setLayout(main);
                    main.setHorizontalGroup(
                            main.createSequentialGroup().addContainerGap().addGroup(
                                    main.createParallelGroup(GroupLayout.Alignment.LEADING).addGroup(
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
                                                    )
                                            ).addGap(DendroFactory.SMALL_GAP).addGroup(
                                                    main.createParallelGroup(GroupLayout.Alignment.LEADING).addComponent(
                                                            radix, GroupLayout.PREFERRED_SIZE, GroupLayout.PREFERRED_SIZE, Short.MAX_VALUE
                                                    ).addComponent(
                                                            baseScroll, GroupLayout.PREFERRED_SIZE, GroupLayout.PREFERRED_SIZE, Short.MAX_VALUE
                                                    ).addComponent(
                                                            exponentScroll, GroupLayout.PREFERRED_SIZE, GroupLayout.PREFERRED_SIZE, Short.MAX_VALUE
                                                    ).addComponent(
                                                            modulusScroll, GroupLayout.PREFERRED_SIZE, GroupLayout.PREFERRED_SIZE, Short.MAX_VALUE
                                                    ).addComponent(
                                                            resultScroll, GroupLayout.PREFERRED_SIZE, GroupLayout.PREFERRED_SIZE, Short.MAX_VALUE
                                                    )
                                            )
                                    ).addComponent(
                                            calc, GroupLayout.PREFERRED_SIZE, GroupLayout.PREFERRED_SIZE, GroupLayout.PREFERRED_SIZE
                                    )
                            ).addContainerGap()
                    );
                    main.setVerticalGroup(
                            main.createSequentialGroup().addContainerGap().addGroup(
                                    main.createParallelGroup(GroupLayout.Alignment.CENTER).addComponent(
                                            a, GroupLayout.PREFERRED_SIZE, GroupLayout.PREFERRED_SIZE, GroupLayout.PREFERRED_SIZE
                                    ).addComponent(
                                            radix, GroupLayout.PREFERRED_SIZE, GroupLayout.PREFERRED_SIZE, GroupLayout.PREFERRED_SIZE
                                    )
                            ).addGap(DendroFactory.SMALL_GAP).addGroup(
                                    main.createParallelGroup(GroupLayout.Alignment.LEADING).addComponent(
                                            b, GroupLayout.PREFERRED_SIZE, GroupLayout.PREFERRED_SIZE, GroupLayout.PREFERRED_SIZE
                                    ).addComponent(
                                            baseScroll, GroupLayout.PREFERRED_SIZE, GroupLayout.PREFERRED_SIZE, GroupLayout.PREFERRED_SIZE
                                    )
                            ).addGap(DendroFactory.SMALL_GAP).addGroup(
                                    main.createParallelGroup(GroupLayout.Alignment.LEADING).addComponent(
                                            c, GroupLayout.PREFERRED_SIZE, GroupLayout.PREFERRED_SIZE, GroupLayout.PREFERRED_SIZE
                                    ).addComponent(
                                            exponentScroll, GroupLayout.PREFERRED_SIZE, GroupLayout.PREFERRED_SIZE, GroupLayout.PREFERRED_SIZE
                                    )
                            ).addGap(DendroFactory.SMALL_GAP).addGroup(
                                    main.createParallelGroup(GroupLayout.Alignment.LEADING).addComponent(
                                            d, GroupLayout.PREFERRED_SIZE, GroupLayout.PREFERRED_SIZE, GroupLayout.PREFERRED_SIZE
                                    ).addComponent(
                                            modulusScroll, GroupLayout.PREFERRED_SIZE, GroupLayout.PREFERRED_SIZE, GroupLayout.PREFERRED_SIZE
                                    )
                            ).addGap(DendroFactory.SMALL_GAP).addGroup(
                                    main.createParallelGroup(GroupLayout.Alignment.LEADING).addComponent(
                                            e, GroupLayout.PREFERRED_SIZE, GroupLayout.PREFERRED_SIZE, GroupLayout.PREFERRED_SIZE
                                    ).addComponent(
                                            resultScroll, GroupLayout.PREFERRED_SIZE, GroupLayout.PREFERRED_SIZE, GroupLayout.PREFERRED_SIZE
                                    )
                            ).addGap(DendroFactory.MEDIUM_GAP).addComponent(
                                    calc, GroupLayout.PREFERRED_SIZE, GroupLayout.PREFERRED_SIZE, GroupLayout.PREFERRED_SIZE
                            ).addContainerGap()
                    );
                }
                back.addTab("Mod Exp", modExp);
            }

            add(back);
            pack();
            int x = getLocation().x + getWidth() / 2, y = getLocation().y + getHeight() / 2;
            setLocation(x - getWidth() / 2, y - getHeight() / 2);
        }
    }

    private void aesButtonChanged() {
        int x = getLocation().x + getWidth() / 2, y = getLocation().y + getHeight() / 2;
        switch (getSelectedAesRadio()) {
            case "Password, IV From Hash" -> setAesPIVfH();
            case "Password, IV" -> setAesPIV();
            case "Key, IV" -> setAesKIV();
            case "Password, No IV" -> setAesPnIV();
            case "Key, No IV" -> setAesKnIV();
        }
        pack();
        setLocation(x - getWidth() / 2, y - getHeight() / 2);
    }

    private void eccButtonChanged() {
        int x = getLocation().x + getWidth() / 2, y = getLocation().y + getHeight() / 2;
        switch (getSelectedEccRadio()) {
            case "ECDSA" -> setEcDSA();
            case "ECDH" -> setEcDH();
            case "Unpacking" -> setEcPack();
        }
        pack();
        setLocation(x - getWidth() / 2, y - getHeight() / 2);
    }

    private String getSelectedAesRadio() {
        Enumeration<AbstractButton> radio = AES_GROUP.getElements();
        while (radio.hasMoreElements()) {
            AbstractButton button = radio.nextElement();

            if (button.isSelected()) {
                return button.getText();
            }
        }
        return "";
    }

    private String getSelectedEccRadio() {
        Enumeration<AbstractButton> radio = ECC_GROUP.getElements();
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
            AES_CONTENT.removeAll();
            GroupLayout main = new GroupLayout(AES_CONTENT);
            AES_CONTENT.setLayout(main);
            main.setHorizontalGroup(
                    main.createSequentialGroup().addGroup(
                            main.createParallelGroup(GroupLayout.Alignment.LEADING).addComponent(
                                    a, GroupLayout.PREFERRED_SIZE, GroupLayout.PREFERRED_SIZE, GroupLayout.PREFERRED_SIZE
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
                    ).addGap(DendroFactory.LARGE_GAP).addComponent(
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
            AES_CONTENT.removeAll();
            GroupLayout main = new GroupLayout(AES_CONTENT);
            AES_CONTENT.setLayout(main);
            main.setHorizontalGroup(
                    main.createSequentialGroup().addGroup(
                            main.createParallelGroup(GroupLayout.Alignment.LEADING).addComponent(
                                    a, GroupLayout.PREFERRED_SIZE, GroupLayout.PREFERRED_SIZE, GroupLayout.PREFERRED_SIZE
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
                    ).addGap(DendroFactory.LARGE_GAP).addComponent(
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
            AES_CONTENT.removeAll();
            GroupLayout main = new GroupLayout(AES_CONTENT);
            AES_CONTENT.setLayout(main);
            main.setHorizontalGroup(
                    main.createSequentialGroup().addGroup(
                            main.createParallelGroup(GroupLayout.Alignment.LEADING).addComponent(
                                    a, GroupLayout.PREFERRED_SIZE, GroupLayout.PREFERRED_SIZE, GroupLayout.PREFERRED_SIZE
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
                    ).addGap(DendroFactory.LARGE_GAP).addComponent(
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
            AES_CONTENT.removeAll();
            GroupLayout main = new GroupLayout(AES_CONTENT);
            AES_CONTENT.setLayout(main);
            main.setHorizontalGroup(
                    main.createSequentialGroup().addGroup(
                            main.createParallelGroup(GroupLayout.Alignment.LEADING).addComponent(
                                    a, GroupLayout.PREFERRED_SIZE, GroupLayout.PREFERRED_SIZE, GroupLayout.PREFERRED_SIZE
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
                    ).addGap(DendroFactory.LARGE_GAP).addComponent(
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
            AES_CONTENT.removeAll();
            GroupLayout main = new GroupLayout(AES_CONTENT);
            AES_CONTENT.setLayout(main);
            main.setHorizontalGroup(
                    main.createSequentialGroup().addGroup(
                            main.createParallelGroup(GroupLayout.Alignment.LEADING).addComponent(
                                    a, GroupLayout.PREFERRED_SIZE, GroupLayout.PREFERRED_SIZE, GroupLayout.PREFERRED_SIZE
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
                    ).addGap(DendroFactory.LARGE_GAP).addComponent(
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

    private void setEcDSA() {
        JLabel a = new JLabel("message");
        JLabel b = new JLabel("Private Key");
        JLabel c = new JLabel("Public Key (X)");
        JLabel d = new JLabel("Public Key (Y)");
        JLabel e = new JLabel("Signature (R)");
        JLabel f = new JLabel("Signature (S)");

        JButton sign = DendroFactory.getButton("Sign");
        sign.addActionListener(event -> {
            BigInteger priv = fromRadixInput(ECC_Z, ECC_RADIX);
            if (priv != null) {
                try {
                    Signature sig = Registry.get((String) ECC_DC.getSelectedItem()).sign(
                            ECC_M.getText().getBytes(DendroCrypto.CHARSET),
                            priv
                    );
                    toRadixOutput(ECC_R, ECC_RADIX, sig.R);
                    toRadixOutput(ECC_S, ECC_RADIX, sig.S);
                } catch (NoSuchAlgorithmException ex) {
                    CURRENT_INSTANCE.LOG_HANDLER.error(getClass(), "Your system does not support SHA-256");
                    new AlertGui(this, "Your system does not support SHA-256", CURRENT_INSTANCE).setVisible(true);
                }
            }
        });
        JButton verify = DendroFactory.getButton("Verify");
        verify.addActionListener(event -> {
            BigInteger x = fromRadixInput(ECC_X, ECC_RADIX),
                    y = fromRadixInput(ECC_Y, ECC_RADIX),
                    r = fromRadixInput(ECC_R, ECC_RADIX),
                    s = fromRadixInput(ECC_S, ECC_RADIX);
            if (x != null && y != null && r != null && s != null) {
                DefinedCurve curve = Registry.get((String) ECC_DC.getSelectedItem());
                ECPoint pub = makeECPoint(x, y, curve);
                if (pub != null) {
                    try {
                        boolean cor = curve.verifySignature(
                                ECC_M.getText().getBytes(DendroCrypto.CHARSET),
                                new Signature(r, s),
                                pub
                        );
                        new AlertGui(this, "Signature " + (cor ? "is Valid" : "is not Valid"), CURRENT_INSTANCE).setVisible(true);
                    } catch (NoSuchAlgorithmException ex) {
                        CURRENT_INSTANCE.LOG_HANDLER.error(getClass(), "Your system does not support SHA-256");
                        new AlertGui(this, "Your system does not support SHA-256", CURRENT_INSTANCE).setVisible(true);
                    }
                }
            }
        });
        JButton gen = DendroFactory.getButton("Generate Keypair");
        gen.addActionListener(event -> {
            ECCKeyPair pair = Registry.get((String) ECC_DC.getSelectedItem()).generateKeyPair();
            toRadixOutput(ECC_X, ECC_RADIX, pair.PUBLIC.X);
            toRadixOutput(ECC_Y, ECC_RADIX, pair.PUBLIC.Y);
            toRadixOutput(ECC_Z, ECC_RADIX, pair.PRIVATE);
        });

        //Group Layout
        {
            ECC_CONTENT.removeAll();
            GroupLayout main = new GroupLayout(ECC_CONTENT);
            ECC_CONTENT.setLayout(main);
            main.setHorizontalGroup(
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
                                    )
                            ).addGap(DendroFactory.SMALL_GAP).addGroup(
                                    main.createParallelGroup(GroupLayout.Alignment.LEADING).addComponent(
                                            ECC_M_SCROLL, GroupLayout.PREFERRED_SIZE, GroupLayout.PREFERRED_SIZE, Short.MAX_VALUE
                                    ).addComponent(
                                            ECC_Z_SCROLL, GroupLayout.PREFERRED_SIZE, GroupLayout.PREFERRED_SIZE, Short.MAX_VALUE
                                    ).addComponent(
                                            ECC_X_SCROLL, GroupLayout.PREFERRED_SIZE, GroupLayout.PREFERRED_SIZE, Short.MAX_VALUE
                                    ).addComponent(
                                            ECC_Y_SCROLL, GroupLayout.PREFERRED_SIZE, GroupLayout.PREFERRED_SIZE, Short.MAX_VALUE
                                    ).addComponent(
                                            ECC_R_SCROLL, GroupLayout.PREFERRED_SIZE, GroupLayout.PREFERRED_SIZE, Short.MAX_VALUE
                                    ).addComponent(
                                            ECC_S_SCROLL, GroupLayout.PREFERRED_SIZE, GroupLayout.PREFERRED_SIZE, Short.MAX_VALUE
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
            );
            main.setVerticalGroup(
                    main.createSequentialGroup().addGroup(
                            main.createParallelGroup(GroupLayout.Alignment.LEADING).addComponent(
                                    a, GroupLayout.PREFERRED_SIZE, GroupLayout.PREFERRED_SIZE, GroupLayout.PREFERRED_SIZE
                            ).addComponent(
                                    ECC_M_SCROLL, GroupLayout.PREFERRED_SIZE, GroupLayout.PREFERRED_SIZE, Short.MAX_VALUE
                            )
                    ).addGap(DendroFactory.SMALL_GAP).addGroup(
                            main.createParallelGroup(GroupLayout.Alignment.LEADING).addComponent(
                                    b, GroupLayout.PREFERRED_SIZE, GroupLayout.PREFERRED_SIZE, GroupLayout.PREFERRED_SIZE
                            ).addComponent(
                                    ECC_Z_SCROLL, GroupLayout.PREFERRED_SIZE, GroupLayout.PREFERRED_SIZE, GroupLayout.PREFERRED_SIZE
                            )
                    ).addGap(DendroFactory.SMALL_GAP).addGroup(
                            main.createParallelGroup(GroupLayout.Alignment.LEADING).addComponent(
                                    c, GroupLayout.PREFERRED_SIZE, GroupLayout.PREFERRED_SIZE, GroupLayout.PREFERRED_SIZE
                            ).addComponent(
                                    ECC_X_SCROLL, GroupLayout.PREFERRED_SIZE, GroupLayout.PREFERRED_SIZE, GroupLayout.PREFERRED_SIZE
                            )
                    ).addGap(DendroFactory.SMALL_GAP).addGroup(
                            main.createParallelGroup(GroupLayout.Alignment.LEADING).addComponent(
                                    d, GroupLayout.PREFERRED_SIZE, GroupLayout.PREFERRED_SIZE, GroupLayout.PREFERRED_SIZE
                            ).addComponent(
                                    ECC_Y_SCROLL, GroupLayout.PREFERRED_SIZE, GroupLayout.PREFERRED_SIZE, GroupLayout.PREFERRED_SIZE
                            )
                    ).addGap(DendroFactory.SMALL_GAP).addGroup(
                            main.createParallelGroup(GroupLayout.Alignment.LEADING).addComponent(
                                    e, GroupLayout.PREFERRED_SIZE, GroupLayout.PREFERRED_SIZE, GroupLayout.PREFERRED_SIZE
                            ).addComponent(
                                    ECC_R_SCROLL, GroupLayout.PREFERRED_SIZE, GroupLayout.PREFERRED_SIZE, GroupLayout.PREFERRED_SIZE
                            )
                    ).addGap(DendroFactory.SMALL_GAP).addGroup(
                            main.createParallelGroup(GroupLayout.Alignment.LEADING).addComponent(
                                    f, GroupLayout.PREFERRED_SIZE, GroupLayout.PREFERRED_SIZE, GroupLayout.PREFERRED_SIZE
                            ).addComponent(
                                    ECC_S_SCROLL, GroupLayout.PREFERRED_SIZE, GroupLayout.PREFERRED_SIZE, GroupLayout.PREFERRED_SIZE
                            )
                    ).addGap(DendroFactory.MEDIUM_GAP).addGroup(
                            main.createParallelGroup(GroupLayout.Alignment.CENTER).addComponent(
                                    gen, GroupLayout.PREFERRED_SIZE, GroupLayout.PREFERRED_SIZE, GroupLayout.PREFERRED_SIZE
                            ).addComponent(
                                    sign, GroupLayout.PREFERRED_SIZE, GroupLayout.PREFERRED_SIZE, GroupLayout.PREFERRED_SIZE
                            ).addComponent(
                                    verify, GroupLayout.PREFERRED_SIZE, GroupLayout.PREFERRED_SIZE, GroupLayout.PREFERRED_SIZE
                            )
                    )
            );
        }
    }

    private void setEcDH() {
        JLabel a = new JLabel("Starting Point (X)");
        JLabel b = new JLabel("Starting Point (Y)");
        JLabel c = new JLabel("Multiplicand");
        JLabel d = new JLabel("Result (X)");
        JLabel e = new JLabel("Result (Y)");

        JButton multiply = DendroFactory.getButton("Multiply");
        multiply.addActionListener(event -> {
            BigInteger x = fromRadixInput(ECC_X, ECC_RADIX),
                    y = fromRadixInput(ECC_Y, ECC_RADIX),
                    z = fromRadixInput(ECC_Z, ECC_RADIX);

            if (x != null && y != null && z != null) {
                ECPoint start = makeECPoint(x, y, Registry.get((String) ECC_DC.getSelectedItem()));
                if (start != null) {
                    ECPoint end = start.multiply(z);
                    if (end == null) {
                        ECC_X2.setText("POINT AT INFINITY");
                        ECC_Y2.setText("POINT AT INFINITY");
                    } else {
                        toRadixOutput(ECC_X2, ECC_RADIX, end.X);
                        toRadixOutput(ECC_Y2, ECC_RADIX, end.Y);
                    }
                }
            }
        });
        JButton useG = DendroFactory.getButton("Use Generator");
        useG.addActionListener(event -> {
            DefinedCurve curve = Registry.get((String) ECC_DC.getSelectedItem());
            toRadixOutput(ECC_X, ECC_RADIX, curve.G.X);
            toRadixOutput(ECC_Y, ECC_RADIX, curve.G.Y);
        });

        //Group Layout
        {
            ECC_CONTENT.removeAll();
            GroupLayout main = new GroupLayout(ECC_CONTENT);
            ECC_CONTENT.setLayout(main);
            main.setHorizontalGroup(
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
                                    )
                            ).addGap(DendroFactory.SMALL_GAP).addGroup(
                                    main.createParallelGroup(GroupLayout.Alignment.TRAILING).addComponent(
                                            ECC_X_SCROLL, GroupLayout.PREFERRED_SIZE, GroupLayout.PREFERRED_SIZE, Short.MAX_VALUE
                                    ).addComponent(
                                            ECC_Y_SCROLL, GroupLayout.PREFERRED_SIZE, GroupLayout.PREFERRED_SIZE, Short.MAX_VALUE
                                    ).addComponent(
                                            ECC_Z_SCROLL, GroupLayout.PREFERRED_SIZE, GroupLayout.PREFERRED_SIZE, Short.MAX_VALUE
                                    ).addComponent(
                                            ECC_X2_SCROLL, GroupLayout.PREFERRED_SIZE, GroupLayout.PREFERRED_SIZE, Short.MAX_VALUE
                                    ).addComponent(
                                            ECC_Y2_SCROLL, GroupLayout.PREFERRED_SIZE, GroupLayout.PREFERRED_SIZE, Short.MAX_VALUE
                                    )
                            )
                    ).addGroup(
                            main.createSequentialGroup().addComponent(
                                    multiply, GroupLayout.PREFERRED_SIZE, GroupLayout.PREFERRED_SIZE, GroupLayout.PREFERRED_SIZE
                            ).addGap(
                                    DendroFactory.SMALL_GAP, DendroFactory.SMALL_GAP, Short.MAX_VALUE
                            ).addComponent(
                                    useG, GroupLayout.PREFERRED_SIZE, GroupLayout.PREFERRED_SIZE, GroupLayout.PREFERRED_SIZE
                            )
                    )
            );
            main.setVerticalGroup(
                    main.createSequentialGroup().addGroup(
                            main.createParallelGroup(GroupLayout.Alignment.LEADING).addComponent(
                                    a, GroupLayout.PREFERRED_SIZE, GroupLayout.PREFERRED_SIZE, GroupLayout.PREFERRED_SIZE
                            ).addComponent(
                                    ECC_X_SCROLL, GroupLayout.PREFERRED_SIZE, GroupLayout.PREFERRED_SIZE, GroupLayout.PREFERRED_SIZE
                            )
                    ).addGap(DendroFactory.SMALL_GAP).addGroup(
                            main.createParallelGroup(GroupLayout.Alignment.LEADING).addComponent(
                                    b, GroupLayout.PREFERRED_SIZE, GroupLayout.PREFERRED_SIZE, GroupLayout.PREFERRED_SIZE
                            ).addComponent(
                                    ECC_Y_SCROLL, GroupLayout.PREFERRED_SIZE, GroupLayout.PREFERRED_SIZE, GroupLayout.PREFERRED_SIZE
                            )
                    ).addGap(DendroFactory.SMALL_GAP).addGroup(
                            main.createParallelGroup(GroupLayout.Alignment.LEADING).addComponent(
                                    c, GroupLayout.PREFERRED_SIZE, GroupLayout.PREFERRED_SIZE, GroupLayout.PREFERRED_SIZE
                            ).addComponent(
                                    ECC_Z_SCROLL, GroupLayout.PREFERRED_SIZE, GroupLayout.PREFERRED_SIZE, GroupLayout.PREFERRED_SIZE
                            )
                    ).addGap(DendroFactory.SMALL_GAP).addGroup(
                            main.createParallelGroup(GroupLayout.Alignment.LEADING).addComponent(
                                    d, GroupLayout.PREFERRED_SIZE, GroupLayout.PREFERRED_SIZE, GroupLayout.PREFERRED_SIZE
                            ).addComponent(
                                    ECC_X2_SCROLL, GroupLayout.PREFERRED_SIZE, GroupLayout.PREFERRED_SIZE, GroupLayout.PREFERRED_SIZE
                            )
                    ).addGap(DendroFactory.SMALL_GAP).addGroup(
                            main.createParallelGroup(GroupLayout.Alignment.LEADING).addComponent(
                                    e, GroupLayout.PREFERRED_SIZE, GroupLayout.PREFERRED_SIZE, GroupLayout.PREFERRED_SIZE
                            ).addComponent(
                                    ECC_Y2_SCROLL, GroupLayout.PREFERRED_SIZE, GroupLayout.PREFERRED_SIZE, GroupLayout.PREFERRED_SIZE
                            )
                    ).addGap(DendroFactory.MEDIUM_GAP).addGroup(
                            main.createParallelGroup(GroupLayout.Alignment.CENTER).addComponent(
                                    multiply, GroupLayout.PREFERRED_SIZE, GroupLayout.PREFERRED_SIZE, GroupLayout.PREFERRED_SIZE
                            ).addComponent(
                                    useG, GroupLayout.PREFERRED_SIZE, GroupLayout.PREFERRED_SIZE, GroupLayout.PREFERRED_SIZE
                            )
                    )
            );
        }
    }

    private void setEcPack() {
        JLabel a = new JLabel("Packed");
        JLabel b = new JLabel("Unpacked (X)");
        JLabel c = new JLabel("Unpacked (Y)");

        JButton unpack = DendroFactory.getButton("Unpack");
        unpack.addActionListener(event -> {
            BigInteger packed = fromRadixInput(ECC_P, ECC_RADIX);
            if (packed != null) {
                DefinedCurve curve = Registry.get((String) ECC_DC.getSelectedItem());
                try {
                    BigInteger[] coordinates = curve.getPackingHandler().unpack(packed, curve.E);
                    toRadixOutput(ECC_X, ECC_RADIX, coordinates[0]);
                    toRadixOutput(ECC_Y, ECC_RADIX, coordinates[1]);
                } catch (NullPointerException ex) {
                    CURRENT_INSTANCE.LOG_HANDLER.error(getClass(), "This is not a valid packed public key");
                    ECC_P.setBackground(DendroFactory.WRONG);
                }
            }
        });
        JButton pack = DendroFactory.getButton("Pack");
        pack.addActionListener(event -> {
            BigInteger x = fromRadixInput(ECC_X, ECC_RADIX),
                    y = fromRadixInput(ECC_Y, ECC_RADIX);
            if (x != null && y != null) {
                DefinedCurve curve = Registry.get((String) ECC_DC.getSelectedItem());
                toRadixOutput(ECC_P, ECC_RADIX, curve.getPackingHandler().pack(makeECPoint(x, y, curve)));
            }
        });

        //Group Layout
        {
            ECC_CONTENT.removeAll();
            GroupLayout main = new GroupLayout(ECC_CONTENT);
            ECC_CONTENT.setLayout(main);
            main.setHorizontalGroup(
                    main.createParallelGroup(GroupLayout.Alignment.CENTER).addGroup(
                            main.createSequentialGroup().addGroup(
                                    main.createParallelGroup(GroupLayout.Alignment.TRAILING).addComponent(
                                            a, GroupLayout.PREFERRED_SIZE, GroupLayout.PREFERRED_SIZE, GroupLayout.PREFERRED_SIZE
                                    ).addComponent(
                                            b, GroupLayout.PREFERRED_SIZE, GroupLayout.PREFERRED_SIZE, GroupLayout.PREFERRED_SIZE
                                    ).addComponent(
                                            c, GroupLayout.PREFERRED_SIZE, GroupLayout.PREFERRED_SIZE, GroupLayout.PREFERRED_SIZE
                                    )
                            ).addGap(DendroFactory.SMALL_GAP).addGroup(
                                    main.createParallelGroup(GroupLayout.Alignment.LEADING).addComponent(
                                            ECC_P_SCROLL, GroupLayout.PREFERRED_SIZE, GroupLayout.PREFERRED_SIZE, Short.MAX_VALUE
                                    ).addComponent(
                                            ECC_X_SCROLL, GroupLayout.PREFERRED_SIZE, GroupLayout.PREFERRED_SIZE, Short.MAX_VALUE
                                    ).addComponent(
                                            ECC_Y_SCROLL, GroupLayout.PREFERRED_SIZE, GroupLayout.PREFERRED_SIZE, Short.MAX_VALUE
                                    )
                            )
                    ).addGroup(
                            main.createSequentialGroup().addComponent(
                                    unpack, GroupLayout.PREFERRED_SIZE, GroupLayout.PREFERRED_SIZE, GroupLayout.PREFERRED_SIZE
                            ).addGap(
                                    DendroFactory.SMALL_GAP, DendroFactory.SMALL_GAP, Short.MAX_VALUE
                            ).addComponent(
                                    pack, GroupLayout.PREFERRED_SIZE, GroupLayout.PREFERRED_SIZE, GroupLayout.PREFERRED_SIZE
                            )
                    )
            );
            main.setVerticalGroup(
                    main.createSequentialGroup().addGroup(
                            main.createParallelGroup(GroupLayout.Alignment.LEADING).addComponent(
                                    a, GroupLayout.PREFERRED_SIZE, GroupLayout.PREFERRED_SIZE, GroupLayout.PREFERRED_SIZE
                            ).addComponent(
                                    ECC_P_SCROLL, GroupLayout.PREFERRED_SIZE, GroupLayout.PREFERRED_SIZE, GroupLayout.PREFERRED_SIZE
                            )
                    ).addGap(DendroFactory.SMALL_GAP).addGroup(
                            main.createParallelGroup(GroupLayout.Alignment.LEADING).addComponent(
                                    b, GroupLayout.PREFERRED_SIZE, GroupLayout.PREFERRED_SIZE, GroupLayout.PREFERRED_SIZE
                            ).addComponent(
                                    ECC_X_SCROLL, GroupLayout.PREFERRED_SIZE, GroupLayout.PREFERRED_SIZE, GroupLayout.PREFERRED_SIZE
                            )
                    ).addGap(DendroFactory.SMALL_GAP).addGroup(
                            main.createParallelGroup(GroupLayout.Alignment.LEADING).addComponent(
                                    c, GroupLayout.PREFERRED_SIZE, GroupLayout.PREFERRED_SIZE, GroupLayout.PREFERRED_SIZE
                            ).addComponent(
                                    ECC_Y_SCROLL, GroupLayout.PREFERRED_SIZE, GroupLayout.PREFERRED_SIZE, GroupLayout.PREFERRED_SIZE
                            )
                    ).addGap(DendroFactory.MEDIUM_GAP).addGroup(
                            main.createParallelGroup(GroupLayout.Alignment.CENTER).addComponent(
                                    unpack, GroupLayout.PREFERRED_SIZE, GroupLayout.PREFERRED_SIZE, GroupLayout.PREFERRED_SIZE
                            ).addComponent(
                                    pack, GroupLayout.PREFERRED_SIZE, GroupLayout.PREFERRED_SIZE, GroupLayout.PREFERRED_SIZE
                            )
                    )
            );
        }
    }

    private void setEccDefCrv() {
        switch ((String) ECC_FORM.getSelectedItem()) {
            case "Weierstrass Prime" -> {
                ECC_DC.removeAllItems();
                for (String curve : DendroCrypto.WEIERSTRASS_PRIME) {
                    ECC_DC.addItem(curve);
                }
            }
            case "Weierstrass Binary" -> {
                ECC_DC.removeAllItems();
                for (String curve : DendroCrypto.WEIERSTRASS_BINARY) {
                    ECC_DC.addItem(curve);
                }
            }
            case "Twisted Edwards" -> {
                ECC_DC.removeAllItems();
                for (String curve : DendroCrypto.TWISTED_EDWARDS) {
                    ECC_DC.addItem(curve);
                }
            }
            case "Montgomery" -> {
                ECC_DC.removeAllItems();
                for (String curve : DendroCrypto.MONTGOMERY) {
                    ECC_DC.addItem(curve);
                }
            }
            case "Edwards" -> {
                ECC_DC.removeAllItems();
                for (String curve : DendroCrypto.EDWARDS) {
                    ECC_DC.addItem(curve);
                }
            }
        }
    }

    private BigInteger fromRadixInput(JTextArea input, JComboBox<String> radix) {
        BigInteger out = null;
        try {
            String raw = Validation.validateString(input);
            switch ((String) radix.getSelectedItem()) {
                case "Base64" -> out = new BigInteger(Base64.getDecoder().decode(raw));
                case "Hexadecimal" -> out = new BigInteger(raw, 16);
                case "Decimal" -> out = new BigInteger(raw);
            }
        } catch (ValidationFailedException ex) {
            CURRENT_INSTANCE.LOG_HANDLER.error(getClass(), "Private Key must be a number matching the radix");
        } catch (IllegalArgumentException ex) {
            CURRENT_INSTANCE.LOG_HANDLER.error(getClass(), "Private Key must be a number matching the radix");
            input.setBackground(DendroFactory.WRONG);
        }
        return out;
    }

    private void toRadixOutput(JTextArea target, JComboBox<String> radix, BigInteger input) {
        String text = "";
        switch ((String) radix.getSelectedItem()) {
            case "Base64" -> text = Base64.getEncoder().encodeToString(input.toByteArray());
            case "Hexadecimal" -> text = input.toString(16);
            case "Decimal" -> text = input.toString();
        }
        target.setText(text);
    }

    private ECPoint makeECPoint(BigInteger x, BigInteger y, DefinedCurve curve) {
        ECPoint out = null;
        if (curve.E instanceof WeierstrassPrime) {
            out = new WpECPoint(x, y, (WeierstrassPrime) curve.E);
        } else if (curve.E instanceof WeierstrassBinary) {
            out = new WbECPoint(x, y, (WeierstrassBinary) curve.E);
        } else if (curve.E instanceof TwistedEdwards) {
            out = new TeECPoint(x, y, (TwistedEdwards) curve.E);
        } else if (curve.E instanceof Montgomery) {
            out = new MECPoint(x, y, (Montgomery) curve.E);
        } else if (curve.E instanceof Edwards) {
            out = new EdECPoint(x, y, (Edwards) curve.E);
        }
        return out;
    }

    @Override
    public void dispose() {
        conclude(true, true);
    }
}
