package com.pnc.ilab.fbchatbot.coldbox.util;

import org.apache.commons.codec.binary.Base64;
import org.bouncycastle.util.io.pem.PemReader;
import sun.misc.BASE64Encoder;

import javax.crypto.Cipher;
import java.io.ByteArrayInputStream;
import java.io.FileReader;
import java.io.IOException;
import java.math.BigInteger;
import java.security.*;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.RSAPublicKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Arrays;

/**
 * // TODO: 9/18/17 Document.
 */
public final class CryptoUtil {

    private static final byte[] PREFIX = new byte[]{0, 0, 0, 7, 's', 's',
            'h', '-', 'r', 's', 'a'};

    public static void main(String[] args) throws Exception {

        Security.addProvider(new org.bouncycastle.jce.provider.BouncyCastleProvider());

//        KeyPair pair = generateKeys();
//        PublicKey pubKey = pair.getPublic();
//        PrivateKey privKey = pair.getPrivate();
//
//        BASE64Encoder b64 = new BASE64Encoder();
//        System.out.println("publicKey : " + b64.encode(pubKey.getEncoded()));
//        System.out.println("privateKey : " + b64.encode(privKey.getEncoded()));
//        decrypt(encrypt(msg, pubKey), privKey);

        String msg = "TEST";

        PublicKey publicKeyFromPemFile = readPublicKeyFromPemFile("public_key.pem");
        PrivateKey privateKeyFromPemFile = readPrivateKeyFromPemFile("private_key.pem");

        String encText = encrypt(msg, publicKeyFromPemFile);
        decrypt(encText, privateKeyFromPemFile);
    }


    public static PrivateKey readPrivateKeyFromPemFile(String filePath) throws Exception {
        FileReader fr = new FileReader(filePath);// Create a FileReader for myhost.crt
        PemReader pemReader = new PemReader(fr);

        PKCS8EncodedKeySpec caKeySpec = new PKCS8EncodedKeySpec(pemReader.readPemObject().getContent());
        KeyFactory kf = KeyFactory.getInstance("RSA");
        PrivateKey caKey = kf.generatePrivate(caKeySpec);
        System.out.println(caKey);
        return caKey;
    }


    public static PublicKey readPublicKeyFromPemFile(String filePath) throws Exception {
        FileReader fr = new FileReader(filePath);// Create a FileReader for myhost.crt
        PemReader pemReader = new PemReader(fr);

        X509EncodedKeySpec caKeySpec = new X509EncodedKeySpec(pemReader.readPemObject().getContent());
        KeyFactory kf = KeyFactory.getInstance("RSA");
        PublicKey caKey = kf.generatePublic(caKeySpec);
        System.out.println(caKey);
        return caKey;
    }

    public static String encrypt(String msg, PublicKey pubKey) throws Exception {
        Cipher cipher = Cipher.getInstance("RSA");
        // encryption
        cipher.init(Cipher.ENCRYPT_MODE, pubKey);
        String encMsg = Base64.encodeBase64String(cipher.doFinal(msg.getBytes("UTF-8")));
        System.out.println("Encrpyted: " + encMsg);

        return encMsg;
    }

    public static String decrypt(String encMsg, PrivateKey privateKey) throws Exception {
        Cipher cipher = Cipher.getInstance("RSA");
        // encryption
        cipher.init(Cipher.DECRYPT_MODE, privateKey);
        String decryptedMsg = new String(cipher.doFinal(Base64.decodeBase64(encMsg)), "UTF-8");
        System.out.println("Decrypted: " + decryptedMsg);
        return encMsg;
    }

    public static KeyPair generateKeys() throws Exception {

        Security.addProvider(new org.bouncycastle.jce.provider.BouncyCastleProvider());

        // Create the public and private keys
        KeyPairGenerator generator = KeyPairGenerator.getInstance("RSA", "BC");
        BASE64Encoder b64 = new BASE64Encoder();

        SecureRandom random = createFixedRandom();
        generator.initialize(1024, random);

        KeyPair pair = generator.generateKeyPair();
        return pair;
    }


    private static RSAPublicKey parseSSHPublicKey(String encKey) throws Exception {
        ByteArrayInputStream in = new ByteArrayInputStream(
                encKey.getBytes());

        byte[] prefix = new byte[11];

        if (in.read(prefix) != 11 || !Arrays.equals(PREFIX, prefix)) {
            throw new IllegalArgumentException("SSH key prefix not found");
        }

        BigInteger e = new BigInteger(readBigInteger(in));
        BigInteger n = new BigInteger(readBigInteger(in));

        return createPublicKey(n, e);

    }


    static RSAPublicKey createPublicKey(BigInteger n, BigInteger e) {
        try {
            return (RSAPublicKey) KeyFactory.getInstance("RSA").generatePublic(
                    new RSAPublicKeySpec(n, e));
        } catch (Exception ex) {
            throw new RuntimeException(ex);
        }
    }

    public static SecureRandom createFixedRandom() {
        return new FixedRand();
    }

    private static class FixedRand extends SecureRandom {

        MessageDigest sha;
        byte[] state;

        FixedRand() {
            try {
                this.sha = MessageDigest.getInstance("SHA-1");
                this.state = sha.digest();
            } catch (NoSuchAlgorithmException e) {
                throw new RuntimeException("can't find SHA-1!");
            }
        }

        public void nextBytes(byte[] bytes) {

            int off = 0;

            sha.update(state);

            while (off < bytes.length) {
                state = sha.digest();

                if (bytes.length - off > state.length) {
                    System.arraycopy(state, 0, bytes, off, state.length);
                } else {
                    System.arraycopy(state, 0, bytes, off, bytes.length - off);
                }

                off += state.length;

                sha.update(state);
            }
        }
    }

    private static byte[] readBigInteger(ByteArrayInputStream in)
            throws IOException {
        byte[] b = new byte[4];

        if (in.read(b) != 4) {
            throw new IOException("Expected length data as 4 bytes");
        }

        int l = ((b[0] & 0xFF) << 24) | ((b[1] & 0xFF) << 16) | ((b[2] & 0xFF) << 8) | (b[3] & 0xFF);

        b = new byte[l];

        if (in.read(b) != l) {
            throw new IOException("Expected " + l + " key bytes");
        }

        return b;
    }
}
