package hau.phan.crypto.service.impl;


import hau.phan.crypto.service.CryptoAESService;
import org.apache.commons.lang3.ArrayUtils;
import org.apache.commons.lang3.StringUtils;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;

import javax.crypto.*;
import javax.crypto.spec.IvParameterSpec;
import java.io.*;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.NoSuchFileException;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.*;
import java.security.cert.*;
import java.util.Arrays;
import java.util.Enumeration;
import java.util.HashMap;
import java.util.Map;

@Service
public class CryptoAESServiceImpl implements CryptoAESService {

    @Value("${key.store.location}")
    private String keyStoreLocation;

    @Value("${keys.passphrase.file.location}")
    private String keyPassphraseLocation;

    private static final String PASSPHRASE_ENCRYPTION_KEY_NAME = "master1";

    private static final String AES_CBC_PKCS5PADDING = "AES/CBC/PKCS5PADDING";

    private static final String smartlinkPubicKeyV1Name = "sl-pcs";

    private static final String SHA256_PEPPER_KEY_NAME = "sha256pepper";

    private static final int AES_KEY_SIZE_INTERNAL = 128;    //Should be at least 128 for PCI compliance, 256 will require Unlimited Strength Policy

    private static final String DEFAULT_KEY_PASSPHRASE = "changeit";

    private static final String HMAC_SHA256_ALGORITHM = "HmacSHA256";

    private Map<String, Cipher> decryptionCiphers = new HashMap<>();
    private Map<String, Cipher> encryptionCiphers = new HashMap<>();
    private Map<String, SecretKey> secretKeys = new HashMap<>();

    private byte[] pepperKeyBytes;

    private StringBuffer keysFailedLoading = new StringBuffer("None");
    private StringBuffer keysWithDefaultPassword = new StringBuffer("None");

    @Override
    public void createAESKey(String keyName, int keySize, char[] keyPassphrase, char[] keyStorePassphrase) {

        try {
            KeyStore keyStore = loadKeystore(keyStorePassphrase);
            if (keyStore.containsAlias(keyName)) {
                    throw new Exception("KeyDuplicateException");
            }

            KeyGenerator keyGen = KeyGenerator.getInstance("AES");
            keyGen.init(keySize);
            SecretKey secretKey = keyGen.generateKey();
            keyStore.setEntry(keyName, new KeyStore.SecretKeyEntry(secretKey), new KeyStore.PasswordProtection(keyPassphrase));
            saveKeyStore(keyStore, keyStorePassphrase);
            addToSecretKeys(keyName, secretKey);
            SecretKey passphraseEncryptionKey = (SecretKey) keyStore.getKey(PASSPHRASE_ENCRYPTION_KEY_NAME, keyStorePassphrase);
            if (passphraseEncryptionKey == null)
                throw new Exception("passphraseEncryptionKey not found in keyStore");
            encryptAndSaveKeyPassphraseToFile(keyName, keyPassphrase, passphraseEncryptionKey);
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    @Override
    public void initializeCiphers(char[] keyStorePassphrase) {
        try {

            //migrate old keystore file
            setupPassphraseEncryptionKey(keyStorePassphrase);
            setupSHA256PepperKey(keyStorePassphrase);

            KeyStore keyStore = loadKeystore(keyStorePassphrase);
            SecretKey passphraseEncryptionKey = (SecretKey) keyStore.getKey(PASSPHRASE_ENCRYPTION_KEY_NAME, keyStorePassphrase);
            if (passphraseEncryptionKey == null)
                throw new RuntimeException("passphraseEncryptionKey not found in keystore");

            SecretKey pepperKey = (SecretKey) keyStore.getKey(SHA256_PEPPER_KEY_NAME, keyStorePassphrase);
            pepperKeyBytes = pepperKey.getEncoded();

            keysFailedLoading = new StringBuffer(512).append("");
            keysWithDefaultPassword = new StringBuffer(512).append("");
            Enumeration<String> aliases = keyStore.aliases();
            while (aliases.hasMoreElements()) {
                String keyName = (String) aliases.nextElement();
                if (StringUtils.equals(keyName, PASSPHRASE_ENCRYPTION_KEY_NAME) || StringUtils.equals(keyName, SHA256_PEPPER_KEY_NAME))
                    continue;
                Key key = null;
                try {
                    String keyPassphrase = getKeyPasshphrase(keyName, passphraseEncryptionKey);
                    System.out.println("keyPassphrase for " + keyName.toString() + keyPassphrase.toString());
                    key = keyStore.getKey(keyName, keyPassphrase.toCharArray());

                } catch (Exception e) {
                    try {

                        key = keyStore.getKey(keyName, DEFAULT_KEY_PASSPHRASE.toCharArray());
                        keysWithDefaultPassword.append(keyName).append(" ");

                    } catch (UnrecoverableKeyException ex) {
                        keysFailedLoading.append(keyName).append(" ");
                        continue;
                    }
                }
                if (key instanceof PrivateKey) {
                    java.security.cert.Certificate cert = keyStore.getCertificate(keyName);
                    PublicKey publicKey = cert.getPublicKey();

                    Cipher encryptionCipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
                    encryptionCipher.init(Cipher.ENCRYPT_MODE, publicKey);
                    encryptionCiphers.put(keyName, encryptionCipher);

                    Cipher decryptionCipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
                    decryptionCipher.init(Cipher.DECRYPT_MODE, key);
                    decryptionCiphers.put(keyName, decryptionCipher);
                }
                if (key instanceof SecretKey) {
                    secretKeys.put(keyName, (SecretKey) key);
                } else {

                }
            }
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }

    @Override
    public byte[] encryptAES(String clearText, String keyName) {
        SecretKey secretKey = secretKeys.get(keyName);
        if (secretKey == null) {
            throw new RuntimeException("Key not found or ciphers not initialized.");
        }
        return encryptAES(clearText, secretKey);
    }

    @Override
    public String decryptAES(byte[] input, String keyName) {
        byte[] ivParamSpec = Arrays.copyOfRange(input, 0, 16);
        byte[] cipherText = Arrays.copyOfRange(input, 16, input.length);
        try {
            SecretKey secretKey = secretKeys.get(keyName);
            Cipher aesCipher = Cipher.getInstance(AES_CBC_PKCS5PADDING);
            aesCipher.init(Cipher.DECRYPT_MODE, secretKey, new IvParameterSpec(ivParamSpec));
            return bytesToString(aesCipher.doFinal(cipherText));
        } catch (InvalidKeyException | NoSuchAlgorithmException | NoSuchPaddingException | IllegalBlockSizeException | BadPaddingException | InvalidAlgorithmParameterException e) {
            throw new RuntimeException(e.getMessage());
        }
    }

    private String getKeyPasshphrase(String keyName, SecretKey passphraseEncryptionKey) throws Exception {
        byte[] passphraseProtected;
        try {
            passphraseProtected = Files.readAllBytes(Paths.get(keyPassphraseLocation + File.separator + keyName + ".kpp"));
        } catch (IOException e) {
            migratePassphraseFiles(keyName, passphraseEncryptionKey);
            passphraseProtected = Files.readAllBytes(Paths.get(keyPassphraseLocation + File.separator + keyName + ".kpp"));
        }

        byte[] iv = Arrays.copyOfRange(passphraseProtected, 0, 16);
        byte[] cipherText = Arrays.copyOfRange(passphraseProtected, 16, passphraseProtected.length);

        Cipher aesCipher = Cipher.getInstance(AES_CBC_PKCS5PADDING);
        aesCipher.init(Cipher.DECRYPT_MODE, passphraseEncryptionKey, new IvParameterSpec(iv));
        byte[] byteDecryptedText = aesCipher.doFinal(cipherText);
        return bytesToString(byteDecryptedText);

    }

    private void migratePassphraseFiles(String keyName, SecretKey passphraseEncryptionKey) throws Exception {
        try {
            final Path binPath = Paths.get(keyPassphraseLocation + File.separator + keyName + ".bin");
            final Path ivpPath = Paths.get(keyPassphraseLocation + File.separator + keyName + ".ivp");

            byte[] dataEncrypted = Files.readAllBytes(binPath);
            byte[] iv = Files.readAllBytes(ivpPath);

            byte[] keyPassphraseProtected = ArrayUtils.addAll(iv, dataEncrypted);

            final String kppPath = keyPassphraseLocation + File.separator + keyName + ".kpp";
            try (FileOutputStream out = new FileOutputStream(kppPath)) {
                out.write(keyPassphraseProtected);
            } catch (IOException e) {
                throw new RuntimeException("Migration KPP failed.");
            }

            final Path binPathBackup = Paths.get(keyPassphraseLocation + File.separator + keyName + ".bin.bak");
            final Path ivpPathBackup = Paths.get(keyPassphraseLocation + File.separator + keyName + ".ivp.bak");
            Files.move(binPath, binPathBackup);
            Files.move(ivpPath, ivpPathBackup);

        } catch (NoSuchFileException e) {
            throw e;
        } catch (IOException e) {
            throw e;
        }
    }

    private void setupPassphraseEncryptionKey(char[] keyStorePassphrase) throws Exception {
        try {
            KeyStore keyStore = loadKeystore(keyStorePassphrase);
            if (keyStore.containsAlias(PASSPHRASE_ENCRYPTION_KEY_NAME))
                return;
            KeyGenerator keyGen = KeyGenerator.getInstance("AES");
            keyGen.init(AES_KEY_SIZE_INTERNAL);
            SecretKey secretKey = keyGen.generateKey();
            keyStore.setEntry(PASSPHRASE_ENCRYPTION_KEY_NAME, new KeyStore.SecretKeyEntry(secretKey), new KeyStore.PasswordProtection(keyStorePassphrase));
            saveKeyStore(keyStore, keyStorePassphrase);
        } catch (Exception e) {
            System.out.println(e.toString());
        }
    }

    private void setupSHA256PepperKey(char[] keyStorePassphrase) throws Exception {
        try {
            KeyStore keyStore = loadKeystore(keyStorePassphrase);
            if (keyStore.containsAlias(SHA256_PEPPER_KEY_NAME))
                return;
            KeyGenerator keyGen = KeyGenerator.getInstance(HMAC_SHA256_ALGORITHM);
            keyGen.init(256);
            SecretKey secretKey = keyGen.generateKey();
            keyStore.setEntry(SHA256_PEPPER_KEY_NAME, new KeyStore.SecretKeyEntry(secretKey), new KeyStore.PasswordProtection(keyStorePassphrase));
            saveKeyStore(keyStore, keyStorePassphrase);
        } catch (Exception e) {
            System.out.println(e.toString());
        }
    }

    private void encryptAndSaveKeyPassphraseToFile(String keyName, char[] keyPassphrase, SecretKey passphraseEncryptionKey) {
        byte[] passphraseProtected = encryptAES(new String(keyPassphrase), passphraseEncryptionKey);

        try (FileOutputStream out = new FileOutputStream(keyPassphraseLocation + File.separator + keyName + ".kpp")) {
            out.write(passphraseProtected);
        } catch (IOException e) {
            System.out.println(e.toString());
        }

    }

    private byte[] encryptAES(String clearText, SecretKey secretKey) {
        try {
            byte[] iv = generateIV();
            Cipher aesCipher = Cipher.getInstance(AES_CBC_PKCS5PADDING);
            aesCipher.init(Cipher.ENCRYPT_MODE, secretKey, new IvParameterSpec(iv));
            byte[] byteCipherText = aesCipher.doFinal(stringToBytes(clearText));
            return ArrayUtils.addAll(iv, byteCipherText);

        } catch (InvalidKeyException | NoSuchAlgorithmException | NoSuchPaddingException | IllegalBlockSizeException | BadPaddingException | InvalidAlgorithmParameterException e) {
            throw new RuntimeException("encrypt");
        }
    }

    private byte[] stringToBytes(String s) {
        return s.getBytes(StandardCharsets.UTF_8);
    }

    private String bytesToString(byte[] b) {
        return new String(b, StandardCharsets.UTF_8);
    }

    private byte[] generateIV() {
        byte[] iv = new byte[16];
        SecureRandom prng = new SecureRandom();
        prng.nextBytes(iv);
        return iv;
    }

    private void addToSecretKeys(String keyName, SecretKey secretKey) {
        secretKeys.put(keyName, secretKey);
    }

    private void saveKeyStore(KeyStore keyStore, char[] keyStorePassphrase) {
        try (FileOutputStream out = new FileOutputStream(keyStoreLocation)) {
            keyStore.store(out, keyStorePassphrase);
            out.flush();
        } catch (IOException e) {
            System.out.println("IOException");
        } catch (KeyStoreException | CertificateException | NoSuchAlgorithmException e) {
            System.out.println("KeyStoreException");
        }
    }

    private KeyStore loadKeystore(char[] keyStorePassphrase) throws Exception {
        try (InputStream fis = new FileInputStream(keyStoreLocation)) {
            KeyStore keyStore = KeyStore.getInstance("JCEKS");
            keyStore.load(fis, keyStorePassphrase);
            return keyStore;
        } catch (NoSuchAlgorithmException | CertificateException | IOException | KeyStoreException e) {
            throw new RuntimeException("keyStoreLoadingError");
        }
    }
}
