package hau.phan.crypto.service;


public interface CryptoAESService {

    public static final int AES_MIN_KEY_SIZE = 128;

    void createAESKey (String keyName, int keySize, char[] keyPassphrase, char[] keyStorePassphrase);

    void initializeCiphers(char[] chars);

    byte[] encryptAES(String clearText, String keyName);

    String decryptAES(byte[] bytes, String keyName);


}
