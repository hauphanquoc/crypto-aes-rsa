package hau.phan.crypto.service;


public interface CryptoRSAService {

    public static final int RSA_MIN_KEY_SIZE = 2048;

    void createRSAKey(String keyName, int keySize, char[] keyPassphrase, char[] keyStorePassphrase);
}
