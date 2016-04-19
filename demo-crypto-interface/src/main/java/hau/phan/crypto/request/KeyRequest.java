package hau.phan.crypto.request;


import java.io.Serializable;

public class KeyRequest implements Serializable {

    private static final long serialVersionUID = -9013795718544293789L;
    private String keyName;
    private int keySize;
    private char[] keyPassphrase;
    private char[] keyStorePassphrase;

    public String getKeyName() {
        return keyName;
    }

    public void setKeyName(String keyName) {
        this.keyName = keyName;
    }

    public int getKeySize() {
        return keySize;
    }

    public void setKeySize(int keySize) {
        this.keySize = keySize;
    }

    public char[] getKeyPassphrase() {
        return keyPassphrase;
    }

    public void setKeyPassphrase(char[] keyPassphrase) {
        this.keyPassphrase = keyPassphrase;
    }

    public char[] getKeyStorePassphrase() {
        return keyStorePassphrase;
    }

    public void setKeyStorePassphrase(char[] keyStorePassphrase) {
        this.keyStorePassphrase = keyStorePassphrase;
    }
}
