package hau.phan.crypto.request;


public class DecryptionRequest {
    private static final long serialVersionUID = -5092236298794733384L;
    private String cipherText;
    private String keyName;

    public String getCipherText() {
        return this.cipherText;
    }

    public void setCipherText(String cipherText) {
        this.cipherText = cipherText;
    }

    public String getKeyName() {
        return this.keyName;
    }

    public void setKeyName(String keyName) {
        this.keyName = keyName.toLowerCase();
    }
}
