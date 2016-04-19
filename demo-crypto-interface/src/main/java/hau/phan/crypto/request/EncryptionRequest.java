package hau.phan.crypto.request;

import java.io.Serializable;


public class EncryptionRequest implements Serializable {

    private static final long serialVersionUID = 161754945974999333L;
    private String clearText;
    private String keyName;

    public String getClearText() {
        return this.clearText;
    }

    public void setClearText(String clearText) {
        this.clearText = clearText;
    }

    public String getKeyName() {
        return this.keyName;
    }

    public void setKeyName(String keyName) {
        this.keyName = keyName.toLowerCase();
    }
}
