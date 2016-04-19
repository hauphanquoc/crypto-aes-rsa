package hau.phan.crypto.service.impl;

import hau.phan.crypto.service.CryptoRSAService;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;

@Service
public class CryptoRSAServiceImpl implements CryptoRSAService{

    @Value("${key.store.location}")
    private String keyStoreLocation;

    @Value("${keys.passphrase.file.location}")
    private String keyPassphraseLocation;

    @Override
    public void createRSAKey(String keyName, int keySize, char[] keyPassphrase, char[] keyStorePassphrase) {

    }
}
