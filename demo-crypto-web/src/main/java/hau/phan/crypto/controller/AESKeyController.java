package hau.phan.crypto.controller;

import hau.phan.crypto.request.DecryptionRequest;
import hau.phan.crypto.request.EncryptionRequest;
import hau.phan.crypto.request.KeyRequest;
import hau.phan.crypto.service.CryptoAESService;
import org.codehaus.plexus.util.Base64;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.web.bind.annotation.*;

@RestController
@RequestMapping(value = "/keys/aes")
public class AESKeyController {

    @Autowired
    private CryptoAESService cryptoAESService;

    @RequestMapping(method = RequestMethod.POST)
    public String keyAdd(@RequestBody KeyRequest keyRequest){
        cryptoAESService.createAESKey(keyRequest.getKeyName(), keyRequest.getKeySize(), keyRequest.getKeyPassphrase(), keyRequest.getKeyStorePassphrase());
        return "ok";
    }

    @RequestMapping(value="/encrypt", method=RequestMethod.POST)
    public String encryptAES(@RequestBody EncryptionRequest request) {
        byte[] encryptionResult = cryptoAESService.encryptAES(request.getClearText(), request.getKeyName());
        return new String(Base64.encodeBase64(encryptionResult));
    }

    @RequestMapping(value="/decrypt", method=RequestMethod.POST)
    public @ResponseBody String decryptAES(@RequestBody DecryptionRequest request) {
        return cryptoAESService.decryptAES(Base64.decodeBase64(request.getCipherText().getBytes()), request.getKeyName());
    }
}
