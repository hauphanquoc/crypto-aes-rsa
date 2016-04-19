package hau.phan.crypto.controller;

import hau.phan.crypto.request.KeyRequest;
import hau.phan.crypto.service.CryptoAESService;
import hau.phan.crypto.service.CryptoRSAService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

@RestController
@RequestMapping(value = "/keys/rsa")
public class RSAKeyController {

    @Autowired
    private CryptoRSAService cryptoAESService;

    @RequestMapping(method= RequestMethod.POST)
    public ResponseEntity<String> generateRSAKey(@RequestBody KeyRequest request) {
        cryptoAESService.createRSAKey(request.getKeyName(), request.getKeySize(), request.getKeyPassphrase(), request.getKeyStorePassphrase());
        return new ResponseEntity<String>("Created", HttpStatus.CREATED);
    }
}
