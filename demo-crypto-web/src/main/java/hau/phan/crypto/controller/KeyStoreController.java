package hau.phan.crypto.controller;

import hau.phan.crypto.service.CryptoAESService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

@RestController
@RequestMapping(value = "/keyStore")
public class KeyStoreController {

    @Autowired
    private CryptoAESService cryptoAESService;

    @RequestMapping(value="/init", method= RequestMethod.POST)
    public ResponseEntity<String> init(@RequestBody String keystorePass) {
        try {
            cryptoAESService.initializeCiphers(keystorePass.toCharArray());
        } catch (Exception e) {
            throw new RuntimeException();
        }
        return new ResponseEntity<String>("OK", HttpStatus.OK);
    }
}
