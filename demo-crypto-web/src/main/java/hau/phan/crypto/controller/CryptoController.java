package hau.phan.crypto.controller;

import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
public class CryptoController {

    @RequestMapping(value = "/add")
    public String ping() {
        return "pong";
    }
}
