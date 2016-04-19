package hau.phan.crypto.controller;

import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
public class HomeController {

    @RequestMapping(value = "/ping")
    public String ping() {
        System.out.println("them 1 dong");
        return "pong";
    }
}
