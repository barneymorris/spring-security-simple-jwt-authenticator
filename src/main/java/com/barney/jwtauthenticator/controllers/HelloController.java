package com.barney.jwtauthenticator.controllers;

import org.springframework.web.bind.annotation.GetMapping;

public class HelloController {
    @GetMapping("/hello")
    public String hello() {
        return "hello";
    }
}
