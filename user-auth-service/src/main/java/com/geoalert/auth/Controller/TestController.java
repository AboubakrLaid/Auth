package com.geoalert.auth.Controller;

import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/api/test")
public class TestController {

    //access by the user and admin
    @GetMapping("/public/hello")
    public String hello()
    {
        return "Hello";
    }

    //access by the admin
    @GetMapping("/private/hello")
    public String helloPrivate()
    {
        return "Hello Private";
    }
}
