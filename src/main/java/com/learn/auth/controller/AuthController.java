package com.learn.auth.controller;



import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/api")
public class AuthController {

    @GetMapping("/public")
    public String publicMessage() {
        return "This is a public message";
    }

    @GetMapping("/user")
    @PreAuthorize("hasRole('USER')")
    public String userMessage() {
        return "Hello User!";
    }

    @GetMapping("/admin")
    @PreAuthorize("hasRole('ADMIN')")
    public String adminMessage() {
        return "Hello Admin!";
    }

}