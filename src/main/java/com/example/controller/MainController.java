package com.example.controller;

import org.springframework.security.core.Authentication;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.GetMapping;

@Controller
public class MainController {

    @GetMapping(value = "/")
    public String home() {
        Authentication authentication = SecurityContextHolder.getContext().getAuthentication(); // Authentication 을 반환
        System.out.println(authentication.getPrincipal());
        return "index";
    }

    @GetMapping(value = "/loginSuccess")
    public String loginSuccess() {
        return "private";
    }

    @GetMapping(value = "/private")
    public String privatePage() {
        return "private";
    }

    @GetMapping(value = "/public")
    public String publicPage() {
        return "public";
    }

    @GetMapping(value = "/login")
    public String loginPage() {
        return "login";
    }

    @GetMapping(value = "/admin")
    public String adminPage() {
        return "admin";
    }

    @GetMapping(value = "/access_denied")
    public String access_denied_page() {
        return "access_denied";
    }

    @GetMapping(value = "/private/context")
    public String privateContextPage(
             Authentication authentication
    ) {

        SecurityContextHolder.getContext().getAuthentication(); // Authentication 을 반환

        System.out.println(authentication.getPrincipal());

        return "private";
    }
}
