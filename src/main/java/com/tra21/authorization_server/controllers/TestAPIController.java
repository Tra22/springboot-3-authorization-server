package com.tra21.authorization_server.controllers;

import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/api/v1/test")
public class TestAPIController {
    @GetMapping
    public ResponseEntity<String> test(){
        return ResponseEntity.ok("Testing successes.");
    }
}
