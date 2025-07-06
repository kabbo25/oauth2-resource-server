package com.oauth2.resource.controller;

import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.http.ResponseEntity;
import java.util.Map;
import java.util.HashMap;

@RestController
public class ResourceController {

    @GetMapping("/public")
    public ResponseEntity<Map<String, Object>> publicEndpoint() {
        Map<String, Object> response = new HashMap<>();
        response.put("message", "This is a public endpoint");
        response.put("timestamp", System.currentTimeMillis());
        response.put("status", "success");
        return ResponseEntity.ok(response);
    }

    @GetMapping("/health")
    public ResponseEntity<Map<String, Object>> healthCheck() {
        Map<String, Object> response = new HashMap<>();
        response.put("status", "UP");
        response.put("server", "oauth2-resource-server");
        response.put("port", 9001);
        response.put("timestamp", System.currentTimeMillis());
        return ResponseEntity.ok(response);
    }

    @GetMapping("/api/user")
    public ResponseEntity<Map<String, Object>> getUserInfo(Authentication authentication) {
        Map<String, Object> response = new HashMap<>();
        
        if (authentication != null && authentication.getPrincipal() instanceof Jwt) {
            Jwt jwt = (Jwt) authentication.getPrincipal();
            
            response.put("message", "Protected endpoint accessed successfully");
            response.put("subject", jwt.getSubject());
            response.put("username", jwt.getClaimAsString("sub"));
            response.put("scopes", jwt.getClaimAsStringList("scope"));
            response.put("issuer", jwt.getIssuer());
            response.put("issuedAt", jwt.getIssuedAt());
            response.put("expiresAt", jwt.getExpiresAt());
            response.put("tokenId", jwt.getId());
        } else {
            response.put("message", "No valid JWT token found");
            response.put("authType", authentication != null ? authentication.getClass().getSimpleName() : "null");
        }
        
        response.put("timestamp", System.currentTimeMillis());
        return ResponseEntity.ok(response);
    }
}