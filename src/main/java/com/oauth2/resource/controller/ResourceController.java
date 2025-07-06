package com.oauth2.resource.controller;

import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.beans.factory.annotation.Autowired;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import jakarta.servlet.http.HttpServletRequest;
import com.oauth2.resource.service.MockDataService;
import java.util.Map;
import java.util.HashMap;
import java.util.List;

@RestController
public class ResourceController {

    private static final Logger logger = LoggerFactory.getLogger(ResourceController.class);
    
    @Autowired
    private MockDataService mockDataService;

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
    public ResponseEntity<Map<String, Object>> getUserInfo(Authentication authentication, HttpServletRequest request) {
        Map<String, Object> response = new HashMap<>();
        
        logger.info("=== /api/user endpoint accessed ===");
        logger.info("Request headers: Authorization={}", request.getHeader("Authorization"));
        logger.info("Request Origin: {}", request.getHeader("Origin"));
        logger.info("Request User-Agent: {}", request.getHeader("User-Agent"));
        
        if (authentication != null && authentication.getPrincipal() instanceof Jwt) {
            Jwt jwt = (Jwt) authentication.getPrincipal();
            
            logger.info("JWT Token Details:");
            logger.info("  Subject: {}", jwt.getSubject());
            logger.info("  Issuer: {}", jwt.getIssuer());
            logger.info("  Audience: {}", jwt.getAudience());
            logger.info("  Client ID: {}", jwt.getClaimAsString("client_id"));
            logger.info("  Scopes: {}", jwt.getClaimAsStringList("scope"));
            logger.info("  Issued At: {}", jwt.getIssuedAt());
            logger.info("  Expires At: {}", jwt.getExpiresAt());
            
            response.put("message", "Protected endpoint accessed successfully");
            response.put("subject", jwt.getSubject());
            response.put("username", jwt.getClaimAsString("sub"));
            response.put("scopes", jwt.getClaimAsStringList("scope"));
            response.put("issuer", jwt.getIssuer());
            response.put("issuedAt", jwt.getIssuedAt());
            response.put("expiresAt", jwt.getExpiresAt());
            response.put("tokenId", jwt.getId());
        } else {
            logger.warn("No valid JWT token found in request");
            response.put("message", "No valid JWT token found");
            response.put("authType", authentication != null ? authentication.getClass().getSimpleName() : "null");
        }
        
        response.put("timestamp", System.currentTimeMillis());
        return ResponseEntity.ok(response);
    }

    @GetMapping("/api/verify")
    public ResponseEntity<Map<String, Object>> verifyToken(Authentication authentication, HttpServletRequest request) {
        Map<String, Object> response = new HashMap<>();
        
        logger.info("=== /api/verify endpoint accessed ===");
        logger.info("Request Origin: {}", request.getHeader("Origin"));
        logger.info("Request Referer: {}", request.getHeader("Referer"));
        
        if (authentication != null && authentication.getPrincipal() instanceof Jwt) {
            Jwt jwt = (Jwt) authentication.getPrincipal();
            
            logger.info("Token verification details:");
            logger.info("  Token ID: {}", jwt.getId());
            logger.info("  Client ID: {}", jwt.getClaimAsString("aud"));
            logger.info("  All Claims: {}", jwt.getClaims());
            
            response.put("valid", true);
            assert jwt.getIssuedAt() != null;
            assert jwt.getExpiresAt() != null;
            response.put("tokenDetails", Map.of(
                "subject", jwt.getSubject(),
                "clientId", jwt.getClaimAsString("aud"),
                "audience", jwt.getAudience(),
                "scopes", jwt.getClaimAsStringList("scope"),
                "issuer", jwt.getIssuer(),
                "issuedAt", jwt.getIssuedAt(),
                "expiresAt", jwt.getExpiresAt(),
                "tokenId", jwt.getId(),
                "allClaims", jwt.getClaims()
            ));
        } else {
            logger.warn("Token verification failed - no valid JWT");
            response.put("valid", false);
            response.put("error", "No valid JWT token found");
        }
        
        response.put("timestamp", System.currentTimeMillis());
        response.put("endpoint", "/api/verify");
        return ResponseEntity.ok(response);
    }

    @GetMapping("/api/client-info")
    public ResponseEntity<Map<String, Object>> getClientInfo(Authentication authentication, HttpServletRequest request) {
        Map<String, Object> response = new HashMap<>();
        
        logger.info("=== /api/client-info endpoint accessed ===");
        
        if (authentication != null && authentication.getPrincipal() instanceof Jwt) {
            Jwt jwt = (Jwt) authentication.getPrincipal();
            
            String clientId = jwt.getClaimAsString("aud");
            String origin = request.getHeader("Origin");
            String referer = request.getHeader("Referer");
            
            logger.info("Client identification:");
            logger.info("  JWT Client ID: {}", clientId);
            logger.info("  Request Origin: {}", origin);
            logger.info("  Request Referer: {}", referer);
            
            String identifiedClient = "unknown";
            if ("client".equals(clientId) || "8080".equals(extractPort(origin)) || "8080".equals(extractPort(referer))) {
                identifiedClient = "spring-boot-client";
            } else if ("react-client".equals(clientId) || "3000".equals(extractPort(origin)) || "3000".equals(extractPort(referer))) {
                identifiedClient = "react-client";
            }
            
            logger.info("  Identified as: {}", identifiedClient);
            
            response.put("clientId", clientId);
            response.put("identifiedClient", identifiedClient);
            response.put("requestOrigin", origin);
            response.put("requestReferer", referer);
            response.put("scopes", jwt.getClaimAsStringList("scope"));
            response.put("subject", jwt.getSubject());
        } else {
            logger.warn("No JWT token available for client identification");
            response.put("error", "No valid JWT token found");
        }
        
        response.put("timestamp", System.currentTimeMillis());
        response.put("endpoint", "/api/client-info");
        return ResponseEntity.ok(response);
    }

    private String extractPort(String url) {
        if (url == null) return null;
        try {
            if (url.contains(":3000")) return "3000";
            if (url.contains(":8080")) return "8080";
            if (url.contains(":9000")) return "9000";
            if (url.contains(":9001")) return "9001";
        } catch (Exception e) {
            logger.debug("Error extracting port from URL: {}", url, e);
        }
        return null;
    }

    @GetMapping("/api/data")
    public ResponseEntity<Map<String, Object>> getDashboardData(Authentication authentication) {
        logger.info("=== /api/data endpoint accessed ===");
        
        if (authentication != null && authentication.getPrincipal() instanceof Jwt) {
            Jwt jwt = (Jwt) authentication.getPrincipal();
            logger.info("Serving dashboard data to user: {}", jwt.getSubject());
            
            Map<String, Object> response = mockDataService.getDashboardData();
            response.put("requestedBy", jwt.getSubject());
            response.put("clientId", jwt.getClaimAsString("aud"));
            response.put("timestamp", System.currentTimeMillis());
            
            return ResponseEntity.ok(response);
        }
        
        return ResponseEntity.status(401).body(Map.of("error", "Unauthorized"));
    }

    @GetMapping("/api/profile")
    @PreAuthorize("hasAuthority('SCOPE_profile')")
    public ResponseEntity<Map<String, Object>> getProfile(Authentication authentication) {
        logger.info("=== /api/profile endpoint accessed ===");
        
        if (authentication != null && authentication.getPrincipal() instanceof Jwt) {
            Jwt jwt = (Jwt) authentication.getPrincipal();
            List<String> scopes = jwt.getClaimAsStringList("scope");
            
            logger.info("Profile access for user: {} with scopes: {}", jwt.getSubject(), scopes);
            
            if (scopes == null || !scopes.contains("profile")) {
                logger.warn("Profile access denied - missing 'profile' scope");
                return ResponseEntity.status(403).body(Map.of(
                    "error", "Insufficient scope",
                    "required", "profile",
                    "available", scopes != null ? scopes : List.of()
                ));
            }
            
            Map<String, Object> profile = mockDataService.getUserProfile(jwt.getSubject());
            profile.put("accessedAt", System.currentTimeMillis());
            profile.put("scopes", scopes);
            
            return ResponseEntity.ok(profile);
        }
        
        return ResponseEntity.status(401).body(Map.of("error", "Unauthorized"));
    }

    @GetMapping("/api/protected")
    @PreAuthorize("hasAuthority('SCOPE_read')")
    public ResponseEntity<Map<String, Object>> getProtectedData(Authentication authentication) {
        logger.info("=== /api/protected endpoint accessed ===");
        
        if (authentication != null && authentication.getPrincipal() instanceof Jwt) {
            Jwt jwt = (Jwt) authentication.getPrincipal();
            List<String> scopes = jwt.getClaimAsStringList("scope");
            
            logger.info("Protected data access for user: {} with scopes: {}", jwt.getSubject(), scopes);
            
            if (scopes == null || !scopes.contains("read")) {
                logger.warn("Protected data access denied - missing 'read' scope");
                return ResponseEntity.status(403).body(Map.of(
                    "error", "Insufficient scope",
                    "required", "read",
                    "available", scopes != null ? scopes : List.of()
                ));
            }
            
            Map<String, Object> response = new HashMap<>();
            response.put("documents", mockDataService.getProtectedDocuments());
            response.put("systemStats", mockDataService.getSystemStats());
            response.put("accessedBy", jwt.getSubject());
            response.put("accessTime", System.currentTimeMillis());
            response.put("classification", "confidential");
            response.put("scopes", scopes);
            
            return ResponseEntity.ok(response);
        }
        
        return ResponseEntity.status(401).body(Map.of("error", "Unauthorized"));
    }

    @GetMapping("/api/admin")
    @PreAuthorize("hasAuthority('SCOPE_admin')")
    public ResponseEntity<Map<String, Object>> getAdminData(Authentication authentication) {
        logger.info("=== /api/admin endpoint accessed ===");
        
        if (authentication != null && authentication.getPrincipal() instanceof Jwt) {
            Jwt jwt = (Jwt) authentication.getPrincipal();
            List<String> scopes = jwt.getClaimAsStringList("scope");
            
            logger.info("Admin data access attempt for user: {} with scopes: {}", jwt.getSubject(), scopes);
            
            if (scopes == null || !scopes.contains("admin")) {
                logger.warn("Admin access denied - missing 'admin' scope for user: {}", jwt.getSubject());
                return ResponseEntity.status(403).body(Map.of(
                    "error", "Insufficient scope",
                    "required", "admin",
                    "available", scopes != null ? scopes : List.of(),
                    "message", "This endpoint requires administrative privileges"
                ));
            }
            
            Map<String, Object> response = new HashMap<>();
            response.put("message", "Admin access granted");
            response.put("adminFeatures", List.of("user_management", "system_config", "audit_logs", "security_settings"));
            response.put("systemHealth", "excellent");
            response.put("accessedBy", jwt.getSubject());
            response.put("accessTime", System.currentTimeMillis());
            response.put("scopes", scopes);
            
            return ResponseEntity.ok(response);
        }
        
        return ResponseEntity.status(401).body(Map.of("error", "Unauthorized"));
    }
}