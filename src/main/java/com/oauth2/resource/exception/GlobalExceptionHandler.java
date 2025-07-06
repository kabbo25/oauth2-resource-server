package com.oauth2.resource.exception;

import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.security.core.AuthenticationException;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.RestControllerAdvice;
import org.springframework.web.context.request.WebRequest;
import org.springframework.web.servlet.NoHandlerFoundException;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.time.LocalDateTime;
import java.util.HashMap;
import java.util.Map;
import java.util.UUID;

@RestControllerAdvice
public class GlobalExceptionHandler {

    private static final Logger logger = LoggerFactory.getLogger(GlobalExceptionHandler.class);

    @ExceptionHandler(AuthenticationException.class)
    public ResponseEntity<Map<String, Object>> handleAuthenticationException(
            AuthenticationException ex, WebRequest request) {
        
        String errorId = UUID.randomUUID().toString();
        logger.error("Authentication failed [{}]: {}", errorId, ex.getMessage(), ex);
        
        Map<String, Object> errorResponse = new HashMap<>();
        errorResponse.put("error", "authentication_failed");
        errorResponse.put("message", "Authentication required");
        errorResponse.put("details", ex.getMessage());
        errorResponse.put("timestamp", LocalDateTime.now());
        errorResponse.put("path", request.getDescription(false).replace("uri=", ""));
        errorResponse.put("errorId", errorId);
        errorResponse.put("status", 401);
        
        return ResponseEntity.status(HttpStatus.UNAUTHORIZED).body(errorResponse);
    }

    @ExceptionHandler(AccessDeniedException.class)
    public ResponseEntity<Map<String, Object>> handleAccessDeniedException(
            AccessDeniedException ex, WebRequest request) {
        
        String errorId = UUID.randomUUID().toString();
        logger.error("Access denied [{}]: {}", errorId, ex.getMessage(), ex);
        
        Map<String, Object> errorResponse = new HashMap<>();
        errorResponse.put("error", "access_denied");
        errorResponse.put("message", "Insufficient permissions");
        errorResponse.put("details", ex.getMessage());
        errorResponse.put("timestamp", LocalDateTime.now());
        errorResponse.put("path", request.getDescription(false).replace("uri=", ""));
        errorResponse.put("errorId", errorId);
        errorResponse.put("status", 403);
        errorResponse.put("suggestion", "Check your token scopes and permissions");
        
        return ResponseEntity.status(HttpStatus.FORBIDDEN).body(errorResponse);
    }

    @ExceptionHandler(NoHandlerFoundException.class)
    public ResponseEntity<Map<String, Object>> handleNoHandlerFoundException(
            NoHandlerFoundException ex, WebRequest request) {
        
        String errorId = UUID.randomUUID().toString();
        logger.warn("Endpoint not found [{}]: {} {}", errorId, ex.getHttpMethod(), ex.getRequestURL());
        
        Map<String, Object> errorResponse = new HashMap<>();
        errorResponse.put("error", "endpoint_not_found");
        errorResponse.put("message", "The requested endpoint does not exist");
        errorResponse.put("method", ex.getHttpMethod());
        errorResponse.put("path", ex.getRequestURL());
        errorResponse.put("timestamp", LocalDateTime.now());
        errorResponse.put("errorId", errorId);
        errorResponse.put("status", 404);
        errorResponse.put("availableEndpoints", Map.of(
            "public", "/public, /health",
            "protected", "/api/user, /api/verify, /api/client-info, /api/data, /api/profile, /api/protected"
        ));
        
        return ResponseEntity.status(HttpStatus.NOT_FOUND).body(errorResponse);
    }

    @ExceptionHandler(IllegalArgumentException.class)
    public ResponseEntity<Map<String, Object>> handleIllegalArgumentException(
            IllegalArgumentException ex, WebRequest request) {
        
        String errorId = UUID.randomUUID().toString();
        logger.error("Invalid argument [{}]: {}", errorId, ex.getMessage(), ex);
        
        Map<String, Object> errorResponse = new HashMap<>();
        errorResponse.put("error", "invalid_argument");
        errorResponse.put("message", "Invalid request parameter");
        errorResponse.put("details", ex.getMessage());
        errorResponse.put("timestamp", LocalDateTime.now());
        errorResponse.put("path", request.getDescription(false).replace("uri=", ""));
        errorResponse.put("errorId", errorId);
        errorResponse.put("status", 400);
        
        return ResponseEntity.status(HttpStatus.BAD_REQUEST).body(errorResponse);
    }

    @ExceptionHandler(Exception.class)
    public ResponseEntity<Map<String, Object>> handleGenericException(
            Exception ex, WebRequest request) {
        
        String errorId = UUID.randomUUID().toString();
        logger.error("Unexpected error [{}]: {}", errorId, ex.getMessage(), ex);
        
        Map<String, Object> errorResponse = new HashMap<>();
        errorResponse.put("error", "internal_server_error");
        errorResponse.put("message", "An unexpected error occurred");
        errorResponse.put("timestamp", LocalDateTime.now());
        errorResponse.put("path", request.getDescription(false).replace("uri=", ""));
        errorResponse.put("errorId", errorId);
        errorResponse.put("status", 500);
        errorResponse.put("support", "Please contact support with error ID: " + errorId);
        
        return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR).body(errorResponse);
    }
}