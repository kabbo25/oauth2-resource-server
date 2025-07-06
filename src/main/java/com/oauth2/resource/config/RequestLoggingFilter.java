package com.oauth2.resource.config;

import jakarta.servlet.*;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.slf4j.MDC;
import org.springframework.stereotype.Component;

import java.io.IOException;
import java.util.UUID;

@Component
public class RequestLoggingFilter implements Filter {

    private static final Logger logger = LoggerFactory.getLogger(RequestLoggingFilter.class);
    private static final String REQUEST_ID_HEADER = "X-Request-ID";
    private static final String MDC_REQUEST_ID = "requestId";
    private static final String MDC_USER_ID = "userId";
    private static final String MDC_CLIENT_ID = "clientId";

    @Override
    public void doFilter(ServletRequest request, ServletResponse response, FilterChain chain)
            throws IOException, ServletException {

        HttpServletRequest httpRequest = (HttpServletRequest) request;
        HttpServletResponse httpResponse = (HttpServletResponse) response;

        // Generate or extract request ID
        String requestId = httpRequest.getHeader(REQUEST_ID_HEADER);
        if (requestId == null || requestId.trim().isEmpty()) {
            requestId = UUID.randomUUID().toString();
        }

        // Add request ID to MDC for structured logging
        MDC.put(MDC_REQUEST_ID, requestId);
        
        // Add request ID to response headers
        httpResponse.setHeader(REQUEST_ID_HEADER, requestId);

        long startTime = System.currentTimeMillis();
        
        try {
            logger.info("REQUEST_START: {} {} from {}", 
                httpRequest.getMethod(), 
                httpRequest.getRequestURI(), 
                getClientIpAddress(httpRequest));
            
            logger.debug("Request Headers: User-Agent={}, Authorization={}, Origin={}", 
                httpRequest.getHeader("User-Agent"),
                httpRequest.getHeader("Authorization") != null ? "Bearer ***" : "none",
                httpRequest.getHeader("Origin"));

            chain.doFilter(request, response);

        } finally {
            long duration = System.currentTimeMillis() - startTime;
            
            logger.info("REQUEST_END: {} {} -> {} in {}ms", 
                httpRequest.getMethod(), 
                httpRequest.getRequestURI(), 
                httpResponse.getStatus(),
                duration);

            // Performance monitoring
            if (duration > 1000) {
                logger.warn("SLOW_REQUEST: {} {} took {}ms", 
                    httpRequest.getMethod(), 
                    httpRequest.getRequestURI(), 
                    duration);
            }

            // Clear MDC
            MDC.clear();
        }
    }

    private String getClientIpAddress(HttpServletRequest request) {
        String xForwardedFor = request.getHeader("X-Forwarded-For");
        if (xForwardedFor != null && !xForwardedFor.isEmpty()) {
            return xForwardedFor.split(",")[0].trim();
        }
        
        String xRealIp = request.getHeader("X-Real-IP");
        if (xRealIp != null && !xRealIp.isEmpty()) {
            return xRealIp;
        }
        
        return request.getRemoteAddr();
    }

    public static void setUserContext(String userId, String clientId) {
        if (userId != null) {
            MDC.put(MDC_USER_ID, userId);
        }
        if (clientId != null) {
            MDC.put(MDC_CLIENT_ID, clientId);
        }
    }
}