package com.oauth2.resource.service;

import org.springframework.stereotype.Service;
import java.util.*;

@Service
public class MockDataService {

    private static final List<Map<String, Object>> MOCK_USERS = Arrays.asList(
        Map.of(
            "id", 1,
            "username", "user",
            "email", "user@example.com",
            "firstName", "Test",
            "lastName", "User",
            "department", "Engineering",
            "role", "Developer",
            "joinDate", "2023-01-15",
            "lastLogin", "2025-07-06T09:30:00Z",
            "isActive", true
        ),
        Map.of(
            "id", 2,
            "username", "admin",
            "email", "admin@example.com",
            "firstName", "Admin",
            "lastName", "User",
            "department", "IT",
            "role", "Administrator",
            "joinDate", "2022-05-10",
            "lastLogin", "2025-07-06T08:45:00Z",
            "isActive", true
        )
    );

    private static final List<Map<String, Object>> MOCK_DASHBOARD_DATA = Arrays.asList(
        Map.of(
            "widget", "user_stats",
            "title", "Active Users",
            "value", 1247,
            "change", "+5.2%",
            "period", "last 24h"
        ),
        Map.of(
            "widget", "revenue",
            "title", "Monthly Revenue",
            "value", "$45,231",
            "change", "+12.3%",
            "period", "this month"
        ),
        Map.of(
            "widget", "orders",
            "title", "New Orders",
            "value", 89,
            "change", "-2.1%",
            "period", "today"
        ),
        Map.of(
            "widget", "satisfaction",
            "title", "Customer Satisfaction",
            "value", "94.5%",
            "change", "+1.8%",
            "period", "this week"
        )
    );

    private static final List<Map<String, Object>> MOCK_PROTECTED_DATA = Arrays.asList(
        Map.of(
            "id", "doc_001",
            "title", "Q4 Financial Report",
            "type", "financial",
            "classification", "confidential",
            "owner", "finance@company.com",
            "lastModified", "2025-01-15T14:30:00Z",
            "size", "2.4MB"
        ),
        Map.of(
            "id", "doc_002", 
            "title", "Security Audit Results",
            "type", "security",
            "classification", "restricted",
            "owner", "security@company.com",
            "lastModified", "2025-01-10T09:15:00Z",
            "size", "1.8MB"
        ),
        Map.of(
            "id", "doc_003",
            "title", "Employee Database Backup",
            "type", "database",
            "classification", "highly-confidential",
            "owner", "it@company.com",
            "lastModified", "2025-01-05T22:00:00Z",
            "size", "145MB"
        )
    );

    public Map<String, Object> getDashboardData() {
        Map<String, Object> response = new HashMap<>();
        response.put("widgets", MOCK_DASHBOARD_DATA);
        response.put("totalUsers", 1247);
        response.put("systemStatus", "operational");
        response.put("lastUpdated", new Date());
        response.put("version", "1.0.0");
        return response;
    }

    public Map<String, Object> getUserProfile(String username) {
        Map<String, Object> user = MOCK_USERS.stream()
            .filter(u -> username.equals(u.get("username")))
            .findFirst()
            .orElse(MOCK_USERS.get(0)); // Default to first user
        
        Map<String, Object> profile = new HashMap<>(user);
        profile.put("preferences", Map.of(
            "theme", "dark",
            "language", "en",
            "notifications", true,
            "timezone", "UTC+6"
        ));
        profile.put("permissions", Arrays.asList("read", "write", "profile"));
        profile.put("lastAccessed", new Date());
        
        return profile;
    }

    public List<Map<String, Object>> getProtectedDocuments() {
        return new ArrayList<>(MOCK_PROTECTED_DATA);
    }

    public Map<String, Object> getSystemStats() {
        return Map.of(
            "uptime", "15 days, 8 hours",
            "memoryUsage", "67%",
            "cpuUsage", "23%",
            "diskSpace", "45% used",
            "activeConnections", 892,
            "requestsPerMinute", 1250,
            "averageResponseTime", "127ms",
            "lastBackup", "2025-07-06T02:00:00Z"
        );
    }
}