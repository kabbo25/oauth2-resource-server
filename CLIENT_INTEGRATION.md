# Resource Server Client Integration Guide

## Overview
This resource server provides JWT token validation and API endpoints for both React and Spring Boot clients.

## Available Endpoints

### Public Endpoints (No Authentication Required)
- `GET /public` - Public test endpoint
- `GET /health` - Basic health check
- `GET /actuator/health` - Detailed health status
- `GET /actuator/info` - Application information

### Protected Endpoints (JWT Required)
- `GET /api/user` - User information (any valid JWT)
- `GET /api/verify` - Token verification details (any valid JWT)
- `GET /api/client-info` - Client identification (any valid JWT)
- `GET /api/data` - Dashboard data (any valid JWT)
- `GET /api/profile` - User profile (requires `profile` scope)
- `GET /api/protected` - Protected documents (requires `read` scope)
- `GET /api/admin` - Admin features (requires `admin` scope)

## React Client Integration

### 1. Update authService.js

```javascript
// Add resource server base URL
const RESOURCE_SERVER_URL = 'http://localhost:9001';

// Add methods to call resource server
export const callResourceServer = async (endpoint) => {
  const token = localStorage.getItem('accessToken');
  if (!token) {
    throw new Error('No access token available');
  }

  const response = await fetch(`${RESOURCE_SERVER_URL}${endpoint}`, {
    method: 'GET',
    headers: {
      'Authorization': `Bearer ${token}`,
      'Content-Type': 'application/json',
      'Origin': 'http://localhost:3000'
    }
  });

  if (!response.ok) {
    const error = await response.json();
    throw new Error(error.message || 'API call failed');
  }

  return response.json();
};

export const getDashboardData = () => callResourceServer('/api/data');
export const getUserProfile = () => callResourceServer('/api/profile');
export const getProtectedData = () => callResourceServer('/api/protected');
export const verifyToken = () => callResourceServer('/api/verify');
```

### 2. Update Dashboard Component

```jsx
import { getDashboardData, getUserProfile, getProtectedData } from '../services/authService';

function Dashboard() {
  const [dashboardData, setDashboardData] = useState(null);
  const [profile, setProfile] = useState(null);
  const [error, setError] = useState(null);

  useEffect(() => {
    const fetchData = async () => {
      try {
        const [dashboard, userProfile] = await Promise.all([
          getDashboardData(),
          getUserProfile()
        ]);
        setDashboardData(dashboard);
        setProfile(userProfile);
      } catch (err) {
        setError(err.message);
      }
    };

    fetchData();
  }, []);

  if (error) return <div>Error: {error}</div>;
  if (!dashboardData) return <div>Loading...</div>;

  return (
    <div>
      <h2>Dashboard</h2>
      <div>
        <h3>User Profile</h3>
        <p>Name: {profile?.firstName} {profile?.lastName}</p>
        <p>Email: {profile?.email}</p>
      </div>
      <div>
        <h3>Dashboard Widgets</h3>
        {dashboardData.widgets?.map(widget => (
          <div key={widget.widget}>
            <h4>{widget.title}</h4>
            <p>{widget.value} ({widget.change})</p>
          </div>
        ))}
      </div>
    </div>
  );
}
```

## Spring Boot Client Integration

### 1. Update ClientController.java

```java
@RestController
public class ClientController {

    private final RestTemplate restTemplate;
    private static final String RESOURCE_SERVER_URL = "http://localhost:9001";

    @Autowired
    public ClientController(RestTemplate restTemplate) {
        this.restTemplate = restTemplate;
    }

    @GetMapping("/dashboard")
    public String dashboard(HttpSession session, Model model) {
        String accessToken = (String) session.getAttribute("access_token");
        
        if (accessToken == null) {
            return "redirect:/";
        }

        try {
            // Call resource server endpoints
            Map<String, Object> dashboardData = callResourceServer("/api/data", accessToken);
            Map<String, Object> profile = callResourceServer("/api/profile", accessToken);
            
            model.addAttribute("dashboardData", dashboardData);
            model.addAttribute("profile", profile);
            model.addAttribute("message", "Data loaded from Resource Server");
            
            return "dashboard";
        } catch (Exception e) {
            model.addAttribute("error", "Failed to load data: " + e.getMessage());
            return "error";
        }
    }

    @GetMapping("/protected-data")
    public ResponseEntity<?> getProtectedData(HttpSession session) {
        String accessToken = (String) session.getAttribute("access_token");
        
        if (accessToken == null) {
            return ResponseEntity.status(401).body("No access token");
        }

        try {
            Map<String, Object> data = callResourceServer("/api/protected", accessToken);
            return ResponseEntity.ok(data);
        } catch (Exception e) {
            return ResponseEntity.status(403).body("Access denied: " + e.getMessage());
        }
    }

    private Map<String, Object> callResourceServer(String endpoint, String accessToken) {
        HttpHeaders headers = new HttpHeaders();
        headers.setBearerAuth(accessToken);
        headers.set("Origin", "http://localhost:8080");
        
        HttpEntity<String> entity = new HttpEntity<>(headers);
        
        ResponseEntity<Map> response = restTemplate.exchange(
            RESOURCE_SERVER_URL + endpoint,
            HttpMethod.GET,
            entity,
            Map.class
        );
        
        return response.getBody();
    }
}
```

### 2. Create dashboard.html template

```html
<!DOCTYPE html>
<html xmlns:th="http://www.thymeleaf.org">
<head>
    <title>Dashboard - Resource Server Data</title>
    <style>
        .widget { border: 1px solid #ccc; margin: 10px; padding: 15px; }
        .error { color: red; }
        .success { color: green; }
    </style>
</head>
<body>
    <h1>Dashboard</h1>
    
    <div th:if="${error}" class="error">
        <p th:text="${error}"></p>
    </div>
    
    <div th:if="${message}" class="success">
        <p th:text="${message}"></p>
    </div>
    
    <div th:if="${profile}">
        <h2>User Profile</h2>
        <p>Name: <span th:text="${profile.firstName}"></span> <span th:text="${profile.lastName}"></span></p>
        <p>Email: <span th:text="${profile.email}"></span></p>
        <p>Department: <span th:text="${profile.department}"></span></p>
    </div>
    
    <div th:if="${dashboardData}">
        <h2>Dashboard Widgets</h2>
        <div th:each="widget : ${dashboardData.widgets}" class="widget">
            <h3 th:text="${widget.title}"></h3>
            <p>Value: <span th:text="${widget.value}"></span></p>
            <p>Change: <span th:text="${widget.change}"></span></p>
            <p>Period: <span th:text="${widget.period}"></span></p>
        </div>
    </div>
    
    <div>
        <a href="/protected-data">View Protected Data</a> | 
        <a href="/logout">Logout</a>
    </div>
</body>
</html>
```

## Testing Instructions

### 1. Start All Services
```bash
# Terminal 1: Authorization Server
cd symmetric-jwt-token && ./mvnw spring-boot:run

# Terminal 2: Resource Server  
cd oauth2-resource-server && ./mvnw spring-boot:run

# Terminal 3: Spring Client
cd oauth2-spring-client && ./mvnw spring-boot:run

# Terminal 4: React Client
cd oauth2-react-client && npm run dev
```

### 2. Test Resource Server Health
```bash
curl http://localhost:9001/actuator/health
curl http://localhost:9001/public
```

### 3. End-to-End Testing

1. **Login via React Client**:
   - Go to http://localhost:3000
   - Login with user/password
   - Navigate to dashboard
   - Verify data loads from resource server

2. **Login via Spring Client**:
   - Go to http://localhost:8080
   - Login with user/password
   - Navigate to dashboard
   - Verify data loads from resource server

3. **Direct API Testing**:
   ```bash
   # Get token from either client first, then:
   curl -H "Authorization: Bearer YOUR_TOKEN" http://localhost:9001/api/data
   curl -H "Authorization: Bearer YOUR_TOKEN" http://localhost:9001/api/profile
   curl -H "Authorization: Bearer YOUR_TOKEN" http://localhost:9001/api/protected
   ```

## Error Handling

The resource server provides detailed error responses with:
- Error ID for tracking
- Timestamp
- Request path
- Suggested solutions
- HTTP status codes

## Monitoring

Available monitoring endpoints:
- `/actuator/health` - Health status
- `/actuator/info` - Application info  
- `/actuator/metrics` - Performance metrics
- Request logging with correlation IDs

## Security Features

- JWT token validation
- Scope-based access control
- CORS configuration for cross-origin requests
- Structured logging with user context
- Global exception handling
- Request/response tracking