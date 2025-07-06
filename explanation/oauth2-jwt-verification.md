# OAuth2 JWT Token Verification Flow

## Overview
The code snippet you mentioned configures a Spring Boot OAuth2 Resource Server to validate JWT tokens using JSON Web Key Set (JWKS) from an Authorization Server.

```java
oauth2 -> oauth2
    .jwt(jwt -> jwt
        .jwkSetUri("http://localhost:9000/oauth2/jwks")
    )
```

## What This Configuration Does

### 1. OAuth2 Resource Server Setup
- Configures the application as an **OAuth2 Resource Server**
- A resource server protects resources and validates access tokens
- It does NOT issue tokens (that's the Authorization Server's job)

### 2. JWT Token Validation
- Specifies that incoming tokens are **JWT (JSON Web Tokens)**
- JWT tokens are self-contained and can be verified without calling the Authorization Server for each request

### 3. JWKS Endpoint Configuration
- Points to the **JSON Web Key Set (JWKS)** endpoint at `http://localhost:9000/oauth2/jwks`
- JWKS contains the public keys used to verify JWT signatures

## Token Verification Flow

### Step 1: Client Request
```
Client Request → Resource Server
Authorization: Bearer eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9...
```

### Step 2: Token Extraction
The Resource Server extracts the JWT token from the `Authorization` header.

### Step 3: Token Structure Analysis
JWT tokens have three parts separated by dots:
```
header.payload.signature
```

**Header Example:**
```json
{
  "alg": "RS256",
  "typ": "JWT",
  "kid": "key-id-123"
}
```

**Payload Example:**
```json
{
  "sub": "user123",
  "aud": "resource-server",
  "iss": "http://localhost:9000",
  "exp": 1625097600,
  "iat": 1625094000,
  "scope": "read write"
}
```

### Step 4: JWKS Retrieval
The Resource Server fetches the JWKS from the Authorization Server:

```http
GET http://localhost:9000/oauth2/jwks
```

**JWKS Response:**
```json
{
  "keys": [
    {
      "kty": "RSA",
      "kid": "key-id-123",
      "use": "sig",
      "n": "0vx7agoebGcQSuuPiLJXZptN9...",
      "e": "AQAB"
    }
  ]
}
```

### Step 5: Key Selection
- Resource Server finds the correct public key using the `kid` (Key ID) from the JWT header
- Matches it with the corresponding key in the JWKS response

### Step 6: Signature Verification
- Uses the public key to verify the JWT signature
- Ensures the token was signed by the trusted Authorization Server
- Confirms the token hasn't been tampered with

### Step 7: Claims Validation
The Resource Server validates standard JWT claims:

- **iss (Issuer)**: Must match the trusted Authorization Server
- **aud (Audience)**: Must include this Resource Server
- **exp (Expiration)**: Token must not be expired
- **iat (Issued At)**: Token must not be used before it was issued
- **nbf (Not Before)**: Token must not be used before this time (if present)

### Step 8: Authorization Decision
If all validations pass:
- ✅ Request is allowed to proceed
- User information is extracted from JWT claims
- Scopes are checked against required permissions

If validation fails:
- ❌ Request is rejected with 401 Unauthorized

## Security Benefits

### 1. No Database Calls
- JWT tokens are self-contained
- No need to query a database for each request
- Improves performance and scalability

### 2. Stateless Authentication
- Resource Server doesn't need to maintain session state
- Each request is independently validated

### 3. Cryptographic Security
- Digital signatures ensure token integrity
- Only the Authorization Server can create valid tokens
- Tampering attempts are detected

### 4. Distributed Architecture
- Multiple Resource Servers can validate tokens independently
- No single point of failure for token validation

## Common JWT Claims

| Claim | Description | Example |
|-------|-------------|---------|
| `sub` | Subject (user identifier) | `"user123"` |
| `iss` | Issuer (Authorization Server) | `"http://localhost:9000"` |
| `aud` | Audience (Resource Server) | `"my-api"` |
| `exp` | Expiration time | `1625097600` |
| `iat` | Issued at time | `1625094000` |
| `scope` | Granted permissions | `"read write"` |

## Error Scenarios

### Invalid Signature
```json
{
  "error": "invalid_token",
  "error_description": "JWT signature validation failed"
}
```

### Expired Token
```json
{
  "error": "invalid_token",
  "error_description": "JWT token has expired"
}
```

### Wrong Audience
```json
{
  "error": "invalid_token",
  "error_description": "JWT audience validation failed"
}
```

## Configuration Options

### Custom JWT Decoder
```java
@Bean
public JwtDecoder jwtDecoder() {
    NimbusJwtDecoder jwtDecoder = NimbusJwtDecoder
        .withJwkSetUri("http://localhost:9000/oauth2/jwks")
        .build();
    
    jwtDecoder.setJwtValidator(jwtValidator());
    return jwtDecoder;
}
```

### Custom Claims Validation
```java
@Bean
public Jwt1Validator<Jwt> jwtValidator() {
    List<OAuth2TokenValidator<Jwt>> validators = new ArrayList<>();
    validators.add(new JwtTimestampValidator());
    validators.add(new JwtIssuerValidator("http://localhost:9000"));
    validators.add(new JwtAudienceValidator("my-resource-server"));
    
    return new DelegatingOAuth2TokenValidator<>(validators);
}
```

## Best Practices

1. **Always Validate Claims**: Don't just verify the signature
2. **Use HTTPS**: Protect JWKS endpoint communication
3. **Handle Key Rotation**: Cache JWKS but refresh periodically
4. **Monitor Token Usage**: Log authentication attempts
5. **Implement Rate Limiting**: Prevent brute force attacks

## Summary

The configuration `oauth2.jwt(jwt -> jwt.jwkSetUri("http://localhost:9000/oauth2/jwks"))` creates a secure, scalable token validation system that:

- Verifies JWT token signatures using public keys from the Authorization Server
- Validates token claims to ensure authenticity and authorization
- Provides stateless authentication without database dependencies
- Enables distributed resource protection across multiple services