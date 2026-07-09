package com.idp.security;

import com.idp.entity.IdentityUser;
import io.jsonwebtoken.Claims;
import io.jsonwebtoken.JwsHeader;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.io.Decoders;
import lombok.RequiredArgsConstructor;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;

import java.util.Date;
import java.util.function.Function;

@Service
@RequiredArgsConstructor
public class JwtService {

    private final JwtKeyProvider keyProvider;

    @Value("${idp.jwt.expiration-ms}")
    private long expirationMs;

    @Value("${idp.jwt.issuer}")
    private String issuer;

    /** Issues a signed identity assertion for the given user. */
    public String generateToken(IdentityUser user, String audience) {
        Date now = new Date();
        Date expiry = new Date(now.getTime() + expirationMs);

        return Jwts.builder()
                .header().add("kid", keyProvider.getCurrentKid()).and()
                .subject(user.getExternalId())
                .claim("username", user.getUsername())
                .claim("email", user.getEmail())
                .claim("fullName", user.getFullName())
                .claim("department", user.getDepartment())
                .claim("role", user.getRole())
                .issuer(issuer)
                .audience().add(audience).and()
                .issuedAt(now)
                .expiration(expiry)
                .signWith(keyProvider.getCurrentSigningKey())
                .compact();
    }

    /** Validates a token, trying the current key and falling back to the previous key (rotation grace period). */
    public Claims validateAndParse(String token) {
        String kid = extractKid(token);

        var key = keyProvider.getKeyForValidation(kid)
                .orElseThrow(() -> new io.jsonwebtoken.security.SignatureException(
                        "Token signed with unknown or retired key id: " + kid));

        return Jwts.parser()
                .verifyWith(key)
                .build()
                .parseSignedClaims(token)
                .getPayload();
    }

    private String extractKid(String token) {
        // Read the header without verifying signature yet, purely to know which key to try.
        String[] parts = token.split("\\.");
        if (parts.length < 2) {
            throw new IllegalArgumentException("Malformed JWT");
        }
        String headerJson = new String(Decoders.BASE64URL.decode(parts[0]));
        // Minimal extraction — avoids pulling in a second JSON parser dependency.
        int kidIndex = headerJson.indexOf("\"kid\":\"");
        if (kidIndex == -1) {
            throw new IllegalArgumentException("Token has no kid header — cannot determine signing key");
        }
        int start = kidIndex + 7;
        int end = headerJson.indexOf("\"", start);
        return headerJson.substring(start, end);
    }
}
