package com.idp.security;

import io.jsonwebtoken.security.Keys;
import jakarta.annotation.PostConstruct;
import lombok.Getter;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;
import org.springframework.util.StringUtils;

import javax.crypto.SecretKey;
import java.nio.charset.StandardCharsets;
import java.util.HashMap;
import java.util.Map;
import java.util.Optional;

/**
 * Manages JWT signing keys with rotation support: new tokens are always
 * signed with the "current" key, but tokens signed with a recently-retired
 * "previous" key can still be validated until that key is cleared from
 * config. This allows JWT_CURRENT_KEY_SECRET to be rotated without
 * invalidating tokens that were issued moments before the rotation.
 *
 * See rotate-secrets.sh for the operational rotation procedure.
 */
@Slf4j
@Component
@RequiredArgsConstructor
public class JwtKeyProvider {

    @Value("${idp.jwt.current-key-id}")
    private String currentKeyId;

    @Value("${idp.jwt.current-key-secret}")
    private String currentKeySecret;

    @Value("${idp.jwt.previous-key-id:}")
    private String previousKeyId;

    @Value("${idp.jwt.previous-key-secret:}")
    private String previousKeySecret;

    @Getter
    private String currentKid;

    private final Map<String, SecretKey> keysByKid = new HashMap<>();

    @PostConstruct
    public void init() {
        if (!StringUtils.hasText(currentKeySecret) || currentKeySecret.length() < 32) {
            throw new IllegalStateException(
                    "idp.jwt.current-key-secret must be set and at least 32 characters — refusing to start with a weak or missing signing key.");
        }

        this.currentKid = currentKeyId;
        keysByKid.put(currentKeyId, toKey(currentKeySecret));
        log.info("JWT signing key loaded: kid={}", currentKeyId);

        if (StringUtils.hasText(previousKeyId) && StringUtils.hasText(previousKeySecret)) {
            keysByKid.put(previousKeyId, toKey(previousKeySecret));
            log.info("Previous JWT key still trusted for validation: kid={}", previousKeyId);
        }
    }

    public SecretKey getCurrentSigningKey() {
        return keysByKid.get(currentKid);
    }

    /** Looks up the key for a given "kid" header — used when validating an incoming token. */
    public Optional<SecretKey> getKeyForValidation(String kid) {
        return Optional.ofNullable(keysByKid.get(kid));
    }

    private SecretKey toKey(String secret) {
        return Keys.hmacShaKeyFor(secret.getBytes(StandardCharsets.UTF_8));
    }
}
