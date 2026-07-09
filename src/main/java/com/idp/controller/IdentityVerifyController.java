package com.idp.controller;

import com.idp.dto.VerifyRequest;
import com.idp.dto.VerifyResponse;
import com.idp.entity.IdentityUser;
import com.idp.repository.IdentityUserRepository;
import jakarta.servlet.http.HttpServletRequest;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

/**
 * Pattern B — App-Initiated Login. A registered client (e.g. ems-auth)
 * calls this endpoint with a user's credentials to verify them against
 * central-idp's own user store. This endpoint itself is protected by a
 * client-id/client-secret pair (service-to-service auth), not open to
 * end users directly — see integration-design.md Section 3
 * for why raw credential relay from an end user's browser is avoided.
 */
@Slf4j
@RestController
@RequestMapping("/api/v1/identity")
@RequiredArgsConstructor
public class IdentityVerifyController {

    private final IdentityUserRepository userRepository;
    private final PasswordEncoder passwordEncoder;

    @Value("${idp.clients.ems-auth.client-id}")
    private String registeredClientId;

    @Value("${idp.clients.ems-auth.client-secret}")
    private String registeredClientSecret;

    @PostMapping("/verify")
    public ResponseEntity<?> verify(@RequestBody VerifyRequest request, HttpServletRequest httpRequest) {
        String clientId = httpRequest.getHeader("X-Client-Id");
        String clientSecret = httpRequest.getHeader("X-Client-Secret");

        if (clientId == null || clientSecret == null
                || !registeredClientId.equals(clientId)
                || !registeredClientSecret.equals(clientSecret)) {
            log.warn("Rejected /verify call from unregistered or missing client credentials");
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED)
                    .body("Unrecognized calling client");
        }

        return userRepository.findByUsernameAndActiveTrue(request.getUsername())
                .filter(user -> passwordEncoder.matches(request.getPassword(), user.getPasswordHash()))
                .<ResponseEntity<?>>map(user -> ResponseEntity.ok(toResponse(user)))
                .orElseGet(() -> {
                    log.info("Failed credential verification for username={}", request.getUsername());
                    return ResponseEntity.status(HttpStatus.UNAUTHORIZED).body("Invalid credentials");
                });
    }

    private VerifyResponse toResponse(IdentityUser user) {
        return new VerifyResponse(user.getExternalId(), user.getUsername(), user.getFullName(), user.getEmail(), user.getDepartment(), user.getRole());
    }
}
