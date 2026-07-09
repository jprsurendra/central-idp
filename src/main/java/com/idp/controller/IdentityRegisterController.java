package com.idp.controller;

import com.idp.dto.RegisterRequest;
import com.idp.dto.RegisterResponse;
import com.idp.entity.IdentityUser;
import com.idp.repository.IdentityUserRepository;
import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

/**
 * Public, self-service registration on central-idp — this is the "existing
 * centralized system's" own user registration, independent of ems-auth.
 * A new user here gets a durable externalId, which ems-auth links its own
 * local profile record to (see AuthController's SSO registration proxy and
 * integration-design.md).
 *
 * Role is deliberately NOT client-settable — every self-registered user
 * gets the default CITIZEN role, preventing privilege escalation via
 * self-registration. Role changes are an administrative action, not
 * something exposed on this endpoint.
 */
@Slf4j
@RestController
@RequestMapping("/api/v1/identity")
@RequiredArgsConstructor
public class IdentityRegisterController {

    private final IdentityUserRepository userRepository;
    private final PasswordEncoder passwordEncoder;

    private static final String DEFAULT_ROLE = "CITIZEN";

    @PostMapping("/register")
    public ResponseEntity<?> register(@Valid @RequestBody RegisterRequest request) {
        if (userRepository.findByUsernameAndActiveTrue(request.getUsername()).isPresent()) {
            return ResponseEntity.status(HttpStatus.CONFLICT)
                    .body("Username already exists");
        }

        IdentityUser user = new IdentityUser();
        user.setUsername(request.getUsername());
        user.setPasswordHash(passwordEncoder.encode(request.getPassword()));
        user.setFullName(request.getFullName());
        user.setEmail(request.getEmail());
        user.setDepartment(request.getDepartment());
        user.setRole(DEFAULT_ROLE);
        user.setActive(true);

        userRepository.save(user);
        log.info("New identity registered: username={} externalId={}", user.getUsername(), user.getExternalId());

        return ResponseEntity.status(HttpStatus.CREATED).body(
                new RegisterResponse(user.getExternalId(), user.getUsername(), user.getFullName(), user.getEmail(), user.getRole()));
    }
}
