package com.idp.controller;

import com.idp.dto.RegisterRequest;
import com.idp.dto.RegisterResponse;
import com.idp.entity.IdentityUser;
import com.idp.repository.IdentityUserRepository;
import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.media.Content;
import io.swagger.v3.oas.annotations.media.Schema;
import io.swagger.v3.oas.annotations.responses.ApiResponse;
import io.swagger.v3.oas.annotations.responses.ApiResponses;
import io.swagger.v3.oas.annotations.tags.Tag;
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
@Tag(name = "Registration", description = "Self-service identity registration — the platform's sole registration authority")
public class IdentityRegisterController {

    private final IdentityUserRepository userRepository;
    private final PasswordEncoder passwordEncoder;

    private static final String DEFAULT_ROLE = "CITIZEN";

    @Operation(
            summary = "Register a new identity",
            description = "Creates a new identity on central-idp and returns a durable externalId. " +
                    "This is the platform's sole registration authority — every account on " +
                    "ems-auth, whether created directly here or via ems-auth's /register/sso " +
                    "proxy, originates from this endpoint. Role is always CITIZEN regardless of " +
                    "request content; there is no way to self-assign an elevated role."
    )
    @ApiResponses({
            @ApiResponse(responseCode = "201", description = "Identity created successfully",
                    content = @Content(schema = @Schema(implementation = RegisterResponse.class))),
            @ApiResponse(responseCode = "400", description = "Validation failed (short password, invalid email, missing fields)"),
            @ApiResponse(responseCode = "409", description = "Username already exists")
    })
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
