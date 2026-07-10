package com.idp.controller;

import com.idp.entity.IdentityUser;
import com.idp.repository.IdentityUserRepository;
import com.idp.security.JwtService;
import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.Parameter;
import io.swagger.v3.oas.annotations.responses.ApiResponse;
import io.swagger.v3.oas.annotations.responses.ApiResponses;
import io.swagger.v3.oas.annotations.tags.Tag;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.util.HtmlUtils;
import org.springframework.web.util.UriComponentsBuilder;

import java.net.URI;
import java.util.Arrays;
import java.util.List;

/**
 * Pattern A — Portal-Initiated Access. Represents the "existing system's"
 * own login page: a user lands here (typically via a link from within
 * central-idp, simulating an external system's home page), logs in
 * with central-idp's own credentials, and is redirected back to the
 * calling application (redirectUri) with a signed identity assertion.
 *
 * See integration-design.md Section 2, Pattern A for the
 * full sequence diagram this implements.
 *
 * Note for Swagger/API consumers: these two endpoints are NOT typical
 * JSON APIs — GET serves an HTML login form, POST performs a 302
 * redirect. They're documented here for completeness and so the flow is
 * visible in one place, but "Try it out" in Swagger UI won't behave like
 * a normal JSON request/response — use a real browser to exercise this
 * flow (see central-idp's README "Trying it out" section).
 *
 * Security notes:
 * - redirectUri and state are attacker-controlled query parameters and
 *   are HTML-escaped before being embedded in the login page, to prevent
 *   reflected XSS.
 * - redirectUri is validated against a configured allowlist before any
 *   token is issued or redirected to, to prevent open-redirect /
 *   token-exfiltration attacks (an attacker sending a victim a link with
 *   their own redirectUri to capture the issued token).
 */
@Slf4j
@Controller
@RequestMapping("/api/v1/identity/authorize")
@RequiredArgsConstructor
@Tag(name = "Portal Login (Pattern A)", description = "Browser-based, portal-initiated login — serves an HTML form and performs a redirect, not typical JSON endpoints")
public class IdentityAuthorizeController {

    private final IdentityUserRepository userRepository;
    private final PasswordEncoder passwordEncoder;
    private final JwtService jwtService;

    @Value("${idp.allowed-redirect-uris}")
    private String allowedRedirectUrisRaw;

    private List<String> allowedRedirectUris() {
        return Arrays.stream(allowedRedirectUrisRaw.split(","))
                .map(String::strip)
                .filter(s -> !s.isEmpty())
                .toList();
    }

    private boolean isAllowedRedirect(String redirectUri) {
        return allowedRedirectUris().stream().anyMatch(redirectUri::startsWith);
    }

    @Operation(
            summary = "Serve the portal login page (HTML, not JSON)",
            description = "Returns an HTML login form. redirectUri must exactly match (by prefix) " +
                    "an entry in the server-side allowlist (idp.allowed-redirect-uris) — an " +
                    "untrusted redirectUri is rejected here, before any credentials are even " +
                    "collected, to prevent token exfiltration to an attacker-controlled destination."
    )
    @ApiResponses({
            @ApiResponse(responseCode = "200", description = "Login form HTML"),
            @ApiResponse(responseCode = "400", description = "redirectUri is not in the configured allowlist, or is missing")
    })
    @GetMapping(produces = MediaType.TEXT_HTML_VALUE)
    @ResponseBody
    public ResponseEntity<String> loginForm(
            @Parameter(description = "Must match an entry in idp.allowed-redirect-uris") @RequestParam String redirectUri,
            @Parameter(description = "Opaque value round-tripped back to the caller, unmodified") @RequestParam(required = false) String state) {
        if (!isAllowedRedirect(redirectUri)) {
            log.warn("Rejected /authorize request — redirectUri not in allowlist: {}", redirectUri);
            return ResponseEntity.badRequest()
                    .body(HtmlUtils.htmlEscape("Error: redirectUri is not a registered, trusted destination."));
        }

        // Both values come from the query string — an attacker fully
        // controls them. HTML-escape before embedding in the page to
        // prevent reflected XSS (e.g. redirectUri="><script>...).
        String safeRedirectUri = HtmlUtils.htmlEscape(redirectUri);
        String safeState = HtmlUtils.htmlEscape(state == null ? "" : state);

        String html = """
                <!DOCTYPE html>
                <html>
                <head><title>central-idp — Sign in</title></head>
                <body style="font-family: sans-serif; max-width: 360px; margin: 80px auto;">
                    <h2>central-idp</h2>
                    <p style="color:#666;">Sign in to continue to the requesting application.</p>
                    <form method="POST" action="/api/v1/identity/authorize">
                        <input type="hidden" name="redirectUri" value="%s"/>
                        <input type="hidden" name="state" value="%s"/>
                        <div style="margin-bottom:12px;">
                            <label>Username</label><br/>
                            <input type="text" name="username" style="width:100%%;padding:8px;" required/>
                        </div>
                        <div style="margin-bottom:12px;">
                            <label>Password</label><br/>
                            <input type="password" name="password" style="width:100%%;padding:8px;" required/>
                        </div>
                        <button type="submit" style="padding:8px 16px;">Sign in</button>
                    </form>
                </body>
                </html>
                """.formatted(safeRedirectUri, safeState);

        return ResponseEntity.ok(html);
    }

    @Operation(
            summary = "Submit login credentials, receive a redirect with a signed token",
            description = "On success, performs a 302 redirect to redirectUri with a signed " +
                    "assertion token appended as a query parameter — this is the response a " +
                    "browser would follow automatically; it is not a JSON response. On failure, " +
                    "returns 400 or 401 with no redirect and no token issued."
    )
    @ApiResponses({
            @ApiResponse(responseCode = "302", description = "Redirect to redirectUri?token=...&state=..."),
            @ApiResponse(responseCode = "400", description = "redirectUri is not in the configured allowlist"),
            @ApiResponse(responseCode = "401", description = "Invalid username or password")
    })
    @PostMapping
    public void handleLogin(@RequestParam String username,
                             @RequestParam String password,
                             @RequestParam String redirectUri,
                             @RequestParam(required = false) String state,
                             @Parameter(hidden = true) HttpServletResponse response) throws Exception {

        if (!isAllowedRedirect(redirectUri)) {
            log.warn("Rejected /authorize POST — redirectUri not in allowlist: {}", redirectUri);
            response.sendError(HttpStatus.BAD_REQUEST.value(), "redirectUri is not a registered, trusted destination");
            return;
        }

        var userOpt = userRepository.findByUsernameAndActiveTrue(username)
                .filter(u -> passwordEncoder.matches(password, u.getPasswordHash()));

        if (userOpt.isEmpty()) {
            log.info("Failed portal login attempt for username={}", username);
            response.sendError(HttpStatus.UNAUTHORIZED.value(), "Invalid credentials");
            return;
        }

        IdentityUser user = userOpt.get();
        String token = jwtService.generateToken(user, redirectUri);

        URI redirect = UriComponentsBuilder.fromUriString(redirectUri)
                .queryParam("token", token)
                .queryParamIfPresent("state", java.util.Optional.ofNullable(state))
                .build(true)
                .toUri();

        // sendRedirect() commits the response immediately, which is what
        // signals to Spring MVC that this void-returning handler has
        // already fully handled the request — manually setting status/
        // headers without committing can leave Spring attempting to
        // resolve a default view for the request path instead.
        response.sendRedirect(redirect.toString());
    }
}
