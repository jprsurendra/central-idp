package com.idp.controller;

import com.idp.entity.IdentityUser;
import com.idp.repository.IdentityUserRepository;
import com.idp.security.JwtService;
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

    @GetMapping(produces = MediaType.TEXT_HTML_VALUE)
    @ResponseBody
    public ResponseEntity<String> loginForm(@RequestParam String redirectUri,
                                            @RequestParam(required = false) String state) {
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

    @PostMapping
    public void handleLogin(@RequestParam String username,
                            @RequestParam String password,
                            @RequestParam String redirectUri,
                            @RequestParam(required = false) String state,
                            HttpServletResponse response) throws Exception {

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