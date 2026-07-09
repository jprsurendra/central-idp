package com.centralidp.controller;

import com.idp.entity.IdentityUser;
import com.idp.repository.IdentityUserRepository;
import com.idp.security.JwtService;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.util.UriComponentsBuilder;

import java.net.URI;

/**
 * Pattern A — Portal-Initiated Access. Represents the "existing system's"
 * own login page: a user lands here (typically via a link from within
 * central-idp, simulating an external system's home page), logs in
 * with central-idp's own credentials, and is redirected back to the
 * calling application (redirectUri) with a signed identity assertion.
 *
 * See integration-design.md Section 2, Pattern A for the
 * full sequence diagram this implements.
 */
@Slf4j
@Controller
@RequestMapping("/api/v1/identity/authorize")
@RequiredArgsConstructor
public class IdentityAuthorizeController {

    private final IdentityUserRepository userRepository;
    private final PasswordEncoder passwordEncoder;
    private final JwtService jwtService;

    @GetMapping(produces = MediaType.TEXT_HTML_VALUE)
    @ResponseBody
    public String loginForm(@RequestParam String redirectUri,
                             @RequestParam(required = false) String state) {
        return """
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
                """.formatted(redirectUri, state == null ? "" : state);
    }

    @PostMapping
    public void handleLogin(@RequestParam String username,
                             @RequestParam String password,
                             @RequestParam String redirectUri,
                             @RequestParam(required = false) String state,
                             HttpServletResponse response) throws Exception {

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
