package com.idp.config;

import io.swagger.v3.oas.models.OpenAPI;
import io.swagger.v3.oas.models.info.Contact;
import io.swagger.v3.oas.models.info.Info;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

/**
 * OpenAPI / Swagger UI configuration.
 *
 * Follows the ems-platform-wide Swagger convention (documented in
 * ems-docs/CONTRIBUTING.md): title format "EMS Platform — <Service> API",
 * version matches this service's own pom.xml version.
 *
 * No Bearer auth security scheme is defined here — none of central-idp's
 * own endpoints require a RajSahay JWT. /verify is protected by a
 * client-id/client-secret pair (documented per-endpoint via @Operation),
 * /authorize and /register are intentionally public.
 */
@Configuration
public class OpenApiConfig {

    @Bean
    public OpenAPI centralIdpOpenAPI() {
        return new OpenAPI()
                .info(new Info()
                        .title("EMS Platform — central-idp API")
                        .version("0.0.1")
                        .description(
                                "Standalone identity provider — PoC stand-in for an external " +
                                "centralized system. Exposes self-service registration, credential " +
                                "verification (Pattern B — client-authenticated), and portal-initiated " +
                                "login (Pattern A — browser redirect flow). See " +
                                "external-system-integration-design.md in ems-docs for the full design."
                        )
                        .contact(new Contact().name("EMS Platform")));
    }
}
