package com.idp.entity;

import jakarta.persistence.*;
import lombok.Getter;
import lombok.Setter;

import java.time.LocalDateTime;
import java.util.UUID;

// No @Data on this JPA entity, consistent with the platform convention
// this PoC follows — see ems-platform's CONTRIBUTING.md.
@Getter
@Setter
@Entity
@Table(name = "identity_users")
public class IdentityUser {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    // The durable identifier exposed to any consumer (e.g. ems-auth).
    // Never expose the internal auto-increment 'id' above externally —
    // it's an implementation detail, not a contract.
    @Column(name = "external_id", nullable = false, unique = true, length = 36)
    private String externalId;

    @Column(nullable = false, unique = true, length = 100)
    private String username;

    @Column(name = "password_hash", nullable = false)
    private String passwordHash;

    @Column(name = "full_name", nullable = false)
    private String fullName;

    @Column(nullable = false, unique = true, length = 150)
    private String email;

    @Column(length = 100)
    private String department;

    @Column(nullable = false, length = 50)
    private String role = "CITIZEN";

    @Column(nullable = false)
    private Boolean active = true;

    @Column(name = "created_at", nullable = false, updatable = false)
    private LocalDateTime createdAt;

    @PrePersist
    protected void onCreate() {
        this.createdAt = LocalDateTime.now();
        if (this.externalId == null) {
            this.externalId = UUID.randomUUID().toString();
        }
    }
}
