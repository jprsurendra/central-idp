package com.idp.repository;

import com.idp.entity.IdentityUser;
import org.springframework.data.jpa.repository.JpaRepository;

import java.util.Optional;

public interface IdentityUserRepository extends JpaRepository<IdentityUser, Long> {
    Optional<IdentityUser> findByUsernameAndActiveTrue(String username);
}
