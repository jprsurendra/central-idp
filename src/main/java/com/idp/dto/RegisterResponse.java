package com.idp.dto;

public class RegisterResponse {
    private String externalId;
    private String username;
    private String fullName;
    private String email;
    private String role;

    public RegisterResponse(String externalId, String username, String fullName, String email, String role) {
        this.externalId = externalId;
        this.username = username;
        this.fullName = fullName;
        this.email = email;
        this.role = role;
    }

    public String getExternalId() { return externalId; }
    public String getUsername() { return username; }
    public String getFullName() { return fullName; }
    public String getEmail() { return email; }
    public String getRole() { return role; }
}
