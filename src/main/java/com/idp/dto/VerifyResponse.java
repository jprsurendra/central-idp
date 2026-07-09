package com.idp.dto;

public class VerifyResponse {
    private String username;
    private String fullName;
    private String department;
    private String role;

    public VerifyResponse(String username, String fullName, String department, String role) {
        this.username = username;
        this.fullName = fullName;
        this.department = department;
        this.role = role;
    }

    public String getUsername() { return username; }
    public String getFullName() { return fullName; }
    public String getDepartment() { return department; }
    public String getRole() { return role; }
}
