package com.ysrm.ms_security.Models.DTOs;

import lombok.Data;

@Data
public class LoginRequest {
    private String email;
    private String password;
    private String recaptchaToken;
}
