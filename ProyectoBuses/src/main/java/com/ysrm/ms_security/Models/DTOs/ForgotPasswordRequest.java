package com.ysrm.ms_security.Models.DTOs;

import lombok.Data;

@Data
public class ForgotPasswordRequest {
    private String email;
    private String recaptchaToken;
}

