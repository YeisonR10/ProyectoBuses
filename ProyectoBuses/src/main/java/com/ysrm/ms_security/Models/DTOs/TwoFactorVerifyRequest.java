package com.ysrm.ms_security.Models.DTOs;

import lombok.Data;

@Data
public class TwoFactorVerifyRequest {
    private String sessionId;
    private String code;
}

