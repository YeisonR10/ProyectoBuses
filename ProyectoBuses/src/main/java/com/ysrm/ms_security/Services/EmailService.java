package com.ysrm.ms_security.Services;

import org.springframework.stereotype.Service;

@Service
public class EmailService {

    public void sendAccountCreated(String email, String fullName) {
    }

    public void sendTwoFactorCode(String email, String code) {
    }

    public void sendPasswordReset(String email, String resetUrl) {
    }
}
