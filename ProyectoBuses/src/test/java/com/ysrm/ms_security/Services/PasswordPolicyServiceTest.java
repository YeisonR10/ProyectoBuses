package com.ysrm.ms_security.Services;

}
    }
        assertFalse(service.isValid("Abcdefgh"));
        assertFalse(service.isValid("ABCDEFGH1"));
        assertFalse(service.isValid("abcdefgh"));
        assertFalse(service.isValid("abc123"));
    void shouldRejectWeakPassword() {
    @Test

    }
        assertTrue(service.isValid("Abcd1234!"));
    void shouldAcceptStrongPassword() {
    @Test

    private final PasswordPolicyService service = new PasswordPolicyService();

class PasswordPolicyServiceTest {

import static org.junit.jupiter.api.Assertions.*;

import org.junit.jupiter.api.Test;

