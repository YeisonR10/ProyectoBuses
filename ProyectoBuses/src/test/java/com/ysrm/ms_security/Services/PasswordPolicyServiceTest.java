package com.ysrm.ms_security.Services;

import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

class PasswordPolicyServiceTest {

    private final PasswordPolicyService service = new PasswordPolicyService();

    @Test
    void shouldAcceptStrongPassword() {
        assertTrue(service.isValid("Abcd1234!"));
    }

    @Test
    void shouldRejectWeakPassword() {
        assertFalse(service.isValid("Abcdefgh"));   // sin digito ni especial
        assertFalse(service.isValid("ABCDEFGH1"));  // sin minuscula ni especial
        assertFalse(service.isValid("abcdefgh"));   // sin mayuscula, digito, especial
        assertFalse(service.isValid("abc123"));     // < 8
    }
}

