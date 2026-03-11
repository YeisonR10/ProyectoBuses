package com.ysrm.ms_security.Services;

import com.ysrm.ms_security.Models.User;
import org.junit.jupiter.api.Test;
import org.springframework.test.util.ReflectionTestUtils;

import java.util.List;

import static org.junit.jupiter.api.Assertions.*;

class JwtServiceTest {

    @Test
    void shouldGenerateAndValidateToken() {
        JwtService service = new JwtService();
        ReflectionTestUtils.setField(service, "secret", "test-secret-key-123456789");
        ReflectionTestUtils.setField(service, "expiration", 3600000L);

        User user = new User();
        user.set_id("u1");
        user.setName("Ana");
        user.setEmail("ana@test.com");

        String token = service.generateToken(user, List.of("ADMIN"));

        assertNotNull(token);
        assertTrue(service.validateToken(token));
        assertEquals("u1", service.getUserFromToken(token).get_id());
        assertTrue(service.getRolesFromToken(token).contains("ADMIN"));
    }
}

