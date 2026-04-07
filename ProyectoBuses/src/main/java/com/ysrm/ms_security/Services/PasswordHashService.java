package com.ysrm.ms_security.Services;

import com.ysrm.ms_security.Models.User;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.stereotype.Service;

import java.util.Locale;

/**
 * Maneja hashing/validacion de contrasenas con BCrypt.
 * Mantiene compatibilidad con contrasenas antiguas SHA-256 (migracion en login).
 */
@Service
public class PasswordHashService {

    private final BCryptPasswordEncoder bcrypt;
    private final EncryptionService encryptionService;

    public PasswordHashService(
            EncryptionService encryptionService,
            @Value("${security.password.bcrypt-strength:10}") int strength) {
        this.encryptionService = encryptionService;
        this.bcrypt = new BCryptPasswordEncoder(Math.max(4, strength));
    }

    public String hashNew(String rawPassword) {
        return bcrypt.encode(rawPassword);
    }

    public boolean matches(String rawPassword, String storedHash) {
        if (rawPassword == null || storedHash == null) {
            return false;
        }
        if (isBcryptHash(storedHash)) {
            return bcrypt.matches(rawPassword, storedHash);
        }
        if (looksLikeSha256Hex(storedHash)) {
            String sha = encryptionService.convertSHA256(rawPassword);
            return sha != null && sha.equalsIgnoreCase(storedHash);
        }
        return false;
    }

    /**
     * Si el usuario tiene password legacy SHA-256 y el password coincide,
     * se migra a BCrypt y se devuelve true.
     */
    public boolean verifyAndUpgradeIfNeeded(User user, String rawPassword) {
        if (user == null) {
            return false;
        }
        String stored = user.getPassword();
        if (!matches(rawPassword, stored)) {
            return false;
        }
        if (stored != null && looksLikeSha256Hex(stored)) {
            user.setPassword(hashNew(rawPassword));
            return true;
        }
        return true;
    }

    private boolean isBcryptHash(String storedHash) {
        return storedHash.startsWith("$2a$") || storedHash.startsWith("$2b$") || storedHash.startsWith("$2y$");
    }

    private boolean looksLikeSha256Hex(String storedHash) {
        if (storedHash.length() != 64) {
            return false;
        }
        String s = storedHash.toLowerCase(Locale.ROOT);
        for (int i = 0; i < s.length(); i++) {
            char c = s.charAt(i);
            boolean hex = (c >= '0' && c <= '9') || (c >= 'a' && c <= 'f');
            if (!hex) {
                return false;
            }
        }
        return true;
    }
}

