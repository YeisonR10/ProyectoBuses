package com.ysrm.ms_security.Services;


import com.ysrm.ms_security.Models.User;
import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jws;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import io.jsonwebtoken.io.Decoders;
import io.jsonwebtoken.security.Keys;
import io.jsonwebtoken.security.SignatureException;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;

import javax.crypto.SecretKey;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.util.Base64;
import java.util.Date;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
@Service
public class JwtService {
    @Value("${jwt.secret}")
    private String secret; // Esta es la clave secreta que se utiliza para firmar el token. Debe mantenerse segura.

    @Value("${jwt.expiration}")
    private Long expiration; // Tiempo de expiración del token en milisegundos.

    private SecretKey getSigningKey() {
        try {
            byte[] digest = MessageDigest.getInstance("SHA-256").digest(secret.getBytes(StandardCharsets.UTF_8));
            return Keys.hmacShaKeyFor(digest);
        } catch (Exception ex) {
            // Fallback para evitar caidas por formato de secreto
            String base64 = Base64.getEncoder().encodeToString(secret.getBytes(StandardCharsets.UTF_8));
            return Keys.hmacShaKeyFor(Decoders.BASE64.decode(base64));
        }
    }

    public String generateToken(User theUser) {
        return generateToken(theUser, List.of("USER"));
    }

    public String generateToken(User theUser, List<String> roles) {
        Date now = new Date();
        Date expiryDate = new Date(now.getTime() + expiration);
        Map<String, Object> claims = new HashMap<>();
        claims.put("id", theUser.get_id());
        claims.put("name", theUser.getName());
        claims.put("email", theUser.getEmail());
        claims.put("roles", roles);

        return Jwts.builder()
                .setClaims(claims)
                .setSubject(theUser.get_id())
                .setIssuedAt(now)
                .setExpiration(expiryDate)
                .signWith(getSigningKey(), SignatureAlgorithm.HS256)
                .compact();
    }
    public boolean validateToken(String token) {
        try {
            Jws<Claims> claimsJws = Jwts.parserBuilder()
                    .setSigningKey(getSigningKey())
                    .build()
                    .parseClaimsJws(token);

            // Verifica la expiración del token
            Date now = new Date();
            return !claimsJws.getBody().getExpiration().before(now);
        } catch (SignatureException ex) {
            // La firma del token es inválida
            return false;
        } catch (Exception e) {
            // Otra excepción
            return false;
        }
    }

    public Claims getClaims(String token) {
        try {
            return Jwts.parserBuilder()
                    .setSigningKey(getSigningKey())
                    .build()
                    .parseClaimsJws(token)
                    .getBody();
        } catch (Exception ex) {
            return null;
        }
    }

    public User getUserFromToken(String token) {
        Claims claims = getClaims(token);
        if (claims == null) {
            return null;
        }
        User user = new User();
        user.set_id((String) claims.get("id"));
        user.setName((String) claims.get("name"));
        user.setEmail((String) claims.get("email"));
        return user;
    }

    public List<String> getRolesFromToken(String token) {
        Claims claims = getClaims(token);
        if (claims == null || claims.get("roles") == null) {
            return List.of();
        }
        Object raw = claims.get("roles");
        if (raw instanceof List<?> list) {
            return list.stream().map(String::valueOf).toList();
        }
        return List.of();
    }
}
