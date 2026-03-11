package com.ysrm.ms_security.Config;

import com.ysrm.ms_security.Services.JwtService;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Component;
import org.springframework.web.servlet.HandlerInterceptor;

import java.util.List;

@Component
public class JwtAuthInterceptor implements HandlerInterceptor {

    @Autowired
    private JwtService jwtService;

    @Override
    public boolean preHandle(HttpServletRequest request, HttpServletResponse response, Object handler) throws Exception {
        String authHeader = request.getHeader("Authorization");

        if (authHeader == null || !authHeader.startsWith("Bearer ")) {
            response.sendError(HttpServletResponse.SC_UNAUTHORIZED, "Sesion expirada o invalida");
            return false;
        }

        String token = authHeader.substring(7);
        if (!jwtService.validateToken(token)) {
            response.sendError(HttpServletResponse.SC_UNAUTHORIZED, "Sesion expirada o invalida");
            return false;
        }

        String path = request.getRequestURI();
        List<String> roles = jwtService.getRolesFromToken(token);
        boolean isAdminPath = path.startsWith("/admin") || path.startsWith("/roles") || path.startsWith("/user-role");

        if (isAdminPath && roles.stream().noneMatch(role -> "ADMIN".equalsIgnoreCase(role))) {
            response.sendError(HttpServletResponse.SC_FORBIDDEN, "Acceso denegado");
            return false;
        }

        return true;
    }
}

