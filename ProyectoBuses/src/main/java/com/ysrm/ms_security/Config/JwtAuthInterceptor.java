package com.ysrm.ms_security.Config;

import com.ysrm.ms_security.Repositories.SessionRepository;
import com.ysrm.ms_security.Services.JwtService;
import com.ysrm.ms_security.Services.AuthorizationService;
import com.ysrm.ms_security.Services.EndpointPermissionResolver;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Component;
import org.springframework.web.servlet.HandlerInterceptor;

import java.util.Date;

@Component
public class JwtAuthInterceptor implements HandlerInterceptor {

    @Autowired
    private JwtService jwtService;

    @Autowired
    private AuthorizationService authorizationService;

    @Autowired
    private EndpointPermissionResolver endpointPermissionResolver;

    @Autowired
    private SessionRepository sessionRepository;

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

        // HU-ENTR-1-009: valida existencia del token de sesion en BD (revocable) y expiracion.
        var session = sessionRepository.getByToken(token);
        if (session == null || Boolean.TRUE.equals(session.getPartialAuth())) {
            response.sendError(HttpServletResponse.SC_UNAUTHORIZED, "Sesion expirada o invalida");
            return false;
        }
        if (session.getExpiration() != null && session.getExpiration().before(new Date())) {
            response.sendError(HttpServletResponse.SC_UNAUTHORIZED, "Sesion expirada o invalida");
            return false;
        }

        var tokenUser = jwtService.getUserFromToken(token);
        String userId = tokenUser == null ? null : tokenUser.get_id();
        if (userId == null || userId.isBlank()) {
            response.sendError(HttpServletResponse.SC_UNAUTHORIZED, "Sesion expirada o invalida");
            return false;
        }

        String path = request.getRequestURI();
        String method = request.getMethod();
        EndpointPermissionResolver.RequiredPermission required = endpointPermissionResolver.resolve(path, method);
        if (required != null) {
            boolean allowed = authorizationService.hasPermission(userId, required.module(), required.action());
            if (!allowed) {
                response.sendError(HttpServletResponse.SC_FORBIDDEN, "Acceso denegado");
                return false;
            }
        }

        return true;
    }
}

