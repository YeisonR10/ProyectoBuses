package com.ysrm.ms_security.Services;

import com.ysrm.ms_security.Models.Permissions.SystemAction;
import com.ysrm.ms_security.Models.Permissions.SystemModule;
import org.springframework.http.HttpMethod;
import org.springframework.stereotype.Service;

/**
 * Mapea endpoint + metodo HTTP a un permiso requerido.
 * Esto permite cumplir HU-ENTR-1-009 (validar permisos para URL/endpoint).
 *
 * Nota: aqui usamos un mapeo simple por prefijos. Si el sistema crece,
 * se puede reemplazar por anotaciones o por una tabla en BD.
 */
@Service
public class EndpointPermissionResolver {

    public RequiredPermission resolve(String path, String httpMethod) {
        if (path == null || httpMethod == null) {
            return null;
        }

        SystemAction action = mapAction(httpMethod);
        if (action == null) {
            return null;
        }

        // Seguridad: el interceptor excluye /security/** por config, pero mantenemos null aqui.
        if (path.startsWith("/security")) {
            return null;
        }

        // Roles y permisos
        if (path.startsWith("/roles/") && path.endsWith("/permissions")) {
            return new RequiredPermission(SystemModule.PERMISSIONS, SystemAction.UPDATE);
        }
        if (path.startsWith("/roles")) {
            return new RequiredPermission(SystemModule.ROLES, action);
        }
        if (path.startsWith("/user-role")) {
            return new RequiredPermission(SystemModule.ROLES, SystemAction.UPDATE);
        }

        // Usuarios
        if (path.startsWith("/users")) {
            return new RequiredPermission(SystemModule.USERS, action);
        }
        if (path.startsWith("/users-query")) {
            return new RequiredPermission(SystemModule.USERS, SystemAction.READ);
        }

        // Modulos del dominio (placeholders para otros servicios/endpoints)
        if (path.startsWith("/buses")) {
            return new RequiredPermission(SystemModule.BUSES, action);
        }
        if (path.startsWith("/routes") || path.startsWith("/rutas")) {
            return new RequiredPermission(SystemModule.ROUTES, action);
        }
        if (path.startsWith("/schedules") || path.startsWith("/programaciones")) {
            return new RequiredPermission(SystemModule.SCHEDULES, action);
        }
        if (path.startsWith("/reports") || path.startsWith("/reportes")) {
            return new RequiredPermission(SystemModule.REPORTS, action);
        }
        if (path.startsWith("/incidents") || path.startsWith("/incidentes")) {
            return new RequiredPermission(SystemModule.INCIDENTS, action);
        }
        if (path.startsWith("/messages") || path.startsWith("/mensajes")) {
            return new RequiredPermission(SystemModule.MASS_MESSAGING, action);
        }

        // Sin regla: no exigir permiso especifico
        return null;
    }

    private SystemAction mapAction(String httpMethod) {
        if (HttpMethod.GET.matches(httpMethod)) return SystemAction.READ;
        if (HttpMethod.POST.matches(httpMethod)) return SystemAction.CREATE;
        if (HttpMethod.PUT.matches(httpMethod) || HttpMethod.PATCH.matches(httpMethod)) return SystemAction.UPDATE;
        if (HttpMethod.DELETE.matches(httpMethod)) return SystemAction.DELETE;
        return null;
    }

    public record RequiredPermission(SystemModule module, SystemAction action) {
    }
}
