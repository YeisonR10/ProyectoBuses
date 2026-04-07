package com.ysrm.ms_security.Services;

import com.ysrm.ms_security.Models.Role;
import com.ysrm.ms_security.Models.Permissions.PermissionGrant;
import com.ysrm.ms_security.Models.Permissions.SystemAction;
import com.ysrm.ms_security.Models.Permissions.SystemModule;
import com.ysrm.ms_security.Repositories.RoleRepository;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.ApplicationArguments;
import org.springframework.boot.ApplicationRunner;
import org.springframework.stereotype.Service;

import java.util.List;

/**
 * Crea roles predeterminados al iniciar la aplicacion si no existen.
 * Cumple HU-ENTR-1-001 (roles predeterminados).
 */
@Service
public class RoleBootstrapService implements ApplicationRunner {

    @Autowired
    private RoleRepository roleRepository;

    @Override
    public void run(ApplicationArguments args) {
        ensureRole("Administrador Sistema", "Acceso total del sistema", allPermissions());
        ensureRole("Administrador Empresa", "Gestion de empresa (buses/rutas/programaciones/reportes/incidentes/mensajes)", companyAdminPermissions());
        ensureRole("Supervisor", "Supervision y reportes", supervisorPermissions());
        ensureRole("Conductor", "Operacion de conduccion y reportes", driverPermissions());
        ensureRole("Ciudadano", "Acceso ciudadano (consulta y reportes basicos)", citizenPermissions());
    }

    private void ensureRole(String name, String description, List<PermissionGrant> permissions) {
        Role existing = roleRepository.findByName(name);
        if (existing != null) {
            return;
        }
        Role role = new Role(name, description, permissions);
        roleRepository.save(role);
    }

    private List<PermissionGrant> allPermissions() {
        return List.of(
                new PermissionGrant(SystemModule.USERS, List.of(SystemAction.READ, SystemAction.CREATE, SystemAction.UPDATE, SystemAction.DELETE)),
                new PermissionGrant(SystemModule.ROLES, List.of(SystemAction.READ, SystemAction.CREATE, SystemAction.UPDATE, SystemAction.DELETE)),
                new PermissionGrant(SystemModule.PERMISSIONS, List.of(SystemAction.READ, SystemAction.CREATE, SystemAction.UPDATE, SystemAction.DELETE)),
                new PermissionGrant(SystemModule.BUSES, List.of(SystemAction.READ, SystemAction.CREATE, SystemAction.UPDATE, SystemAction.DELETE)),
                new PermissionGrant(SystemModule.ROUTES, List.of(SystemAction.READ, SystemAction.CREATE, SystemAction.UPDATE, SystemAction.DELETE)),
                new PermissionGrant(SystemModule.SCHEDULES, List.of(SystemAction.READ, SystemAction.CREATE, SystemAction.UPDATE, SystemAction.DELETE)),
                new PermissionGrant(SystemModule.REPORTS, List.of(SystemAction.READ, SystemAction.CREATE, SystemAction.UPDATE, SystemAction.DELETE)),
                new PermissionGrant(SystemModule.INCIDENTS, List.of(SystemAction.READ, SystemAction.CREATE, SystemAction.UPDATE, SystemAction.DELETE)),
                new PermissionGrant(SystemModule.MASS_MESSAGING, List.of(SystemAction.READ, SystemAction.CREATE, SystemAction.UPDATE, SystemAction.DELETE))
        );
    }

    private List<PermissionGrant> companyAdminPermissions() {
        return List.of(
                new PermissionGrant(SystemModule.BUSES, List.of(SystemAction.READ, SystemAction.CREATE, SystemAction.UPDATE, SystemAction.DELETE)),
                new PermissionGrant(SystemModule.ROUTES, List.of(SystemAction.READ, SystemAction.CREATE, SystemAction.UPDATE, SystemAction.DELETE)),
                new PermissionGrant(SystemModule.SCHEDULES, List.of(SystemAction.READ, SystemAction.CREATE, SystemAction.UPDATE, SystemAction.DELETE)),
                new PermissionGrant(SystemModule.REPORTS, List.of(SystemAction.READ)),
                new PermissionGrant(SystemModule.INCIDENTS, List.of(SystemAction.READ, SystemAction.CREATE, SystemAction.UPDATE)),
                new PermissionGrant(SystemModule.MASS_MESSAGING, List.of(SystemAction.READ, SystemAction.CREATE))
        );
    }

    private List<PermissionGrant> supervisorPermissions() {
        return List.of(
                new PermissionGrant(SystemModule.REPORTS, List.of(SystemAction.READ)),
                new PermissionGrant(SystemModule.INCIDENTS, List.of(SystemAction.READ, SystemAction.UPDATE)),
                new PermissionGrant(SystemModule.BUSES, List.of(SystemAction.READ)),
                new PermissionGrant(SystemModule.ROUTES, List.of(SystemAction.READ)),
                new PermissionGrant(SystemModule.SCHEDULES, List.of(SystemAction.READ))
        );
    }

    private List<PermissionGrant> driverPermissions() {
        return List.of(
                new PermissionGrant(SystemModule.ROUTES, List.of(SystemAction.READ)),
                new PermissionGrant(SystemModule.SCHEDULES, List.of(SystemAction.READ)),
                new PermissionGrant(SystemModule.INCIDENTS, List.of(SystemAction.CREATE, SystemAction.READ))
        );
    }

    private List<PermissionGrant> citizenPermissions() {
        return List.of(
                new PermissionGrant(SystemModule.ROUTES, List.of(SystemAction.READ)),
                new PermissionGrant(SystemModule.SCHEDULES, List.of(SystemAction.READ)),
                new PermissionGrant(SystemModule.INCIDENTS, List.of(SystemAction.CREATE))
        );
    }
}

