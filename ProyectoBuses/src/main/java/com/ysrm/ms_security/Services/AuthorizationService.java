package com.ysrm.ms_security.Services;

import com.ysrm.ms_security.Models.Permissions.PermissionGrant;
import com.ysrm.ms_security.Models.Permissions.SystemAction;
import com.ysrm.ms_security.Models.Permissions.SystemModule;
import com.ysrm.ms_security.Models.Role;
import com.ysrm.ms_security.Models.UserRole;
import com.ysrm.ms_security.Repositories.RoleRepository;
import com.ysrm.ms_security.Repositories.UserRoleRepository;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

import java.util.HashSet;
import java.util.List;
import java.util.Objects;
import java.util.Set;

/**
 * Resuelve permisos efectivos del usuario (union de permisos de todos sus roles).
 * Se consulta en BD en cada request protegido para que cambios de permisos/roles
 * apliquen inmediatamente (HU-ENTR-1-001).
 */
@Service
public class AuthorizationService {

    @Autowired
    private UserRoleRepository userRoleRepository;

    @Autowired
    private RoleRepository roleRepository;

    public boolean hasPermission(String userId, SystemModule module, SystemAction action) {
        if (userId == null || module == null || action == null) {
            return false;
        }

        List<UserRole> userRoles = userRoleRepository.findByUserId(userId);
        if (userRoles == null || userRoles.isEmpty()) {
            return false;
        }

        Set<String> roleIds = new HashSet<>();
        for (UserRole ur : userRoles) {
            if (ur != null && ur.getRole() != null && ur.getRole().getId() != null) {
                roleIds.add(ur.getRole().getId());
            }
        }

        for (String roleId : roleIds) {
            Role role = roleRepository.findById(roleId).orElse(null);
            if (role == null || role.getPermissions() == null) {
                continue;
            }
            for (PermissionGrant grant : role.getPermissions()) {
                if (grant == null || grant.getModule() == null || grant.getActions() == null) {
                    continue;
                }
                if (Objects.equals(grant.getModule(), module) && grant.getActions().contains(action)) {
                    return true;
                }
            }
        }

        return false;
    }
}

