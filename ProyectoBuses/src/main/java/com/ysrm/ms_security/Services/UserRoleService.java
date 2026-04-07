package com.ysrm.ms_security.Services;

import com.ysrm.ms_security.Models.Role;
import com.ysrm.ms_security.Models.User;
import com.ysrm.ms_security.Models.UserRole;
import com.ysrm.ms_security.Repositories.RoleRepository;
import com.ysrm.ms_security.Repositories.UserRepository;
import com.ysrm.ms_security.Repositories.UserRoleRepository;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

import java.util.List;
import java.util.Objects;

@Service
public class UserRoleService {
    @Autowired
    private UserRepository theUserRepository;

    @Autowired
    private RoleRepository theRoleRepository;

    @Autowired
    private UserRoleRepository theUserRoleRepository;

    @Autowired
    private EmailService emailService;

    public boolean addUserRole(String userId,
                               String roleId){
        User user=this.theUserRepository.findById(userId).orElse(null);
        Role role=this.theRoleRepository.findById(roleId).orElse(null);
        if (user!=null && role!=null){
            // Evita duplicados (mismo usuario + mismo rol).
            UserRole existing = this.theUserRoleRepository.findByUserIdAndRoleId(userId, roleId);
            if (existing != null) {
                return true;
            }
            UserRole theUserRole= new UserRole(user,role);
            this.theUserRoleRepository.save(theUserRole);
            emailService.sendRolesChanged(user.getEmail(), "Se asigno el rol: " + role.getName());
            return true;
        }else{
            return false;
        }
    }

    public boolean removeUserRole(String userRoleId) {
        UserRole userRole = this.theUserRoleRepository.findById(userRoleId).orElse(null);
        if (userRole != null) {
            if (userRole.getUser() != null && userRole.getUser().getEmail() != null && userRole.getRole() != null) {
                emailService.sendRolesChanged(userRole.getUser().getEmail(), "Se removio el rol: " + userRole.getRole().getName());
            }
            this.theUserRoleRepository.delete(userRole);
            return true;
        } else {
            return false;
        }
    }

    /**
     * Reemplaza los roles de un usuario (asignacion multiple en una sola operacion).
     * Los permisos se acumulan por rol, y este cambio aplica inmediatamente porque la autorizacion se evalua contra BD.
     */
    public boolean setRolesForUser(String userId, List<String> roleIds) {
        User user = this.theUserRepository.findById(userId).orElse(null);
        if (user == null) {
            return false;
        }

        List<UserRole> current = this.theUserRoleRepository.findByUserId(userId);
        // Elimina los que ya no estan
        if (current != null) {
            for (UserRole ur : current) {
                String rid = ur.getRole() == null ? null : ur.getRole().getId();
                if (rid != null && (roleIds == null || roleIds.stream().noneMatch(r -> Objects.equals(r, rid)))) {
                    this.theUserRoleRepository.delete(ur);
                }
            }
        }

        // Agrega los nuevos
        if (roleIds != null) {
            for (String roleId : roleIds) {
                Role role = this.theRoleRepository.findById(roleId).orElse(null);
                if (role == null) {
                    continue;
                }
                UserRole existing = this.theUserRoleRepository.findByUserIdAndRoleId(userId, roleId);
                if (existing == null) {
                    this.theUserRoleRepository.save(new UserRole(user, role));
                }
            }
        }

        emailService.sendRolesChanged(user.getEmail(), "Sus roles/permisos fueron actualizados");
        return true;
    }
}
