package com.ysrm.ms_security.Services;

import com.ysrm.ms_security.Models.Role;
import com.ysrm.ms_security.Models.DTOs.RolePermissionsRequest;
import com.ysrm.ms_security.Repositories.RoleRepository;
import com.ysrm.ms_security.Repositories.UserRoleRepository;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

import java.util.List;

@Service
public class RoleService {

    @Autowired
    private RoleRepository theRoleRepository;

    @Autowired
    private UserRoleRepository theUserRoleRepository;

    @Autowired
    private EmailService emailService;

    public List<Role> find(){
        return this.theRoleRepository.findAll();
    }

    public Role findById(String id){
        return this.theRoleRepository.findById(id).orElse(null);
    }

    public Role create(Role newRole){
        return this.theRoleRepository.save(newRole);
    }

    public Role update(String id, Role newRole){
        Role actualRole = this.theRoleRepository.findById(id).orElse(null);

        if(actualRole != null){
            actualRole.setName(newRole.getName());
            actualRole.setDescription(newRole.getDescription());
            // Si viene permissions en el payload, se actualiza (edicion completa).
            if (newRole.getPermissions() != null) {
                actualRole.setPermissions(newRole.getPermissions());
            }
            this.theRoleRepository.save(actualRole);

            if (newRole.getPermissions() != null && actualRole.getId() != null) {
                this.theUserRoleRepository.findByRoleId(actualRole.getId()).stream()
                        .filter(ur -> ur.getUser() != null && ur.getUser().getEmail() != null)
                        .forEach(ur -> emailService.sendPermissionsChanged(ur.getUser().getEmail(), actualRole.getName()));
            }
            return actualRole;
        } else {
            return null;
        }
    }

    public Role updatePermissions(String id, RolePermissionsRequest request) {
        Role actualRole = this.theRoleRepository.findById(id).orElse(null);
        if (actualRole == null) {
            return null;
        }
        actualRole.setPermissions(request == null ? null : request.getPermissions());
        this.theRoleRepository.save(actualRole);

        // Notificar a usuarios con este rol (best-effort). Esto cumple HU-ENTR-1-002.
        if (actualRole.getId() != null) {
            this.theUserRoleRepository.findByRoleId(actualRole.getId()).stream()
                    .filter(ur -> ur.getUser() != null && ur.getUser().getEmail() != null)
                    .forEach(ur -> emailService.sendPermissionsChanged(ur.getUser().getEmail(), actualRole.getName()));
        }
        return actualRole;
    }

    public boolean delete(String id){
        Role theRole = this.theRoleRepository.findById(id).orElse(null);
        if(theRole == null){
            return false;
        }

        // HU-ENTR-1-001: al eliminar, validar que no haya usuarios asignados.
        if (!this.theUserRoleRepository.findByRoleId(id).isEmpty()) {
            throw new IllegalStateException("No se puede eliminar el rol porque hay usuarios asignados");
        }

        this.theRoleRepository.delete(theRole);
        return true;
    }
}
