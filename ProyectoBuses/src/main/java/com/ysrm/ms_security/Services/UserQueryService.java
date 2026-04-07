package com.ysrm.ms_security.Services;

import com.ysrm.ms_security.Models.DTOs.UserWithRolesResponse;
import com.ysrm.ms_security.Models.Role;
import com.ysrm.ms_security.Models.User;
import com.ysrm.ms_security.Models.UserRole;
import com.ysrm.ms_security.Repositories.RoleRepository;
import com.ysrm.ms_security.Repositories.UserRepository;
import com.ysrm.ms_security.Repositories.UserRoleRepository;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

import java.util.*;

/**
 * Consultas para HU-ENTR-1-002: listar usuarios con roles y buscar por nombre/email.
 */
@Service
public class UserQueryService {

    @Autowired
    private UserRepository userRepository;

    @Autowired
    private UserRoleRepository userRoleRepository;

    @Autowired
    private RoleRepository roleRepository;

    public List<UserWithRolesResponse> listUsersWithRoles(String q) {
        List<User> users;
        if (q == null || q.isBlank()) {
            users = userRepository.findAll();
        } else {
            users = userRepository.searchByNameOrEmail(q);
        }

        if (users == null || users.isEmpty()) {
            return List.of();
        }

        List<UserWithRolesResponse> out = new ArrayList<>();
        for (User u : users) {
            if (u == null || u.get_id() == null) {
                continue;
            }
            List<UserRole> urs = userRoleRepository.findByUserId(u.get_id());
            Set<String> roleIds = new HashSet<>();
            if (urs != null) {
                for (UserRole ur : urs) {
                    if (ur != null && ur.getRole() != null && ur.getRole().getId() != null) {
                        roleIds.add(ur.getRole().getId());
                    }
                }
            }
            List<Role> roles = roleIds.stream()
                    .map(id -> roleRepository.findById(id).orElse(null))
                    .filter(Objects::nonNull)
                    .toList();

            out.add(UserWithRolesResponse.from(u, roles));
        }
        return out;
    }
}

