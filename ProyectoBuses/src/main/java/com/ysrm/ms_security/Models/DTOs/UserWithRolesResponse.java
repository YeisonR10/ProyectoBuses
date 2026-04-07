package com.ysrm.ms_security.Models.DTOs;

import com.ysrm.ms_security.Models.Role;
import com.ysrm.ms_security.Models.User;
import lombok.Data;

import java.util.ArrayList;
import java.util.List;

@Data
public class UserWithRolesResponse {
    private String id;
    private String name;
    private String lastName;
    private String email;
    private List<Role> roles = new ArrayList<>();

    public static UserWithRolesResponse from(User user, List<Role> roles) {
        UserWithRolesResponse r = new UserWithRolesResponse();
        r.setId(user == null ? null : user.get_id());
        r.setName(user == null ? null : user.getName());
        r.setLastName(user == null ? null : user.getLastName());
        r.setEmail(user == null ? null : user.getEmail());
        if (roles != null) {
            r.setRoles(roles);
        }
        return r;
    }
}

