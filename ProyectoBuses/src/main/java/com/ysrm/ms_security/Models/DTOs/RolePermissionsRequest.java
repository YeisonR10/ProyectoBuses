package com.ysrm.ms_security.Models.DTOs;

import com.ysrm.ms_security.Models.Permissions.PermissionGrant;
import lombok.Data;

import java.util.ArrayList;
import java.util.List;

@Data
public class RolePermissionsRequest {
    private List<PermissionGrant> permissions = new ArrayList<>();
}

