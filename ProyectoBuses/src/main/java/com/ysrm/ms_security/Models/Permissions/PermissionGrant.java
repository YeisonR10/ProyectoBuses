package com.ysrm.ms_security.Models.Permissions;

import lombok.Data;

import java.util.ArrayList;
import java.util.List;

/**
 * Permisos por modulo, con una lista de acciones permitidas.
 * Se almacena embebido dentro de Role (documento Mongo).
 */
@Data
public class PermissionGrant {
    private SystemModule module;
    private List<SystemAction> actions = new ArrayList<>();

    public PermissionGrant() {
    }

    public PermissionGrant(SystemModule module, List<SystemAction> actions) {
        this.module = module;
        if (actions != null) {
            this.actions = actions;
        }
    }
}

