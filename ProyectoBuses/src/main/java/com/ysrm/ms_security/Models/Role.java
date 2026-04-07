package com.ysrm.ms_security.Models;

import com.ysrm.ms_security.Models.Permissions.PermissionGrant;
import lombok.Data;
import org.springframework.data.annotation.Id;
import org.springframework.data.mongodb.core.mapping.Document;

import java.util.ArrayList;
import java.util.List;

@Data
@Document
public class Role {
    @Id
    private String id;
    private String name;
    private String description;

    /**
     * Permisos granulares por modulo/accion para este rol.
     * Se evalua en tiempo real (contra BD) en cada request protegido.
     */
    private List<PermissionGrant> permissions = new ArrayList<>();

    public Role(){

    }

    public Role(String name, String description) {
        this.name = name;
        this.description = description;
    }

    public Role(String name, String description, List<PermissionGrant> permissions) {
        this.name = name;
        this.description = description;
        if (permissions != null) {
            this.permissions = permissions;
        }
    }
}
