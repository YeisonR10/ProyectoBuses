package com.ysrm.ms_security.Controllers;

import com.ysrm.ms_security.Models.Role;
import com.ysrm.ms_security.Models.DTOs.RolePermissionsRequest;
import com.ysrm.ms_security.Services.RoleService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.util.List;
import java.util.Map;

@CrossOrigin
@RestController
@RequestMapping("/roles")
public class RoleController {

    @Autowired
    private RoleService theRoleService;

    @GetMapping("")
    public List<Role> find() {
        return this.theRoleService.find();
    }

    @GetMapping("{id}")
    public Role findById(@PathVariable String id) {
        return this.theRoleService.findById(id);
    }

    @PostMapping
    public Role create(@RequestBody Role newRole) {
        return this.theRoleService.create(newRole);
    }

    @PutMapping("{id}")
    public Role update(@PathVariable String id, @RequestBody Role newRole) {
        return this.theRoleService.update(id, newRole);
    }

    @PutMapping("{id}/permissions")
    public ResponseEntity<?> updatePermissions(@PathVariable String id, @RequestBody RolePermissionsRequest request) {
        Role updated = this.theRoleService.updatePermissions(id, request);
        return updated == null
                ? ResponseEntity.status(HttpStatus.NOT_FOUND).body(Map.of("error", "Rol no encontrado"))
                : ResponseEntity.ok(updated);
    }

    @DeleteMapping("{id}")
    public ResponseEntity<?> delete(@PathVariable String id) {
        try {
            boolean deleted = this.theRoleService.delete(id);
            return deleted
                    ? ResponseEntity.ok(Map.of("message", "Rol eliminado"))
                    : ResponseEntity.status(HttpStatus.NOT_FOUND).body(Map.of("error", "Rol no encontrado"));
        } catch (IllegalStateException ex) {
            return ResponseEntity.status(HttpStatus.CONFLICT).body(Map.of("error", ex.getMessage()));
        }
    }
}
