package com.ysrm.ms_security.Controllers;

import com.ysrm.ms_security.Services.UserRoleService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.util.List;
import java.util.Map;

@CrossOrigin
@RestController
@RequestMapping("/user-role")
public class UserRoleController {
    @Autowired
    private UserRoleService theUserRoleService;

    @PostMapping("user/{userId}/role/{roleId}")
    public ResponseEntity<Map<String, String>> addUserRole(
            @PathVariable String userId,
            @PathVariable String roleId) {

        boolean response = this.theUserRoleService.addUserRole(userId, roleId);
        if (response) {
            return ResponseEntity.ok(Map.of("message", "Success"));
        } else {
            return ResponseEntity
                    .status(HttpStatus.NOT_FOUND)
                    .body(Map.of("message", "User or Role not found"));
        }
    }

    @DeleteMapping("{userRoleId}")
    public ResponseEntity<Map<String, String>> removeUserRole(
            @PathVariable String userRoleId) {

        boolean response = this.theUserRoleService.removeUserRole(userRoleId);
        if (response) {
            return ResponseEntity.ok(Map.of("message", "Success"));
        } else {
            return ResponseEntity
                    .status(HttpStatus.NOT_FOUND)
                    .body(Map.of("message", "User or Role not found"));
        }
    }

    @PutMapping("user/{userId}")
    public ResponseEntity<Map<String, String>> setRolesForUser(
            @PathVariable String userId,
            @RequestBody Map<String, List<String>> body) {
        List<String> roleIds = body == null ? null : body.get("roleIds");
        boolean ok = this.theUserRoleService.setRolesForUser(userId, roleIds);
        return ok
                ? ResponseEntity.ok(Map.of("message", "Success"))
                : ResponseEntity.status(HttpStatus.NOT_FOUND).body(Map.of("message", "User not found"));
    }
}
