package com.ysrm.ms_security.Controllers;

import com.ysrm.ms_security.Models.DTOs.UserWithRolesResponse;
import com.ysrm.ms_security.Services.UserQueryService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.web.bind.annotation.*;

import java.util.List;

@CrossOrigin
@RestController
@RequestMapping("/users-query")
public class UserQueryController {

    @Autowired
    private UserQueryService userQueryService;

    @GetMapping("")
    public List<UserWithRolesResponse> listUsersWithRoles(@RequestParam(required = false) String q) {
        return userQueryService.listUsersWithRoles(q);
    }
}

