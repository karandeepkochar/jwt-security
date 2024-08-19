package com.bizztalk.auth.jwt_security.controller;

import com.bizztalk.auth.jwt_security.entity.Role;
import com.bizztalk.auth.jwt_security.entity.User;
import com.bizztalk.auth.jwt_security.service.RoleService;
import lombok.RequiredArgsConstructor;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.*;

@RestController
@RequestMapping("/api/v1/modify-role")
@RequiredArgsConstructor
public class RoleModificationController {

    private final RoleService roleService;

    @PreAuthorize("hasRole('ROLE_ADMIN')")
    @PutMapping("/to-admin/{id}")
    public ResponseEntity<User> modifyRoleToAdmin(@PathVariable Integer id){
        User user = roleService.updateRole(id, Role.ADMIN);
        return ResponseEntity.ok(user);
    }

    @PreAuthorize("hasRole('ROLE_ADMIN')")
    @PutMapping("/to-user/{id}")
    public ResponseEntity<User> modifyRoleToUser(@PathVariable Integer id){
        User user = roleService.updateRole(id, Role.USER);
        return ResponseEntity.ok(user);
    }
}
