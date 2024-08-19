package com.bizztalk.auth.jwt_security.service;

import com.bizztalk.auth.jwt_security.entity.Role;
import com.bizztalk.auth.jwt_security.entity.User;
import com.bizztalk.auth.jwt_security.repository.UserRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Service;

@Service
@RequiredArgsConstructor
public class RoleService {

    private final UserRepository userRepository;

    public User updateRole(Integer id, Role role) {
        User user = userRepository.findById(id).orElseThrow();
        if (user.getRole() != role) {
            user.setRole(role);
            userRepository.save(user);
        }
        return user;
    }
}
