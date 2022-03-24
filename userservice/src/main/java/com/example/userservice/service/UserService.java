package com.example.userservice.service;

import com.example.userservice.domain.AppUser;
import com.example.userservice.domain.Role;

import java.util.List;

public interface UserService {

    AppUser saveUser(AppUser user);

    Role saveRole(Role role);

    void addRoleToAppUser(String userName, String role);

    AppUser getUser(String username);

    List<AppUser> getAppUsers();
}
