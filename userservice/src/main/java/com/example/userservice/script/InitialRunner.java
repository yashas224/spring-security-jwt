package com.example.userservice.script;

import com.example.userservice.domain.AppUser;
import com.example.userservice.domain.Role;
import com.example.userservice.service.UserService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.CommandLineRunner;
import org.springframework.stereotype.Component;

import java.util.ArrayList;

@Component
public class InitialRunner implements CommandLineRunner {

    @Autowired
    UserService userService;

    @Override
    public void run(String... args) throws Exception {
        userService.saveRole(new Role(null, "ROLE_USER"));
        userService.saveRole(new Role(null, "ROLE_MANAGER"));
        userService.saveRole(new Role(null, "ROLE_ADMIN"));
        userService.saveRole(new Role(null, "ROLE_SUPER_ADMIN"));

        userService.saveUser(new AppUser(null, "yashas Samaga", "yashas", "samaga", new ArrayList<>()));
        userService.saveUser(new AppUser(null, "krishna Samaga", "krishna", "samaga", new ArrayList<>()));
        userService.saveUser(new AppUser(null, "malathi Samaga", "malathi", "samaga", new ArrayList<>()));
        userService.saveUser(new AppUser(null, "jim Smith", "jim", "jim", null));


        userService.addRoleToAppUser("yashas", "ROLE_USER");
        userService.addRoleToAppUser("krishna", "ROLE_MANAGER");
        userService.addRoleToAppUser("jim", "ROLE_ADMIN");
        userService.addRoleToAppUser("malathi", "ROLE_SUPER_ADMIN");
        userService.addRoleToAppUser("malathi", "ROLE_ADMIN");
        userService.addRoleToAppUser("malathi", "ROLE_USER");
    }
}
