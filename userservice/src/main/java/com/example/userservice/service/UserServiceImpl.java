package com.example.userservice.service;

import com.example.userservice.domain.AppUser;
import com.example.userservice.domain.Role;
import com.example.userservice.repository.RoleRepository;
import com.example.userservice.repository.UserRepository;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

import javax.transaction.Transactional;
import java.util.List;
import java.util.stream.Collectors;

@Service
@Transactional
@Slf4j
public class UserServiceImpl implements UserService, UserDetailsService {

    @Autowired
    UserRepository userRepository;
    @Autowired
    RoleRepository roleRepository;

    @Autowired
    PasswordEncoder passwordEncoder;

    @Override
    public AppUser saveUser(AppUser user) {
        log.info("saving user");
        user.setPassword(passwordEncoder.encode(user.getPassword()));
        return userRepository.save(user);
    }

    @Override
    public Role saveRole(Role role) {
        log.info("saving Role");
        return roleRepository.save(role);
    }

    @Override
    public void addRoleToAppUser(String userName, String role) {
        log.info("Adding Role to user");
        AppUser user = userRepository.findByUsername(userName);
        Role roleObj = roleRepository.findByName(role);
        if (roleObj != null && user != null) {
            user.getRoles().add(roleObj);
        }
    }

    @Override
    public AppUser getUser(String username) {
        log.info("retriving user ");
        return userRepository.findByUsername(username);
    }

    @Override
    public List<AppUser> getAppUsers() {
        log.info("retriving Role");
        return userRepository.findAll();
    }

    @Override
    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
        AppUser appUser = userRepository.findByUsername(username);
        if (appUser != null) {
            List<GrantedAuthority> authorityList = appUser.getRoles().
                    stream().
                    map(role -> new SimpleGrantedAuthority(role.getName()))
                    .collect(Collectors.toList());
            return new User(username, appUser.getPassword(), authorityList);
        } else {
            return null;
        }

    }
}
