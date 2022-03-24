package com.example.userservice.api;


import com.auth0.jwt.JWT;
import com.auth0.jwt.algorithms.Algorithm;
import com.auth0.jwt.exceptions.JWTVerificationException;
import com.auth0.jwt.interfaces.DecodedJWT;
import com.auth0.jwt.interfaces.JWTVerifier;
import com.example.userservice.domain.AppUser;
import com.example.userservice.domain.Role;
import com.example.userservice.service.UserService;
import com.fasterxml.jackson.databind.ObjectMapper;
import lombok.AllArgsConstructor;
import lombok.Data;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.util.Date;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.stream.Collectors;

@RestController
@RequestMapping("/api")
public class UserController {

    @Autowired
    private UserService userService;


    @GetMapping("/user")
    public ResponseEntity<List<AppUser>> getAllUsers() {
        return ResponseEntity.ok(userService.getAppUsers());
    }

    @PostMapping("/user/save")
    public ResponseEntity<AppUser> saveUser(@RequestBody AppUser appUser) {
        return ResponseEntity.created(null).body(userService.saveUser(appUser));
    }


    @PostMapping("/role/save")
    public ResponseEntity<Role> saveUser(@RequestBody Role role) {
        return ResponseEntity.created(null).body(userService.saveRole(role));
    }

    @PostMapping("/role/addtouser")
    public ResponseEntity<?> saveUser(@RequestBody HelperForm form) {
        userService.addRoleToAppUser(form.getUsername(), form.getRole());
        return ResponseEntity.ok().build();
    }

    @GetMapping("/token/refresh")
    public void refreshToken(HttpServletRequest request, HttpServletResponse response) throws IOException {
        String token = request.getHeader(HttpHeaders.AUTHORIZATION);
        int accessTokenTimeLimit = 1; // min

        if (token != null && token.startsWith("Bearer ")) {
            String jws = token.substring("Bearer ".length());
            try {
                Algorithm algorithm = Algorithm.HMAC256("secret");
                JWTVerifier verifier = JWT.require(algorithm)
                        .withIssuer("/api/login")
                        .build(); //Reusable verifier instance
                DecodedJWT jwt = verifier.verify(jws);
                String userName = jwt.getSubject();
                AppUser appUser = userService.getUser(userName);
                if (appUser == null) {
                    setResponseBody(response, "fake token");
                    throw new RuntimeException("fake Token");
                }
                String accessToken = JWT.create()
                        .withSubject(appUser.getUsername())
                        .withExpiresAt(new Date(System.currentTimeMillis() + (accessTokenTimeLimit * 60 * 1000)))
                        .withIssuer(request.getRequestURI().toString())
                        .withClaim("roles", appUser.getRoles()
                                .stream().map(grantedAuthority -> grantedAuthority.getName())
                                .collect(Collectors.toList()))
                        .sign(algorithm);

                Map<String, String> tokenMap = new HashMap<>();
                tokenMap.put("access_token", accessToken);
                tokenMap.put("refresh_token", jws);
                response.setContentType(MediaType.APPLICATION_JSON_VALUE);
                new ObjectMapper().writeValue(response.getOutputStream(), tokenMap);
            } catch (JWTVerificationException exception) {
                //Invalid signature/claims
                response.setStatus(HttpStatus.FORBIDDEN.value());
                setResponseBody(response, exception.getMessage());
                throw new RuntimeException(exception.getMessage());
            }
        } else {
            setResponseBody(response, "No Token to refresh");
            throw new RuntimeException("No Token to refresh");
        }
    }


    private void setResponseBody(HttpServletResponse response, Object body) throws IOException {
        new ObjectMapper().writeValue(response.getOutputStream(), body);
    }
}

@Data
@AllArgsConstructor
class HelperForm {
    String username;
    String role;
}
