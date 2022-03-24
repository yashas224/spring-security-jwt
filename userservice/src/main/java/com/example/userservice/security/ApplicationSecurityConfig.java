package com.example.userservice.security;

import com.example.userservice.flter.AuthenticationFilter;
import com.example.userservice.flter.AuthorizationFilter;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.HttpMethod;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;

@Configuration
@EnableWebSecurity
public class ApplicationSecurityConfig extends WebSecurityConfigurerAdapter {


    @Autowired
    private UserDetailsService userDetailsService;

    @Autowired
    PasswordEncoder passwordEncoder;

    @Override
    protected void configure(AuthenticationManagerBuilder auth) throws Exception {
        auth.userDetailsService(userDetailsService).passwordEncoder(passwordEncoder);

    }

    @Override
    public AuthenticationManager authenticationManagerBean() throws Exception {
        return super.authenticationManagerBean();
    }

    @Override
    protected void configure(HttpSecurity http) throws Exception {

        http.csrf().disable();
        http.sessionManagement().sessionCreationPolicy(SessionCreationPolicy.STATELESS);
        // default /login is public
        http.authorizeRequests().antMatchers("/api/login","/api/token/refresh").permitAll();
        http.authorizeRequests()
                .antMatchers(HttpMethod.GET, "/api/user/**").hasAuthority("ROLE_USER")
                .antMatchers(HttpMethod.POST, "/api/user/**").hasAnyAuthority("ROLE_ADMIN")
                .anyRequest()
                .authenticated();

        //filter
        AuthenticationFilter filter = new AuthenticationFilter(authenticationManagerBean());
        filter.setFilterProcessesUrl("/api/login");
        http.addFilter(filter);
        http.addFilterBefore(new AuthorizationFilter(), AuthenticationFilter.class);
    }
}
