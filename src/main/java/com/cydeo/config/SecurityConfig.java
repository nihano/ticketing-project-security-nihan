package com.cydeo.config;

import jdk.dynalink.linker.LinkerServices;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.provisioning.InMemoryUserDetailsManager;
import org.springframework.security.web.SecurityFilterChain;


import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

@Configuration
public class SecurityConfig {


    @Bean
    public UserDetailsService userDetailService(PasswordEncoder encoder) {
        //we are creating User from Spring User class
        List<UserDetails> userList = new ArrayList<>();
        userList.add(new User("mike", encoder.encode("password"), Arrays.asList(new SimpleGrantedAuthority("ROLE_ADMIN"))));     //spring security User
        userList.add(new User("ozzy", encoder.encode("password"), Arrays.asList(new SimpleGrantedAuthority("ROLE_MANAGER"))));

        //UserDetailsService is interface, returning the implementation class below
        return new InMemoryUserDetailsManager(userList);
    }

    @Bean
    public SecurityFilterChain filterChain(HttpSecurity http) throws Exception {

        return http
                .authorizeRequests() //every page needs to be authorized
                .antMatchers("/user/**").hasRole("ADMIN")
                .antMatchers("/project/**").hasRole("MANAGER")
                .antMatchers("/task/employees/**").hasRole("EMPLOYEE")
                .antMatchers("/task/**").hasRole("MANAGER")
//                .antMatchers("/task/**").hasAnyRole("EMPLOYEE", "ADMIN")  more than one role
//                .antMatchers("/task/**").hasAuthority("ROLE_EMPLOYEE") // we need to put _ if we use hasAuthority
                .antMatchers( //no authentication for below
                        "/",
                        "/login",
                        "/fragments/**",
                        "/assets/**",
                        "/images/**"
                ).permitAll()
                .anyRequest().authenticated()//rest needs to be authenticated
                .and()
//                .httpBasic()//pop up page/form will remove later, and we use our login page
                .formLogin()
                .loginPage("/login") //the form that we want to use
                .defaultSuccessUrl("/welcome") //after successfully login
                .failureUrl("/login?error=true")
                .permitAll()//login page needs to be accessible to anyone
                .and().build();

    }
}
