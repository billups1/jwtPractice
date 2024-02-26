package com.jwt.practice.controller;

import com.jwt.practice.config.auth.PrincipalDetails;
import com.jwt.practice.domain.User;
import com.jwt.practice.domain.UserRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequiredArgsConstructor
public class RestApiController {

    private final UserRepository userRepository;

    @Autowired
    private BCryptPasswordEncoder bCryptPasswordEncoder;

    @GetMapping("/home")
    public String home(@AuthenticationPrincipal PrincipalDetails principalDetails) {
        System.out.println(principalDetails.getAuthorities());
        return "home";
    }

    @GetMapping("/api/user")
    public String user() {
        return "user";
    }

    @GetMapping("/api/manager")
    public String manager() {
        return "manager";
    }

    @GetMapping("/api/admin")
    public String admin() {
        return "admin";
    }

    @PostMapping("/join")
    public String join(@RequestBody User user) {
        user.setRoles("ROLE_USER");
        user.setPassword(bCryptPasswordEncoder.encode(user.getPassword()));
        userRepository.save(user);
        return "회원가입 성공";
    }

}
