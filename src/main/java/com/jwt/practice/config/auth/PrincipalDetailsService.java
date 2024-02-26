package com.jwt.practice.config.auth;

import com.jwt.practice.domain.User;
import com.jwt.practice.domain.UserRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;

@Service
@RequiredArgsConstructor
public class PrincipalDetailsService implements UserDetailsService {

    private final UserRepository userRepository;

    @Override
    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
        User user = userRepository.findByUsername(username);

        if (user != null) {
            PrincipalDetails principalDetails = new PrincipalDetails(user);
            System.out.println("PrincipalDetailsService loadUserByUsername");
            return principalDetails;
        }

        return null;
    }
}
