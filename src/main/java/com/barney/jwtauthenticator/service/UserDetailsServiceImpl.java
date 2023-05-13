package com.barney.jwtauthenticator.service;

import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.stereotype.Service;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.Map;

@Service
public class UserDetailsServiceImpl implements UserDetailsService {

    private final BCryptPasswordEncoder bCryptPasswordEncoder;

    public UserDetailsServiceImpl(BCryptPasswordEncoder bCryptPasswordEncoder) {
        this.bCryptPasswordEncoder = bCryptPasswordEncoder;
    }

    @Override
    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
        Map<String, String> map = new HashMap<>();
        map.put("martin", bCryptPasswordEncoder.encode("123"));

        if (map.containsKey(username)) {
            return new User(username, map.get(username), new ArrayList<>());
        }

        throw new UsernameNotFoundException(username);
    }
}
