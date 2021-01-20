package com.example.authentication.jwt;

import java.util.ArrayList;
import java.util.List;

import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;

import com.example.authentication.model.User;

public final class JwtUserFactory {

    private JwtUserFactory() {
    }

    public static JwtUser create(User user) {
        return new JwtUser(
                user.getId(),
                user.getUsername(),
                user.getPassword(),
                user.getEmail(),
                mapToGrantedAuthorities(user.getRoles()),
                user.isActive()
        );
    }

    private static List<GrantedAuthority> mapToGrantedAuthorities(int roleNumber) {
    	Role[] roleNames = Role.values();
    	List<GrantedAuthority> authorities = new ArrayList<>();
    	for (Role role: roleNames) {
    		if ((roleNumber & role.getRoleNumber()) > 0) {
    			authorities.add(new SimpleGrantedAuthority(role.toString()));
    		}
    	}
    	return authorities;
    }
}
