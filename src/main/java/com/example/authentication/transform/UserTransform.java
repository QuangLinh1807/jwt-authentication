package com.example.authentication.transform;

import java.text.DateFormat;
import java.text.ParseException;
import java.util.ArrayList;
import java.util.List;

import com.example.authentication.dto.CreateUserDTO;
import com.example.authentication.dto.UserDTO;
import com.example.authentication.jwt.Role;
import com.example.authentication.model.User;

public class UserTransform {

	private DateFormat dateFormat;

	public UserTransform(DateFormat dateFormat) {
		this.dateFormat = dateFormat;
	}

	public User apply(CreateUserDTO dto) throws ParseException {
		User user = new User();
		user.setUsername(dto.getUsername());
		user.setPassword(dto.getPassword());
		user.setEmail(dto.getEmail());
		user.setFirstname(dto.getFirstname());
		user.setLastname(dto.getLastname());
		user.setActive(true);
		List<Role> roles = dto.getRoles();
		if (roles != null && roles.size() > 0) {
			int roleNumber = 0;
			for (Role r : roles) {
				roleNumber += r.getRoleNumber();
			}
			user.setRoles(roleNumber);
		}
		user.setDob(dateFormat.parse(dto.getDob()));

		return user;
	}

	public UserDTO apply(User user) {
		UserDTO dto = new UserDTO();
		dto.setUsername(user.getUsername());
		dto.setEmail(user.getEmail());
		dto.setFirstname(user.getFirstname());
		dto.setLastname(user.getLastname());
		if (user.getDob() != null) {
			dto.setDob(dateFormat.format(user.getDob()));
		}

		int roleNumber = user.getRoles();
		List<Role> roles = new ArrayList<>();
		Role[] roleNames = Role.values();
		for (Role role : roleNames) {
			if ((roleNumber & role.getRoleNumber()) > 0) {
				roles.add(role);
			}
		}
		dto.setRoles(roles);
		dto.setActive(user.isActive());
		return dto;
	}
}
