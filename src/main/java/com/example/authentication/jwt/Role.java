package com.example.authentication.jwt;

public enum Role {
	ROLE_USER(1), ROLE_ADMIN(2);

	private final int roleNumber;

	private Role(int number) {
		this.roleNumber = number;
	}

	public int getRoleNumber() {
		return roleNumber;
	}
	
}
