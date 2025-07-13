package com.Login.Utility.Security;

import java.util.Collection;
import java.util.Collections;

import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;

import com.Login.Entity.UserAuthEntity;

public class CustomUserDetails implements UserDetails {

	private static final long serialVersionUID = 1L;

	private final UserAuthEntity userAuthEntity;

	public CustomUserDetails(UserAuthEntity userAuthEntity) {
		super();
		this.userAuthEntity = userAuthEntity;
	}

	@Override
	public Collection<? extends GrantedAuthority> getAuthorities() {
		return Collections.singleton(new SimpleGrantedAuthority("ROLE_" + userAuthEntity.getRole()));
	}

	@Override
	public String getPassword() {
		return userAuthEntity.getPasswordHash();
	}

	@Override
	public String getUsername() {
		return userAuthEntity.getUsername();
	}

}
