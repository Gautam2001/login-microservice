package com.Login.Utility.Security;

import org.springframework.security.authentication.DisabledException;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;

import com.Login.Dao.UserAuthDao;
import com.Login.Entity.UserAuthEntity;
import com.Login.Entity.UserAuthEntity.AccountStatus;
import com.Login.Utility.CommonUtils;

@Service
public class CustomUserDetailsService implements UserDetailsService {

	private final UserAuthDao userAuthDao;

	public CustomUserDetailsService(UserAuthDao userAuthDao) {
		super();
		this.userAuthDao = userAuthDao;
	}

	@Override
	public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
		CommonUtils.logMethodEntry(this);
		UserAuthEntity user = userAuthDao.getUserByUsername(username)
				.orElseThrow(() -> new UsernameNotFoundException("User not found with username: " + username));

		if (user.getAccountStatus() == AccountStatus.INACTIVE && user.getRole().toString().equalsIgnoreCase("ADMIN")) {
			throw new DisabledException("Account is Inactive");
		}
		return new CustomUserDetails(user);
	}

}
