package com.Login.service.impl;

import java.security.SecureRandom;
import java.time.Duration;
import java.time.Instant;
import java.util.HashMap;
import java.util.Map;
import java.util.Optional;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseCookie;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.stereotype.Service;

import com.Login.Dao.PasswordStagingDao;
import com.Login.Dao.SignupStagingDao;
import com.Login.Dao.UserAuthDao;
import com.Login.Dto.UserChangePasswordDTO;
import com.Login.Dto.UserLoginDTO;
import com.Login.Dto.UserOtpDTO;
import com.Login.Dto.UserSignupDTO;
import com.Login.Dto.UsernameDTO;
import com.Login.Entity.PasswordStagingEntity;
import com.Login.Entity.SignupStagingEntity;
import com.Login.Entity.UserAuthEntity;
import com.Login.Entity.UserAuthEntity.AccountStatus;
import com.Login.Entity.UserAuthEntity.Role;
import com.Login.Utility.AppException;
import com.Login.Utility.CommonUtils;
import com.Login.Utility.EmailService;
import com.Login.Utility.Security.JwtUtil;
import com.Login.service.LoginService;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.JwtException;
import jakarta.mail.MessagingException;
import jakarta.transaction.Transactional;
import jakarta.validation.Valid;

@Service
public class LoginServiceImpl implements LoginService {

	private static final SecureRandom SECURE_RANDOM = new SecureRandom();

	@Autowired
	private BCryptPasswordEncoder passwordEncoder;

	@Autowired
	private AuthenticationManager authenticationManager;

	@Autowired
	private JwtUtil jwtUtil;

	@Autowired
	private UserAuthDao userAuthDao;

	@Autowired
	private SignupStagingDao signupStagingDao;

	@Autowired
	private EmailService emailService;

	@Autowired
	private PasswordStagingDao passwordStagingDao;

	@Override
	@Transactional(rollbackOn = Exception.class)
	public HashMap<String, Object> userRequestSignup(@Valid UserSignupDTO userSignupDTO) {
		String username = CommonUtils.normalizeUsername(userSignupDTO.getUsername());
		userSignupDTO.setUsername(username);
		CommonUtils.logMethodEntry(this, "Signup attempt for user: " + username);

		CommonUtils.ensureUserDoesNotExist(userAuthDao, username);
		CommonUtils.validatePasswordRegex(userSignupDTO.getPassword());

		HashMap<String, Object> response = new HashMap<>();

		Role role;
		try {
			role = Role.valueOf(userSignupDTO.getRole().toUpperCase());
		} catch (IllegalArgumentException e) {
			throw new AppException("Invalid role provided: " + userSignupDTO.getRole(), HttpStatus.BAD_REQUEST);
		}

		Optional<SignupStagingEntity> signupOptional = signupStagingDao.getUserByUsername(username);
		if (signupOptional.isPresent()) {
			CommonUtils.logMethodEntry(this, "Cleaning existing signup staging record for: " + username);
			int deletedCount = signupStagingDao.deleteByUsername(username);
			signupStagingDao.flush();
			CommonUtils.logMethodEntry(this, "Deleted " + deletedCount + " staging records.");
		}

		String otp = String.format("%06d", SECURE_RANDOM.nextInt(1000000));
		Instant expiry = Instant.now().plus(Duration.ofMinutes(10));

		CommonUtils.logMethodEntry(this, "OTP: " + otp + " Expiry: " + expiry);

		SignupStagingEntity signupStagingEntity = new SignupStagingEntity(username, userSignupDTO.getName(),
				passwordEncoder.encode(userSignupDTO.getPassword()), role, otp, expiry);

		SignupStagingEntity savedUser = signupStagingDao.save(signupStagingEntity);
		if (savedUser == null || savedUser.getId() == null) {
			throw new AppException("Failed to send the OTP. Please try again.", HttpStatus.INTERNAL_SERVER_ERROR);
		}

		try {
			emailService.sendOtpEmail(savedUser.getUsername(), savedUser.getName(), otp, "Signup");
		} catch (MessagingException e) {
		    e.printStackTrace();
		    throw new AppException("Failed to send OTP email: " + e.getMessage(), HttpStatus.INTERNAL_SERVER_ERROR);
		} catch (Exception e) {
			signupStagingDao.deleteById(savedUser.getId());
			e.printStackTrace();
			throw new AppException("Failed to send email. Try again later.", HttpStatus.INTERNAL_SERVER_ERROR);
		}

		return CommonUtils.prepareResponse(response,
				" OTP Send to email: " + savedUser.getUsername() + " successfully.", true);
	}

	@Override
	@Transactional
	public HashMap<String, Object> userSignup(@Valid UserOtpDTO userSignupOtpDTO) {
		CommonUtils.logMethodEntry(this);

		String username = CommonUtils.normalizeUsername(userSignupOtpDTO.getUsername());
		userSignupOtpDTO.setUsername(username);

		CommonUtils.ensureUserDoesNotExist(userAuthDao, username);

		HashMap<String, Object> response = new HashMap<>();

		SignupStagingEntity signUpData = signupStagingDao.getUserByUsername(username)
				.orElseThrow(() -> new AppException("Problem in onboarding the user. Please try again.",
						HttpStatus.INTERNAL_SERVER_ERROR));

		String providedOtp = userSignupOtpDTO.getOtp();
		if (providedOtp == null || !providedOtp.matches("\\d{6}")) {
			throw new AppException("Invalid OTP format", HttpStatus.BAD_REQUEST);
		}

		if (!signUpData.getOtp().equals(providedOtp)) {
			CommonUtils.logMethodEntry(this, "Invalid OTP entered for user: " + username);
			throw new AppException("Invalid OTP", HttpStatus.BAD_REQUEST);
		}

		if (signUpData.getExpiry().isBefore(Instant.now())) {
			CommonUtils.logMethodEntry(this, "Expired OTP for user: " + username);
			throw new AppException("OTP Expired", HttpStatus.BAD_REQUEST);
		}
		
		if (signUpData.getRole().equals(Role.SUPERADMIN)) {
			int count = userAuthDao.countByRole(signUpData.getRole());
			if (count >= 1) {
				CommonUtils.logMethodEntry(this, "Super Admin cannot be more than 1." + username);
				throw new AppException("Super Admin cannot be more than 1.", HttpStatus.BAD_REQUEST);
			}
		}

		UserAuthEntity userAuthEntity = new UserAuthEntity(signUpData.getUsername(), signUpData.getName(),
				signUpData.getPasswordHash(), signUpData.getRole());

		UserAuthEntity savedUser = userAuthDao.save(userAuthEntity);
		if (savedUser == null || savedUser.getUserId() == null) {
			throw new AppException("Failed to save the member. Please try again.", HttpStatus.INTERNAL_SERVER_ERROR);
		}

		signupStagingDao.deleteById(signUpData.getId());

		CommonUtils.logMethodEntry(this, "Signup successful for user: " + username);
		return CommonUtils.prepareResponse(response, savedUser.getRole() + " signup successful", true);
	}

	@Override
	@Transactional(rollbackOn = Exception.class)
	public HashMap<String, Object> signupResendOtp(@Valid UsernameDTO usernameDTO) {
		String username = CommonUtils.normalizeUsername(usernameDTO.getUsername());
		CommonUtils.logMethodEntry(this, "Signup Resend Otp for user: " + username);

		CommonUtils.ensureUserDoesNotExist(userAuthDao, username);

		HashMap<String, Object> response = new HashMap<>();

		SignupStagingEntity existing = signupStagingDao.getUserByUsername(username)
				.orElseThrow(() -> new AppException("User not found in signup staging. Please sign up first.",
						HttpStatus.BAD_REQUEST));

		if (existing.getOtpResendCount() >= 5) {
			throw new AppException("OTP resend limit exceeded. Please try again later.", HttpStatus.TOO_MANY_REQUESTS);
		}

		String otp = String.format("%06d", SECURE_RANDOM.nextInt(1000000));
		Instant expiry = Instant.now().plus(Duration.ofMinutes(10));
		existing.setOtp(otp);
		existing.setExpiry(expiry);
		existing.setOtpResendCount(existing.getOtpResendCount() + 1);

		SignupStagingEntity savedUser = signupStagingDao.save(existing);

		if (savedUser == null || savedUser.getId() == null) {
			throw new AppException("Failed to store OTP. Please try again.", HttpStatus.INTERNAL_SERVER_ERROR);
		}

		CommonUtils.logMethodEntry(this, "OTP: " + otp + " Expiry: " + expiry);

		try {
			emailService.sendOtpEmail(savedUser.getUsername(), savedUser.getName(), otp, "Signup");
		} catch (Exception e) {
			signupStagingDao.deleteById(savedUser.getId());
			throw new AppException("Failed to send OTP email. Please try again later.", HttpStatus.BAD_REQUEST);
		}

		return CommonUtils.prepareResponse(response, "OTP sent to email: " + savedUser.getUsername() + " successfully.",
				true);
	}

	@Override
	public ResponseEntity<HashMap<String, Object>> userLogin(@Valid UserLoginDTO userLoginDTO) {
		String username = CommonUtils.normalizeUsername(userLoginDTO.getUsername());
		userLoginDTO.setUsername(username);
		CommonUtils.logMethodEntry(this, "Login attempt for user: " + username);

		UserAuthEntity user = CommonUtils.fetchUserIfExists(userAuthDao, username,
				"User does not exist, try signing up first.");

		if (user.getAccountStatus() == AccountStatus.INACTIVE && user.getRole() == Role.ADMIN) {
			throw new AppException("Admin account is inactive", HttpStatus.FORBIDDEN);
		}

		Authentication authentication;
		try {
			authentication = authenticationManager
					.authenticate(new UsernamePasswordAuthenticationToken(username, userLoginDTO.getPassword()));
		} catch (AuthenticationException ex) {
			throw new AppException("Username or password is incorrect", HttpStatus.UNAUTHORIZED);
		}

		UserDetails userDetails = (UserDetails) authentication.getPrincipal();

		String role = userDetails.getAuthorities().stream().map(GrantedAuthority::getAuthority).findFirst()
				.orElseThrow(() -> new AppException("User role missing", HttpStatus.INTERNAL_SERVER_ERROR));

		String accessToken = jwtUtil.generateAccessToken(userDetails.getUsername(), role);
		String refreshToken = jwtUtil.generateRefreshToken(userDetails.getUsername(), role);

		ResponseCookie refreshCookie = ResponseCookie.from("refreshToken", refreshToken).httpOnly(true).secure(true)
				.path("/auth/refresh").maxAge(1 * 24 * 60 * 60).sameSite("None").build();

		HashMap<String, Object> response = new HashMap<>();
		response.put("accessToken", accessToken);
		response.put("role", user.getRole().toString());
		response.put("username", user.getUsername());
		response.put("name", user.getName());
		response.put("accountStatus", user.getAccountStatus().toString());

		CommonUtils.logMethodEntry(this, "Access Token: " + accessToken);
		CommonUtils.logMethodEntry(this, "Refresh Token: " + refreshToken);

		return ResponseEntity.ok().header(HttpHeaders.SET_COOKIE, refreshCookie.toString())
				.body(CommonUtils.prepareResponse(response, "Login successful.", true));
	}

	@Override
	public ResponseEntity<HashMap<String, Object>> userLogout() {
		CommonUtils.logMethodEntry(this);

		ResponseCookie deleteCookie = ResponseCookie.from("refreshToken", "").httpOnly(true).secure(true)
				.path("/auth/refresh").maxAge(0) // Expire token immediately
				.sameSite("Strict").build();

		HashMap<String, Object> response = new HashMap<>();

		return ResponseEntity.ok().header(HttpHeaders.SET_COOKIE, deleteCookie.toString())
				.body(CommonUtils.prepareResponse(response, "Logged out successfully", true));
	}

	@Override
	public HashMap<String, Object> refreshToken(String refreshToken) {
		CommonUtils.logMethodEntry(this);

		HashMap<String, Object> response = new HashMap<>();

		if (refreshToken == null) {
			throw new AppException("Refresh token missing", HttpStatus.UNAUTHORIZED);
		}

		try {
			Claims claims = jwtUtil.validateToken(refreshToken, "refresh");
			String username = claims.getSubject();

			UserAuthEntity user = CommonUtils.fetchUserIfExists(userAuthDao, username, "User no longer exists");

			if (user.getAccountStatus() == AccountStatus.INACTIVE) {
				throw new AppException("Account is inactive", HttpStatus.FORBIDDEN);
			}

			String role = (String) claims.get("role");

			String newAccessToken = jwtUtil.generateAccessToken(username, role);

			response.put("accessToken", newAccessToken);

			CommonUtils.logMethodEntry(this, "Access Token: " + newAccessToken);

			return CommonUtils.prepareResponse(response, "Access token refreshed.", true);

		} catch (JwtException | IllegalArgumentException ex) {
			throw new AppException("Invalid or expired refresh token", HttpStatus.UNAUTHORIZED);
		}
	}

	@Override
	@Transactional(rollbackOn = Exception.class)
	public HashMap<String, Object> requestForgotPassword(@Valid UsernameDTO usernameDTO) {
		String username = CommonUtils.normalizeUsername(usernameDTO.getUsername());

		CommonUtils.logMethodEntry(this, "Request Forgot Password attempt for user: " + username);

		HashMap<String, Object> response = new HashMap<>();

		// Fetch user
		UserAuthEntity user = CommonUtils.fetchUserIfExists(userAuthDao, username,
				"User does not exist, try signing up first.");

		if (user.getRole() == Role.ADMIN) {
			throw new AppException("Admin cannot change password from here.", HttpStatus.FORBIDDEN);
		}

		String otp = String.format("%06d", SECURE_RANDOM.nextInt(1000000));
		Instant expiry = Instant.now().plus(Duration.ofMinutes(10));

		CommonUtils.logMethodEntry(this, "Generated OTP: " + otp + ", Expiry: " + expiry);

		PasswordStagingEntity savedUser;

		// Update or insert OTP
		Optional<PasswordStagingEntity> passwordOptional = passwordStagingDao.getUserByUsername(username);
		if (passwordOptional.isPresent()) {
			CommonUtils.logMethodEntry(this, "Updating existing password staging record for: " + username);
			PasswordStagingEntity existing = passwordOptional.get();
			existing.setOtp(otp);
			existing.setExpiry(expiry);
			if (existing.getOtpResendCount() == 5) {
				existing.setOtpResendCount(2);
			}
			savedUser = passwordStagingDao.save(existing);
		} else {
			CommonUtils.logMethodEntry(this, "Creating new password staging record for: " + username);
			PasswordStagingEntity newEntity = new PasswordStagingEntity(username, otp, expiry);
			savedUser = passwordStagingDao.save(newEntity);
		}

		if (savedUser == null || savedUser.getId() == null) {
			throw new AppException("Failed to store OTP. Please try again.", HttpStatus.INTERNAL_SERVER_ERROR);
		}

		try {
			emailService.sendOtpEmail(savedUser.getUsername(), user.getName(), otp, "Forgot Password");
		} catch (Exception e) {
			passwordStagingDao.deleteById(savedUser.getId()); // Manual rollback
			throw new AppException("Failed to send OTP email. Please try again later.", HttpStatus.BAD_REQUEST);
		}

		return CommonUtils.prepareResponse(response, "OTP sent to email: " + savedUser.getUsername() + " successfully.",
				true);
	}

	@Override
	@Transactional
	public HashMap<String, Object> validateOtp(@Valid UserOtpDTO validateUserOtpDTO) {
		CommonUtils.logMethodEntry(this);

		String username = CommonUtils.normalizeUsername(validateUserOtpDTO.getUsername());
		validateUserOtpDTO.setUsername(username);

		CommonUtils.fetchUserIfExists(userAuthDao, username, "User does not exist, try signing up first.");

		HashMap<String, Object> response = new HashMap<>();

		PasswordStagingEntity passwordStagingData = passwordStagingDao.getUserByUsername(username).orElseThrow(
				() -> new AppException("OTP Validation failed. Please try again.", HttpStatus.INTERNAL_SERVER_ERROR));

		String providedOtp = validateUserOtpDTO.getOtp();
		if (providedOtp == null || !providedOtp.matches("\\d{6}")) {
			throw new AppException("Invalid OTP format", HttpStatus.BAD_REQUEST);
		}

		if (!passwordStagingData.getOtp().equals(providedOtp)) {
			CommonUtils.logMethodEntry(this, "Invalid OTP entered for user: " + username);
			throw new AppException("Invalid OTP", HttpStatus.BAD_REQUEST);
		}

		if (passwordStagingData.getExpiry().isBefore(Instant.now())) {
			CommonUtils.logMethodEntry(this, "Expired OTP for user: " + username);
			throw new AppException("OTP Expired", HttpStatus.BAD_REQUEST);
		}

		// generating otp-token for forgotPassword Validation
		String otpToken = String.format("%06d", SECURE_RANDOM.nextInt(1000000));
		Instant expiry = Instant.now().plus(Duration.ofDays(1));

		passwordStagingData.setOtp(otpToken);
		passwordStagingData.setExpiry(expiry);
		PasswordStagingEntity savedUser = passwordStagingDao.save(passwordStagingData);

		if (savedUser == null || savedUser.getId() == null) {
			throw new AppException("Failed to store OTP. Please try again.", HttpStatus.BAD_REQUEST);
		}

		CommonUtils.logMethodEntry(this, "Generated OTP Token: " + otpToken + ", Expiry: " + expiry);
		response.put("otpToken", otpToken);

		return CommonUtils.prepareResponse(response, "OTP Validation successful", true);
	}

	@Override
	@Transactional(rollbackOn = Exception.class)
	public HashMap<String, Object> forgotpassResendOtp(@Valid UsernameDTO usernameDTO) {
		String username = CommonUtils.normalizeUsername(usernameDTO.getUsername());
		CommonUtils.logMethodEntry(this, "Signup Resend Otp for user: " + username);

		UserAuthEntity user = CommonUtils.fetchUserIfExists(userAuthDao, username,
				"User does not exist, try signing up first.");

		HashMap<String, Object> response = new HashMap<>();

		PasswordStagingEntity existing = passwordStagingDao.getUserByUsername(username).orElseThrow(
				() -> new AppException("User not found in password staging. Please retry.", HttpStatus.BAD_REQUEST));

		if (existing.getOtpResendCount() >= 5) {
			throw new AppException("OTP resend limit exceeded. Please try again later.", HttpStatus.TOO_MANY_REQUESTS);
		}

		String otp = String.format("%06d", SECURE_RANDOM.nextInt(1000000));
		Instant expiry = Instant.now().plus(Duration.ofMinutes(10));
		existing.setOtp(otp);
		existing.setExpiry(expiry);
		existing.setOtpResendCount(existing.getOtpResendCount() + 1);

		PasswordStagingEntity savedUser = passwordStagingDao.save(existing);

		if (savedUser == null || savedUser.getId() == null) {
			throw new AppException("Failed to store OTP. Please try again.", HttpStatus.INTERNAL_SERVER_ERROR);
		}

		CommonUtils.logMethodEntry(this, "OTP: " + otp + " Expiry: " + expiry);

		try {
			emailService.sendOtpEmail(savedUser.getUsername(), user.getName(), otp, "Forgot Password");
		} catch (Exception e) {
			passwordStagingDao.deleteById(savedUser.getId());
			throw new AppException("Failed to send OTP email. Please try again later.", HttpStatus.BAD_REQUEST);
		}

		return CommonUtils.prepareResponse(response, "OTP sent to email: " + savedUser.getUsername() + " successfully.",
				true);
	}

	@Override
	public HashMap<String, Object> requestResetPassword(@Valid UserLoginDTO resetPasswordDTO) {
		String username = CommonUtils.normalizeUsername(resetPasswordDTO.getUsername());
		CommonUtils.ValidateUserWithToken(username);

		resetPasswordDTO.setUsername(username);
		CommonUtils.logMethodEntry(this, "Request Reset Password attempt for user: " + username);

		HashMap<String, Object> response = new HashMap<>();

		CommonUtils.fetchUserIfExists(userAuthDao, username, "User does not exist, try signing up first.");

		try {
			authenticationManager
					.authenticate(new UsernamePasswordAuthenticationToken(username, resetPasswordDTO.getPassword()));
		} catch (AuthenticationException ex) {
			throw new AppException("Password is incorrect", HttpStatus.UNAUTHORIZED);
		}

		// generating otp-token for forgotPassword Validation
		String otpToken = String.format("%06d", SECURE_RANDOM.nextInt(1000000));
		Instant expiry = Instant.now().plus(Duration.ofDays(1));

		PasswordStagingEntity savedUser;

		// Update or insert OTP Token
		Optional<PasswordStagingEntity> passwordOptional = passwordStagingDao.getUserByUsername(username);
		if (passwordOptional.isPresent()) {
			CommonUtils.logMethodEntry(this, "Updating existing password staging record for: " + username);
			PasswordStagingEntity existing = passwordOptional.get();
			existing.setOtp(otpToken);
			existing.setExpiry(expiry);
			savedUser = passwordStagingDao.save(existing);
		} else {
			CommonUtils.logMethodEntry(this, "Creating new password staging record for: " + username);
			PasswordStagingEntity newEntity = new PasswordStagingEntity(username, otpToken, expiry);
			savedUser = passwordStagingDao.save(newEntity);
		}

		if (savedUser == null || savedUser.getId() == null) {
			throw new AppException("Failed to store OTP. Please try again.", HttpStatus.INTERNAL_SERVER_ERROR);
		}

		CommonUtils.logMethodEntry(this, "Generated OTP Token: " + otpToken + ", Expiry: " + expiry);
		response.put("otpToken", otpToken);

		return CommonUtils.prepareResponse(response, "Password validation successful", true);
	}

	@Override
	@Transactional
	public HashMap<String, Object> changePassword(@Valid UserChangePasswordDTO changePasswordDTO,
			boolean chechTokenUser) {
		CommonUtils.logMethodEntry(this);

		String username = CommonUtils.normalizeUsername(changePasswordDTO.getUsername());
		if (chechTokenUser) {
			CommonUtils.ValidateUserWithToken(username);
		}
		changePasswordDTO.setUsername(username);

		UserAuthEntity user = CommonUtils.fetchUserIfExists(userAuthDao, username,
				"User does not exist, try signing up first.");
		CommonUtils.validatePasswordRegex(changePasswordDTO.getNewPassword());

		HashMap<String, Object> response = new HashMap<>();

		PasswordStagingEntity passwordStagingData = passwordStagingDao.getUserByUsername(username).orElseThrow(
				() -> new AppException("Password change failed. Please try again.", HttpStatus.INTERNAL_SERVER_ERROR));

		String providedOtp = changePasswordDTO.getOtpToken();
		if (providedOtp == null || !providedOtp.matches("\\d{6}")
				|| !passwordStagingData.getOtp().equals(providedOtp)) {
			throw new AppException("Password change Authentication failed. Please try again.", HttpStatus.BAD_REQUEST);
		}

		if (passwordStagingData.getExpiry().isBefore(Instant.now())) {
			CommonUtils.logMethodEntry(this, "Expired OTP for user: " + username);
			throw new AppException("Session Expired. Please try again", HttpStatus.BAD_REQUEST);
		}

		user.setPasswordHash(passwordEncoder.encode(changePasswordDTO.getNewPassword()));
		UserAuthEntity savedUser = userAuthDao.save(user);
		if (savedUser == null || savedUser.getUserId() == null) {
			throw new AppException("Failed to save the member. Please try again.", HttpStatus.INTERNAL_SERVER_ERROR);
		}

		passwordStagingDao.deleteById(passwordStagingData.getId());

		CommonUtils.logMethodEntry(this, "Password change successful for user: " + username);
		return CommonUtils.prepareResponse(response, "Password change successful", true);
	}

	@Override
	public ResponseEntity<Map<String, Object>> checkUserExists(@Valid UsernameDTO usernameDTO) {
		CommonUtils.logMethodEntry(this);

		String username = CommonUtils.normalizeUsername(usernameDTO.getUsername());
		usernameDTO.setUsername(username);

		Optional<UserAuthEntity> userOpt = userAuthDao.getUserByUsername(username);
		if (userOpt.isPresent()) {
			CommonUtils.logMethodEntry(this, "User fetched successfully.");
			return ResponseEntity.ok().body(Map.of("exists", true, "name", userOpt.get().getName(), "role", userOpt.get().getRole()));
		} else {
			CommonUtils.logMethodEntry(this, "User not Found.");
			return ResponseEntity.status(HttpStatus.NOT_FOUND).body(Map.of("exists", false));
		}
	}
	
	@Override
	public ResponseEntity<Map<String, Object>> checkSuperAdminExists(@Valid UsernameDTO usernameDTO) {
		CommonUtils.logMethodEntry(this);

		String username = CommonUtils.normalizeUsername(usernameDTO.getUsername());
		usernameDTO.setUsername(username);

		Optional<UserAuthEntity> userOpt = userAuthDao.getUserByUsernameAndRole(username, Role.SUPERADMIN);
		if (userOpt.isPresent()) {
			CommonUtils.logMethodEntry(this, "User fetched successfully.");
			return ResponseEntity.ok().body(Map.of("exists", true, "name", userOpt.get().getName(), "role", userOpt.get().getRole()));
		} else {
			CommonUtils.logMethodEntry(this, "User not Found.");
			return ResponseEntity.status(HttpStatus.NOT_FOUND).body(Map.of("exists", false));
		}
	}

}
