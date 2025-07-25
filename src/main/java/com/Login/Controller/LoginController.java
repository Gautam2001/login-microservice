package com.Login.Controller;

import java.util.HashMap;
import java.util.Map;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.CookieValue;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import com.Login.Dto.UserChangePasswordDTO;
import com.Login.Dto.UserLoginDTO;
import com.Login.Dto.UserOtpDTO;
import com.Login.Dto.UserSignupDTO;
import com.Login.Dto.UsernameDTO;
import com.Login.Utility.CommonUtils;
import com.Login.service.LoginService;

import jakarta.validation.Valid;

@RestController
@RequestMapping("/auth")
public class LoginController {

	@Autowired
	private LoginService loginService;

	@GetMapping("/ping")
	public ResponseEntity<HashMap<String, Object>> ping() {
		CommonUtils.logMethodEntry(this);

		HashMap<String, Object> response = new HashMap<>();

		return ResponseEntity.ok(CommonUtils.prepareResponse(response, "pong", true));
	}

	@PostMapping("/request-signup")
	public ResponseEntity<HashMap<String, Object>> userRequestSignup(@RequestBody @Valid UserSignupDTO userSignupDTO) {
		CommonUtils.logMethodEntry(this);

		HashMap<String, Object> response = loginService.userRequestSignup(userSignupDTO);

		return ResponseEntity.ok(response);
	}

	@PostMapping("/signup")
	public ResponseEntity<HashMap<String, Object>> userSignup(@RequestBody @Valid UserOtpDTO userSignupOtpDTO) {
		CommonUtils.logMethodEntry(this);

		HashMap<String, Object> response = loginService.userSignup(userSignupOtpDTO);

		return ResponseEntity.ok(response);
	}

	@PostMapping("/signup-resend-otp")
	public ResponseEntity<HashMap<String, Object>> signupResendOtp(@RequestBody @Valid UsernameDTO usernameDTO) {
		CommonUtils.logMethodEntry(this);

		HashMap<String, Object> response = loginService.signupResendOtp(usernameDTO);

		return ResponseEntity.ok(response);
	}

	@PostMapping("/login")
	public ResponseEntity<HashMap<String, Object>> userLogin(@RequestBody @Valid UserLoginDTO userLoginDTO) {
		CommonUtils.logMethodEntry(this);

		ResponseEntity<HashMap<String, Object>> response = loginService.userLogin(userLoginDTO);

		return response;
	}

	@PostMapping("/logout")
	public ResponseEntity<HashMap<String, Object>> userLogout() {
		CommonUtils.logMethodEntry(this);

		ResponseEntity<HashMap<String, Object>> response = loginService.userLogout();

		return response;
	}

	@PostMapping("/refresh")
	public ResponseEntity<HashMap<String, Object>> refreshToken(@CookieValue(required = false) String refreshToken) {
		CommonUtils.logMethodEntry(this);

		HashMap<String, Object> response = loginService.refreshToken(refreshToken);

		return ResponseEntity.ok(response);
	}

	@PostMapping("/request-forgot-password")
	public ResponseEntity<HashMap<String, Object>> requestForgotPassword(@RequestBody @Valid UsernameDTO usernameDTO) {
		CommonUtils.logMethodEntry(this);

		HashMap<String, Object> response = loginService.requestForgotPassword(usernameDTO);

		return ResponseEntity.ok(response);
	}

	@PostMapping("/validate-otp")
	public ResponseEntity<HashMap<String, Object>> validateOtp(@RequestBody @Valid UserOtpDTO validateUserOtpDTO) {
		CommonUtils.logMethodEntry(this);

		HashMap<String, Object> response = loginService.validateOtp(validateUserOtpDTO);

		return ResponseEntity.ok(response);
	}

	@PostMapping("/forgot-password")
	public ResponseEntity<HashMap<String, Object>> forgotPassword(
			@RequestBody @Valid UserChangePasswordDTO changePasswordDTO) {
		CommonUtils.logMethodEntry(this);

		HashMap<String, Object> response = loginService.changePassword(changePasswordDTO, false);

		return ResponseEntity.ok(response);
	}

	@PostMapping("/forgotpass-resend-otp")
	public ResponseEntity<HashMap<String, Object>> forgotpassResendOtp(@RequestBody @Valid UsernameDTO usernameDTO) {
		CommonUtils.logMethodEntry(this);

		HashMap<String, Object> response = loginService.forgotpassResendOtp(usernameDTO);

		return ResponseEntity.ok(response);
	}

	@PostMapping("/request-reset-password")
	public ResponseEntity<HashMap<String, Object>> requestResetPassword(
			@RequestBody @Valid UserLoginDTO resetPasswordDTO) {
		CommonUtils.logMethodEntry(this);

		HashMap<String, Object> response = loginService.requestResetPassword(resetPasswordDTO);

		return ResponseEntity.ok(response);
	}

	// same as forgot-password but requires an accessToken to proceed.
	@PostMapping("/reset-password")
	public ResponseEntity<HashMap<String, Object>> resetPassword(
			@RequestBody @Valid UserChangePasswordDTO changePasswordDTO) {
		CommonUtils.logMethodEntry(this);

		HashMap<String, Object> response = loginService.changePassword(changePasswordDTO, true);

		return ResponseEntity.ok(response);
	}

	// for external micro-services
	@PostMapping("/check-user-exists")
	public ResponseEntity<Map<String, Object>> checkUserExists(@RequestBody @Valid UsernameDTO usernameDTO) {
		CommonUtils.logMethodEntry(this);

		ResponseEntity<Map<String, Object>> response = loginService.checkUserExists(usernameDTO);

		return response;
	}

}
