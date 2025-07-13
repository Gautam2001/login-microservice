package com.Login.service;

import java.util.HashMap;
import java.util.Map;

import org.springframework.http.ResponseEntity;
import org.springframework.stereotype.Component;

import com.Login.Dto.UserChangePasswordDTO;
import com.Login.Dto.UserLoginDTO;
import com.Login.Dto.UserOtpDTO;
import com.Login.Dto.UserSignupDTO;
import com.Login.Dto.UsernameDTO;

import jakarta.validation.Valid;

@Component
public interface LoginService {

	HashMap<String, Object> userRequestSignup(@Valid UserSignupDTO userSignupDTO);

	HashMap<String, Object> userSignup(@Valid UserOtpDTO userSignupOtpDTO);

	HashMap<String, Object> signupResendOtp(@Valid UsernameDTO usernameDTO);

	ResponseEntity<HashMap<String, Object>> userLogin(@Valid UserLoginDTO userLoginDTO);

	ResponseEntity<HashMap<String, Object>> userLogout();

	HashMap<String, Object> refreshToken(String refreshToken);

	HashMap<String, Object> requestForgotPassword(@Valid UsernameDTO usernameDTO);

	HashMap<String, Object> validateOtp(@Valid UserOtpDTO validateUserOtpDTO);

	HashMap<String, Object> forgotpassResendOtp(@Valid UsernameDTO usernameDTO);

	HashMap<String, Object> requestResetPassword(@Valid UserLoginDTO resetPasswordDTO);

	HashMap<String, Object> changePassword(@Valid UserChangePasswordDTO changePasswordDTO);

	ResponseEntity<Map<String, Object>> checkUserExists(@Valid UsernameDTO usernameDTO);

}
