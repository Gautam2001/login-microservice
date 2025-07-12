package com.Login.Dto;

import jakarta.validation.constraints.Email;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.NotNull;
import jakarta.validation.constraints.Size;
import lombok.Data;

@Data
public class UserChangePasswordDTO {

	@NotBlank(message = "Username is required")
	@Email(message = "Invalid Email format")
	private String username;

	@NotNull(message = "OTP is required")
	@Size(min = 6, max = 6, message = "OTP must be of 6 digits.")
	private String otpToken;

	@NotBlank(message = "Password is required")
	@Size(min = 8, max = 20, message = "Password must be between 8 and 20 characters")
	private String newPassword;

}
