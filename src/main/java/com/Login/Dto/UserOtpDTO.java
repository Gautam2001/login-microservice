package com.Login.Dto;

import jakarta.validation.constraints.Email;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.NotNull;
import jakarta.validation.constraints.Size;
import lombok.Data;

@Data
public class UserOtpDTO {

	@NotBlank(message = "Username is required")
	@Email(message = "Invalid Email format")
	private String username;

	@NotNull(message = "OTP is required")
	@Size(min = 6, max = 6, message = "OTP must be of 6 digits.")
	private String otp;

}
