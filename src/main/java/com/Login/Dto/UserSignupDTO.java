package com.Login.Dto;

import jakarta.validation.constraints.Email;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Size;
import lombok.Data;

@Data
public class UserSignupDTO {

	@NotBlank(message = "Username is required")
	@Email(message = "Invalid Email format")
	private String username;

	@NotBlank(message = "Name is required")
	@Size(min = 2, max = 50, message = "Name between 2 and 50 Characters")
	private String name;

	@NotBlank(message = "Password is required")
	@Size(min = 8, max = 20, message = "Password must be between 8 and 20 characters")
	private String password;

	@NotBlank(message = "Role is required")
	@Size(min = 4, max = 5, message = "Specify the role of the Member")
	private String role;

}
