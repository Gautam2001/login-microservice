package com.Login.Utility;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.mail.SimpleMailMessage;
import org.springframework.mail.javamail.JavaMailSender;
import org.springframework.stereotype.Service;

import jakarta.mail.MessagingException;

@Service
public class EmailService {

	@Autowired
	private JavaMailSender mailSender;

	public void sendOtpEmail(String toEmail, String name, String otp, String purpose) throws MessagingException {
		SimpleMailMessage message = new SimpleMailMessage();
		message.setTo(toEmail);
		message.setSubject("Your OTP Code for " + purpose);
		message.setText("Hi " + name + "\n\nYour OTP code for " + purpose + " is: " + otp
				+ "\n\nThis code is valid for 10 minutes.\n\nThank you\nTeam Messengers");

		mailSender.send(message);
	}
}
