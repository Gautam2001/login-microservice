package com.Login.Utility;

import org.json.JSONArray;
import org.json.JSONObject;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;

import com.mailjet.client.ClientOptions;
import com.mailjet.client.MailjetClient;
import com.mailjet.client.MailjetRequest;
import com.mailjet.client.MailjetResponse;
import com.mailjet.client.resource.Emailv31;

@Service
public class EmailService {

	private final MailjetClient client;

	public EmailService(@Value("${MJ_APIKEY_PUBLIC}") String apiKey, @Value("${MJ_APIKEY_PRIVATE}") String apiSecret,
			@Value("${EMAIL_USER}") String senderEmail) {
		this.senderEmail = senderEmail;
		ClientOptions options = ClientOptions.builder().apiKey(apiKey).apiSecretKey(apiSecret).build();
		this.client = new MailjetClient(options);
	}

	private final String senderEmail;

	public void sendOtpEmail(String toEmail, String name, String otp, String purpose) {
		JSONObject message = new JSONObject()
				.put("From", new JSONObject().put("Email", senderEmail).put("Name", "Gautam Singhal"))
				.put("To", new JSONArray().put(new JSONObject().put("Email", toEmail).put("Name", name)))
				.put("Subject", "Your OTP Code for " + purpose).put("TextPart",
						"Hi " + name + ",\nYour OTP code for " + purpose + " is: " + otp + "\nValid for 10 minutes.");

		MailjetRequest request = new MailjetRequest(Emailv31.resource).property(Emailv31.MESSAGES,
				new JSONArray().put(message));

		try {
			MailjetResponse response = client.post(request);
			System.out.println("Mailjet Status: " + response.getStatus());
			System.out.println(response.getData());
		} catch (Exception e) {
			e.printStackTrace();
			throw new RuntimeException("Failed to send OTP email via Mailjet");
		}
	}
}
