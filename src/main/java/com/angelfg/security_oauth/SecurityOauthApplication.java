package com.angelfg.security_oauth;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.CommandLineRunner;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.security.crypto.password.PasswordEncoder;

@SpringBootApplication
public class SecurityOauthApplication implements CommandLineRunner {

	@Autowired
	private PasswordEncoder passwordEncoder;

	public static void main(String[] args) {
		SpringApplication.run(SecurityOauthApplication.class, args);
	}

	@Override
	public void run(String... args) throws Exception {
//		System.out.println("user: " + this.passwordEncoder.encode("to_be_encoded"));
		// user: $2a$10$fbn6kkAm/Up5titTiozr2uN3MLL39otuKAUBHdaqzcmVVuSjTQHeK

//		System.out.println("client: " + this.passwordEncoder.encode("secret"));
		// client: $2a$10$NSWrnJdEyTR7r/4oR.chg.QxpOl/dtS4qzVIY7K348qg2TvgIh.qu
	}

}
