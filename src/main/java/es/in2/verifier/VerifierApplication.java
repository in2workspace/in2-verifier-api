package es.in2.verifier;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.boot.context.properties.ConfigurationPropertiesScan;

@SpringBootApplication
@ConfigurationPropertiesScan
public class VerifierApplication {

	public static void main(String[] args) {
		SpringApplication.run(VerifierApplication.class, args);
	}

}
