package es.in2.verifier;

import org.springframework.boot.SpringApplication;

public class TestVerifierApplication {

	public static void main(String[] args) {
		SpringApplication.from(VerifierApplication::main).with(TestcontainersConfiguration.class).run(args);
	}

}
