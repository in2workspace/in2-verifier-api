package es.in2.verifier;

import org.junit.jupiter.api.Test;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.context.annotation.Import;

@Import(TestcontainersConfiguration.class)
@SpringBootTest
class VerifierApplicationTests {

    @Test
    void contextLoads() {
        // This method is empty because it is only
        // used to check that the context loads correctly.
    }

}
