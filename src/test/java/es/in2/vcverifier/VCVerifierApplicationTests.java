package es.in2.vcverifier;

import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.test.context.ActiveProfiles;

@SpringBootTest
@ActiveProfiles("test")
class VCVerifierApplicationTests {

    @Test
    void contextLoads() {
        // The test will automatically fail if the application context cannot be loaded.
    }



    @Test
    void testMain() {
        VCVerifierApplication.main(new String[] {"--spring.profiles.active=test"});
        Assertions.assertTrue(true);
    }

}
