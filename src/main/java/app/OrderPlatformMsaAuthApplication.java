package app;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.data.redis.repository.configuration.EnableRedisRepositories;
import org.springframework.scheduling.annotation.EnableScheduling;

@SpringBootApplication
@EnableScheduling
@EnableRedisRepositories
public class OrderPlatformMsaAuthApplication {

	public static void main(String[] args) {
		SpringApplication.run(OrderPlatformMsaAuthApplication.class, args);
	}

}
