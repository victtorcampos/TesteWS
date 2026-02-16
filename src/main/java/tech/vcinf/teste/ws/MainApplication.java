package tech.vcinf.teste.ws;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import org.springframework.boot.ApplicationArguments;
import org.springframework.boot.ApplicationRunner;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;

import tech.vcinf.teste.ws.gerador.CacertUtil;
import tech.vcinf.teste.ws.http.RequestClient;

@SpringBootApplication
public class MainApplication implements ApplicationRunner {
	private static final Logger logger = LoggerFactory.getLogger(MainApplication.class);

	@Override
	public void run(ApplicationArguments args) {
		CacertUtil.createTrustStore();
		RequestClient.statusServico();
	}

	public static void main(String[] args) {
		SpringApplication.run(MainApplication.class, args);
	}

}
