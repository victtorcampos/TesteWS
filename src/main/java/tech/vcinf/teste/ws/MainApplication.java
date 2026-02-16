package tech.vcinf.teste.ws;

import org.springframework.boot.ApplicationArguments;
import org.springframework.boot.ApplicationRunner;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;

import tech.vcinf.teste.ws.cert.PfxConfig;
import tech.vcinf.teste.ws.cert.WindowsMyConfig;
import tech.vcinf.teste.ws.client.StatusClient;
import tech.vcinf.teste.ws.ssl.ClientSslContextFactory;

import javax.net.ssl.SSLContext;
import java.util.logging.ConsoleHandler;
import java.util.logging.Level;
import java.util.logging.Logger;
import java.util.logging.SimpleFormatter;

@SpringBootApplication
public class MainApplication implements ApplicationRunner {
	private static final Logger logger = Logger.getLogger(MainApplication.class.getName());

	@Override
	public void run(ApplicationArguments args) {
		configurarLog();
		
		logger.info("========================================");
		logger.info("=== TESTE DE CERTIFICADOS mTLS ===");
		logger.info("========================================");
		
		// Detectar qual tipo de teste executar baseado nos parâmetros
		String pfxPath = System.getProperty("pfx.path");
		String pfxPassword = System.getProperty("pfx.password");
		String thumbprint = System.getProperty("cert.thumbprint");
		String endpoint = System.getProperty("endpoint", 
			"https://nfe.sefaz.mt.gov.br/nfews/v2/services/NfeStatusServico4");
		
		if (pfxPath != null && pfxPassword != null) {
			testarPfx(pfxPath, pfxPassword, endpoint);
		} else if (thumbprint != null) {
			testarWindowsMy(thumbprint, endpoint);
		} else {
			logger.severe("❌ Nenhum parâmetro de certificado fornecido!");
			logger.severe("");
			logger.severe("Para testar com PFX:");
			logger.severe("  mvn spring-boot:run -Dpfx.path=C:\\\\certificado\\\\407.pfx -Dpfx.password=12345");
			logger.severe("");
			logger.severe("Para testar com Windows Store:");
			logger.severe("  mvn spring-boot:run -Dcert.thumbprint=C48514B5EDF842D34C322A1AAFAF8F6FDA3117A7");
			logger.severe("");
		}
	}
	
	private void testarPfx(String pfxPath, String pfxPassword, String endpoint) {
		try {
			logger.info("");
			logger.info("=== TESTE PFX ===");
			logger.info("Path: " + pfxPath);
			logger.info("Endpoint: " + endpoint);
			logger.info("");
			
			// Criar configuração
			PfxConfig config = new PfxConfig(pfxPath, pfxPassword.toCharArray());
			
			// Criar SSLContext
			logger.info("Criando SSLContext do arquivo PFX...");
			SSLContext sslContext = ClientSslContextFactory.from(config);
			logger.info("✅ SSLContext criado com sucesso!");
			logger.info("");
			
			// Criar cliente e executar consulta
			StatusClient client = new StatusClient(sslContext);
			String xmlBody = criarXmlConsultaStatus();
			
			logger.info("Enviando consulta de status...");
			String resposta = client.consultarStatus(endpoint, xmlBody);
			
			logger.info("✅ RESPOSTA RECEBIDA COM SUCESSO!");
			logger.info("Tamanho: " + resposta.length() + " bytes");
			logger.fine("Resposta: " + resposta);
			logger.info("");
			logger.info("✅ TESTE PFX CONCLUÍDO COM SUCESSO!");
			
		} catch (Exception e) {
			logger.log(Level.SEVERE, "❌ TESTE PFX FALHOU", e);
		}
	}
	
	private void testarWindowsMy(String thumbprint, String endpoint) {
		try {
			// Verificar SO
			String os = System.getProperty("os.name").toLowerCase();
			if (!os.contains("win")) {
				logger.severe("❌ Teste Windows-MY só pode rodar em Windows!");
				logger.severe("Sistema operacional detectado: " + os);
				return;
			}
			
			logger.info("");
			logger.info("=== TESTE WINDOWS-MY ===");
			logger.info("Thumbprint: " + thumbprint);
			logger.info("Endpoint: " + endpoint);
			logger.info("");
			
			// Criar configuração
			WindowsMyConfig config = new WindowsMyConfig(thumbprint);
			
			// Criar SSLContext
			logger.info("Criando SSLContext do Windows Certificate Store...");
			SSLContext sslContext = ClientSslContextFactory.from(config);
			logger.info("✅ SSLContext criado com sucesso!");
			logger.info("");
			
			// Criar cliente e executar consulta
			StatusClient client = new StatusClient(sslContext);
			String xmlBody = criarXmlConsultaStatus();
			
			logger.info("Enviando consulta de status...");
			String resposta = client.consultarStatus(endpoint, xmlBody);
			
			logger.info("✅ RESPOSTA RECEBIDA COM SUCESSO!");
			logger.info("Tamanho: " + resposta.length() + " bytes");
			logger.fine("Resposta: " + resposta);
			logger.info("");
			logger.info("✅ TESTE WINDOWS-MY CONCLUÍDO COM SUCESSO!");
			
		} catch (Exception e) {
			logger.log(Level.SEVERE, "❌ TESTE WINDOWS-MY FALHOU", e);
		}
	}
	
	private String criarXmlConsultaStatus() {
		return """<?xml version="1.0" encoding="UTF-8"?>
<soap12:Envelope xmlns:soap12="http://www.w3.org/2003/05/soap-envelope" 
                 xmlns:nfe="http://www.portalfiscal.inf.br/nfe/wsdl/NFeStatusServico4">
  <soap12:Body>
    <nfe:nfeStatusServicoNF>
      <nfeDadosMsg>
        <consStatServ xmlns="http://www.portalfiscal.inf.br/nfe" versao="4.00">
          <tpAmb>2</tpAmb>
          <cUF>51</cUF>
          <xServ>STATUS</xServ>
        </consStatServ>
      </nfeDadosMsg>
    </nfe:nfeStatusServicoNF>
  </soap12:Body>
</soap12:Envelope>""";
	}
	
	private void configurarLog() {
		Logger rootLogger = Logger.getLogger("");
		rootLogger.setLevel(Level.INFO);
		
		// Remover handlers existentes
		for (var handler : rootLogger.getHandlers()) {
			rootLogger.removeHandler(handler);
		}
		
		ConsoleHandler handler = new ConsoleHandler();
		handler.setLevel(Level.ALL);
		handler.setFormatter(new SimpleFormatter());
		rootLogger.addHandler(handler);
	}

	public static void main(String[] args) {
		SpringApplication.run(MainApplication.class, args);
	}
}
