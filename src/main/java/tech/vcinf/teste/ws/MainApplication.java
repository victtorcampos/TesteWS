package tech.vcinf.teste.ws;

import org.springframework.boot.ApplicationArguments;
import org.springframework.boot.ApplicationRunner;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;

import tech.vcinf.teste.ws.Ssl.ClientSslContextFactory;
import tech.vcinf.teste.ws.cert.PfxConfig;
import tech.vcinf.teste.ws.cert.WindowsMyConfig;
import tech.vcinf.teste.ws.client.StatusClient;

import javax.net.ssl.SSLContext;
import java.util.logging.Level;
import java.util.logging.Logger;

@SpringBootApplication
public class MainApplication implements ApplicationRunner {
	private static final Logger logger = Logger.getLogger(MainApplication.class.getName());

	// ========== CONFIGURAÇÕES DE TESTE (HARDCODED) ==========

	// Escolha qual tipo de teste executar: "PFX" ou "WINDOWS_MY"
	private static final String TIPO_TESTE = "PFX"; // ou "WINDOWS_MY"

	// Configurações para PFX
	private static final String PFX_PATH = "C:\\certificado\\407.pfx";
	private static final String PFX_PASSWORD = "12345";

	// Configurações para Windows Store
	private static final String WINDOWS_THUMBPRINT = "C48514B5EDF842D34C322A1AAFAF8F6FDA3117A7";

	// Endpoint de teste
	private static final String ENDPOINT = "https://nfe.sefaz.mt.gov.br/nfews/v2/services/NfeStatusServico4";

	// =========================================================

	@Override
	public void run(ApplicationArguments args) {
		logger.info("=".repeat(50));
		logger.info("TESTE DE CERTIFICADO mTLS - " + TIPO_TESTE);
		logger.info("=".repeat(50));
		logger.info("");

		if ("PFX".equalsIgnoreCase(TIPO_TESTE)) {
			testarPfx();
		} else if ("WINDOWS_MY".equalsIgnoreCase(TIPO_TESTE)) {
			testarWindowsMy();
		} else {
			logger.severe("❌ TIPO_TESTE inválido: " + TIPO_TESTE);
			logger.severe("Use 'PFX' ou 'WINDOWS_MY'");
		}
	}

	private void testarPfx() {
		try {
			logger.info("📝 Configuração:");
			logger.info("  Arquivo: " + PFX_PATH);
			logger.info("  Endpoint: " + ENDPOINT);
			logger.info("");

			// 1. Criar configuração
			PfxConfig config = new PfxConfig(PFX_PATH, PFX_PASSWORD.toCharArray());

			// 2. Criar SSLContext
			logger.info("🔑 Criando SSLContext do arquivo PFX...");
			SSLContext sslContext = ClientSslContextFactory.from(config);
			logger.info("✅ SSLContext criado!");
			logger.info("");

			// 3. Executar consulta
			executarConsulta(sslContext);

		} catch (Exception e) {
			logger.log(Level.SEVERE, "❌ TESTE PFX FALHOU", e);
		}
	}

	private void testarWindowsMy() {
		try {
			// Verificar SO
			String os = System.getProperty("os.name").toLowerCase();
			if (!os.contains("win")) {
				logger.severe("❌ Teste Windows-MY só funciona em Windows!");
				logger.severe("SO detectado: " + os);
				return;
			}

			logger.info("📝 Configuração:");
			logger.info("  Thumbprint: " + WINDOWS_THUMBPRINT);
			logger.info("  Endpoint: " + ENDPOINT);
			logger.info("");

			// 1. Criar configuração
			WindowsMyConfig config = new WindowsMyConfig(WINDOWS_THUMBPRINT);

			// 2. Criar SSLContext
			logger.info("🔑 Criando SSLContext do Windows Store...");
			SSLContext sslContext = ClientSslContextFactory.from(config);
			logger.info("✅ SSLContext criado!");
			logger.info("");

			// 3. Executar consulta
			executarConsulta(sslContext);

		} catch (Exception e) {
			logger.log(Level.SEVERE, "❌ TESTE WINDOWS-MY FALHOU", e);
		}
	}

	private void executarConsulta(SSLContext sslContext) {
		try {
			StatusClient client = new StatusClient(sslContext);
			String xmlBody = criarXmlConsultaStatus();

			logger.info("🚀 Enviando consulta de status...");
			String resposta = client.consultarStatus(ENDPOINT, xmlBody);

			logger.info("");
			logger.info("✅ SUCESSO!");
			logger.info("  Tamanho da resposta: " + resposta.length() + " bytes");
			logger.info("");
			logger.info("=".repeat(50));
			logger.info("🎉 TESTE CONCLUÍDO COM SUCESSO!");
			logger.info("=".repeat(50));

		} catch (Exception e) {
			logger.log(Level.SEVERE, "❌ Falha na consulta", e);
			throw e;
		}
	}

	private String criarXmlConsultaStatus() {
		return "<?xml version=\"1.0\" encoding=\"utf-8\"?><soap12:Envelope xmlns:xsi=\"http://www.w3.org/2001/XMLSchema-instance\" xmlns:xsd=\"http://www.w3.org/2001/XMLSchema\" xmlns:soap12=\"http://www.w3.org/2003/05/soap-envelope\"><soap12:Body><nfeDadosMsg xmlns=\"http://www.portalfiscal.inf.br/nfe/wsdl/NFeStatusServico4\"><consStatServ xmlns=\"http://www.portalfiscal.inf.br/nfe\" versao=\"4.00\"><tpAmb>1</tpAmb><cUF>51</cUF><xServ>STATUS</xServ></consStatServ></nfeDadosMsg></soap12:Body></soap12:Envelope>";
	}

	public static void main(String[] args) {
		SpringApplication.run(MainApplication.class, args);
	}
}
