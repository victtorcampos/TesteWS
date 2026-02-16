package tech.vcinf.teste.ws;

import org.springframework.boot.ApplicationArguments;
import org.springframework.boot.ApplicationRunner;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;

import javax.net.ssl.KeyManagerFactory;
import javax.net.ssl.SSLContext;
import javax.net.ssl.TrustManagerFactory;
import java.io.InputStream;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.KeyStore;
import java.security.MessageDigest;
import java.security.cert.X509Certificate;
import java.time.Duration;
import java.util.Enumeration;
import java.util.logging.Level;
import java.util.logging.Logger;

@SpringBootApplication
public class MainApplication implements ApplicationRunner {
	private static final Logger logger = Logger.getLogger(MainApplication.class.getName());

	// ========== CONFIGURAÇÕES DE TESTE (HARDCODED) ==========
	
	// Escolha qual tipo de teste executar: "PFX" ou "WINDOWS_MY"
	private static final String TIPO_TESTE = "PFX"; // ou "WINDOWS_MY"
	
	// Configurações para PFX
	private static final String PFX_PATH = "C:\\\\certificado\\\\407.pfx";
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
		
		SSLContext sslContext = null;

		if ("PFX".equalsIgnoreCase(TIPO_TESTE)) {
			sslContext = criarSslContextPfx(PFX_PATH, PFX_PASSWORD);
		} else if ("WINDOWS_MY".equalsIgnoreCase(TIPO_TESTE)) {
			sslContext = criarSslContextWindowsMy(WINDOWS_THUMBPRINT);
		}

		if (sslContext != null) {
			enviarConsultaStatus(sslContext, ENDPOINT, criarXmlConsultaStatus());
		} else {
			logger.severe("❌ Não foi possível criar o SSLContext. Verifique o TIPO_TESTE.");
		}
	}
	
	// ========== MÉTODOS DE SSL (FASE 1) ==========

	private SSLContext criarSslContextPfx(String path, String senha) {
		try {
			logger.info("🔑 Criando SSLContext do arquivo PFX: " + path);
			KeyStore ks = KeyStore.getInstance("PKCS12");
			try (InputStream in = Files.newInputStream(Path.of(path))) {
				ks.load(in, senha.toCharArray());
			}
			
			KeyManagerFactory kmf = KeyManagerFactory.getInstance("SunX509");
			kmf.init(ks, senha.toCharArray());
			
			TrustManagerFactory tmf = TrustManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm());
			tmf.init((KeyStore) null);
			
			SSLContext ctx = SSLContext.getInstance("TLS");
			ctx.init(kmf.getKeyManagers(), tmf.getTrustManagers(), null);
			
			logger.info("✅ SSLContext PFX criado!");
			return ctx;
		} catch (Exception e) {
			logger.log(Level.SEVERE, "❌ Erro no SSLContext PFX", e);
			return null;
		}
	}

	private SSLContext criarSslContextWindowsMy(String thumbprint) {
		try {
			String os = System.getProperty("os.name").toLowerCase();
			if (!os.contains("win")) {
				logger.severe("❌ Windows-MY requer Windows SO.");
				return null;
			}

			logger.info("🔑 Criando SSLContext do Windows Store: " + thumbprint);
			KeyStore ks = KeyStore.getInstance("Windows-MY");
			ks.load(null, null);
			
			String alias = buscarAliasPorThumbprint(ks, thumbprint);
			if (alias == null) throw new IllegalStateException("Thumbprint não encontrado");
			
			KeyManagerFactory kmf = KeyManagerFactory.getInstance("SunX509");
			kmf.init(ks, null);
			
			TrustManagerFactory tmf = TrustManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm());
			tmf.init((KeyStore) null);
			
			SSLContext ctx = SSLContext.getInstance("TLS");
			ctx.init(kmf.getKeyManagers(), tmf.getTrustManagers(), null);
			
			logger.info("✅ SSLContext Windows-MY criado!");
			return ctx;
		} catch (Exception e) {
			logger.log(Level.SEVERE, "❌ Erro no SSLContext Windows-MY", e);
			return null;
		}
	}

	private String buscarAliasPorThumbprint(KeyStore ks, String target) throws Exception {
		String targetClean = target.replaceAll("[^0-9A-Fa-f]", "").toUpperCase();
		MessageDigest sha1 = MessageDigest.getInstance("SHA-1");
		Enumeration<String> aliases = ks.aliases();
		while (aliases.hasMoreElements()) {
			String alias = aliases.nextElement();
			X509Certificate cert = (X509Certificate) ks.getCertificate(alias);
			if (cert != null && bytesToHex(sha1.digest(cert.getEncoded())).equals(targetClean)) {
				return alias;
			}
		}
		return null;
	}

	private String bytesToHex(byte[] bytes) {
		StringBuilder sb = new StringBuilder();
		for (byte b : bytes) sb.append(String.format("%02X", b));
		return sb.toString();
	}
	
	// ========== MÉTODOS HTTP (FASE 2) ==========

	private void enviarConsultaStatus(SSLContext sslContext, String endpoint, String xml) {
		try {
			logger.info("🚀 Enviando consulta para: " + endpoint);
			
			HttpClient client = HttpClient.newBuilder()
				.sslContext(sslContext)
				.connectTimeout(Duration.ofSeconds(30))
				.build();

			HttpRequest request = HttpRequest.newBuilder()
				.uri(URI.create(endpoint))
				.header("Content-Type", "application/soap+xml; charset=utf-8")
				.POST(HttpRequest.BodyPublishers.ofString(xml, StandardCharsets.UTF_8))
				.timeout(Duration.ofSeconds(60))
				.build();

			HttpResponse<String> response = client.send(request, HttpResponse.BodyHandlers.ofString());

			logger.info("📥 Resposta recebida: HTTP " + response.statusCode());
			if (response.statusCode() == 200) {
				logger.info("✅ SUCESSO!");
				logger.info("Tamanho: " + response.body().length() + " bytes");
			} else {
				logger.warning("⚠️ Status diferente de 200: " + response.statusCode());
				logger.warning(response.body());
			}
			
			logger.info("=".repeat(50));
			logger.info("🎉 TESTE CONCLUÍDO!");
			logger.info("=".repeat(50));

		} catch (Exception e) {
			logger.log(Level.SEVERE, "❌ Falha na comunicação HTTP", e);
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

	public static void main(String[] args) {
		SpringApplication.run(MainApplication.class, args);
	}
}
