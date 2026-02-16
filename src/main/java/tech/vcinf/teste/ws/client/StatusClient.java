package tech.vcinf.teste.ws.client;

import javax.net.ssl.SSLContext;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.util.logging.Level;
import java.util.logging.Logger;

/**
 * Cliente HTTP para consulta de status usando mTLS.
 * Usa java.net.http.HttpClient (Java 11+) com SSLContext configurado.
 */
public final class StatusClient {
    
    private static final Logger logger = Logger.getLogger(StatusClient.class.getName());
    private final HttpClient client;
    
    /**
     * Cria um cliente de status com o SSLContext fornecido.
     * 
     * @param sslContext SSLContext configurado para mTLS
     */
    public StatusClient(SSLContext sslContext) {
        if (sslContext == null) {
            throw new IllegalArgumentException("SSLContext não pode ser nulo");
        }
        
        this.client = HttpClient.newBuilder()
            .sslContext(sslContext)
            .connectTimeout(Duration.ofSeconds(30))
            .version(HttpClient.Version.HTTP_1_1)
            .build();
        
        logger.info("StatusClient inicializado com SSLContext customizado");
    }
    
    /**
     * Envia requisição SOAP de consulta de status.
     * 
     * @param endpoint URI do webservice (ex: https://nfe.sefaz.mt.gov.br/nfews/v2/services/NfeStatusServico4)
     * @param xmlBody  Corpo XML da requisição SOAP
     * @return corpo da resposta como String
     * @throws RuntimeException se ocorrer erro na comunicação
     */
    public String consultarStatus(URI endpoint, String xmlBody) {
        try {
            logger.info("Enviando requisição para: " + endpoint);
            logger.fine("Body length: " + xmlBody.length() + " bytes");
            
            HttpRequest request = HttpRequest.newBuilder()
                .uri(endpoint)
                .header("Content-Type", "application/soap+xml; charset=utf-8")
                .header("Accept", "application/soap+xml")
                .POST(HttpRequest.BodyPublishers.ofString(xmlBody, StandardCharsets.UTF_8))
                .timeout(Duration.ofSeconds(60))
                .build();
            
            HttpResponse<String> response = client.send(request, HttpResponse.BodyHandlers.ofString(StandardCharsets.UTF_8));
            
            int statusCode = response.statusCode();
            logger.info("Resposta recebida - HTTP " + statusCode + " - " + response.body().length() + " bytes");
            
            if (statusCode < 200 || statusCode >= 300) {
                logger.warning("HTTP status não-sucesso: " + statusCode);
                logger.warning("Body: " + response.body());
            }
            
            return response.body();
            
        } catch (Exception e) {
            logger.log(Level.SEVERE, "Erro ao consultar status", e);
            throw new RuntimeException("Falha ao consultar status: " + e.getMessage(), e);
        }
    }
    
    /**
     * Envia requisição SOAP de consulta de status (sobrecarga com endpoint como String).
     */
    public String consultarStatus(String endpoint, String xmlBody) {
        try {
            return consultarStatus(URI.create(endpoint), xmlBody);
        } catch (IllegalArgumentException e) {
            throw new IllegalArgumentException("Endpoint inválido: " + endpoint, e);
        }
    }
}
