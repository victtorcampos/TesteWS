package tech.vcinf.teste.ws.http;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.IOException;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.file.Paths;
import java.time.Duration;

import javax.net.ssl.SSLContext;

public class RequestClient {
    private static final Logger logger = LoggerFactory.getLogger(RequestClient.class);
    private static final SSLContext sslContext = SslContextUtils.criarContexto(
            "C:/certificado/407.pfx",
            "12345",
            Paths.get("cacerts").toAbsolutePath().toString()

    );
    private static final HttpClient client = HttpClient.newBuilder()
            .version(HttpClient.Version.HTTP_2)
            .connectTimeout(Duration.ofSeconds(10))
            .sslContext(sslContext)
            .build();

    public static void statusServico() {
        String xml = "<?xml version=\"1.0\" encoding=\"utf-8\"?><soap12:Envelope xmlns:xsi=\"http://www.w3.org/2001/XMLSchema-instance\" xmlns:xsd=\"http://www.w3.org/2001/XMLSchema\" xmlns:soap12=\"http://www.w3.org/2003/05/soap-envelope\"><soap12:Body><nfeDadosMsg xmlns=\"http://www.portalfiscal.inf.br/nfe/wsdl/NFeStatusServico4\"><consStatServ xmlns=\"http://www.portalfiscal.inf.br/nfe\" versao=\"4.00\"><tpAmb>1</tpAmb><cUF>51</cUF><xServ>STATUS</xServ></consStatServ></nfeDadosMsg></soap12:Body></soap12:Envelope>";

        HttpRequest request = HttpRequest.newBuilder()
                .uri(URI.create("https://nfe.sefaz.mt.gov.br/nfews/v2/services/NfeStatusServico4"))
                .timeout(Duration.ofSeconds(20))
                .header("Content-Type", "application/soap+xml; charset=utf-8")
                .POST(HttpRequest.BodyPublishers.ofString(xml))
                .build();
        HttpResponse<String> response = null;
        try {
            response = HttpClient.newHttpClient().send(request, HttpResponse.BodyHandlers.ofString());
            if (response.statusCode() == 200) {
                logger.info("Sucesso! Resposta: {}", response.body());
            } else {
                logger.warn("Atenção! Status: {} - Body: {}", response.statusCode(), response.body());
            }
        } catch (IOException e) {
            logger.error("Erro ao enviar requisição HTTP: {}", e.getMessage());
        } catch (InterruptedException e) {
            logger.error("Erro ao interromper requisição HTTP: {}", e.getMessage());
        }
        logger.info("Resposta HTTP: {}", response.statusCode());
        logger.info("Corpo da resposta: {}", response.body());

    }

}
