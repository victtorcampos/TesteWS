package tech.vcinf.teste.ws.test;

import tech.vcinf.teste.ws.Ssl.ClientSslContextFactory;
import tech.vcinf.teste.ws.cert.WindowsMyConfig;
import tech.vcinf.teste.ws.client.StatusClient;

import javax.net.ssl.SSLContext;
import java.util.logging.ConsoleHandler;
import java.util.logging.Level;
import java.util.logging.Logger;
import java.util.logging.SimpleFormatter;

/**
 * Teste manual para validar SSLContext com certificado do Windows Certificate
 * Store.
 * 
 * ⚠️ SÓ EXECUTA EM WINDOWS!
 * 
 * Uso:
 * mvn compile exec:java
 * -Dexec.mainClass="tech.vcinf.teste.ws.test.StatusClientWindowsMyTest" \
 * -Dcert.thumbprint="C48514B5EDF842D34C322A1AAFAF8F6FDA3117A7" \
 * -Dendpoint="https://nfe.sefaz.mt.gov.br/nfews/v2/services/NfeStatusServico4"
 */
public class StatusClientWindowsMyTest {

    private static final Logger logger = Logger.getLogger(StatusClientWindowsMyTest.class.getName());

    public static void main(String[] args) {
        configurarLog();

        try {
            // 1. Verificar sistema operacional
            String os = System.getProperty("os.name").toLowerCase();
            if (!os.contains("win")) {
                logger.severe("❌ Este teste só pode rodar em Windows!");
                logger.severe("Sistema operacional detectado: " + os);
                System.exit(1);
            }

            // 2. Obter configurações
            String thumbprint = System.getProperty("cert.thumbprint");
            String endpoint = System.getProperty("endpoint");

            if (thumbprint == null || endpoint == null) {
                logger.severe("Parâmetros obrigatórios não fornecidos!");
                logger.severe("Use: -Dcert.thumbprint=... -Dendpoint=...");
                System.exit(1);
            }

            logger.info("=== TESTE WINDOWS-MY ===");
            logger.info("Thumbprint: " + thumbprint);
            logger.info("Endpoint: " + endpoint);

            // 3. Criar configuração
            WindowsMyConfig config = new WindowsMyConfig(thumbprint);

            // 4. Criar SSLContext
            logger.info("Criando SSLContext do Windows Store...");
            SSLContext sslContext = ClientSslContextFactory.from(config);
            logger.info("✅ SSLContext criado com sucesso");

            // 5. Criar cliente e executar consulta
            StatusClient client = new StatusClient(sslContext);
            String xmlBody = criarXmlConsultaStatus();

            logger.info("Enviando consulta de status...");
            String resposta = client.consultarStatus(endpoint, xmlBody);

            logger.info("✅ Resposta recebida com sucesso!");
            logger.info("Tamanho da resposta: " + resposta.length() + " bytes");
            logger.fine("Resposta: " + resposta);

            System.exit(0);

        } catch (Exception e) {
            logger.log(Level.SEVERE, "❌ TESTE FALHOU", e);
            System.exit(1);
        }
    }

    private static String criarXmlConsultaStatus() {
        return "<?xml version=\"1.0\" encoding=\"utf-8\"?><soap12:Envelope xmlns:xsi=\"http://www.w3.org/2001/XMLSchema-instance\" xmlns:xsd=\"http://www.w3.org/2001/XMLSchema\" xmlns:soap12=\"http://www.w3.org/2003/05/soap-envelope\"><soap12:Body><nfeDadosMsg xmlns=\"http://www.portalfiscal.inf.br/nfe/wsdl/NFeStatusServico4\"><consStatServ xmlns=\"http://www.portalfiscal.inf.br/nfe\" versao=\"4.00\"><tpAmb>1</tpAmb><cUF>51</cUF><xServ>STATUS</xServ></consStatServ></nfeDadosMsg></soap12:Body></soap12:Envelope>";
    }

    private static void configurarLog() {
        Logger rootLogger = Logger.getLogger("");
        rootLogger.setLevel(Level.INFO);

        ConsoleHandler handler = new ConsoleHandler();
        handler.setLevel(Level.ALL);
        handler.setFormatter(new SimpleFormatter());
        rootLogger.addHandler(handler);
    }
}
