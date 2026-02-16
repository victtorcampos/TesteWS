package tech.vcinf.teste.ws.test;

import tech.vcinf.teste.ws.cert.PfxConfig;
import tech.vcinf.teste.ws.client.StatusClient;
import tech.vcinf.teste.ws.ssl.ClientSslContextFactory;

import javax.net.ssl.SSLContext;
import java.util.logging.ConsoleHandler;
import java.util.logging.Level;
import java.util.logging.Logger;
import java.util.logging.SimpleFormatter;

/**
 * Teste manual para validar SSLContext com certificado PFX.
 * 
 * Uso:
 *   mvn compile exec:java -Dexec.mainClass="tech.vcinf.teste.ws.test.StatusClientPfxTest" \
 *     -Dpfx.path="C:\\certificado\\407.pfx" \
 *     -Dpfx.password="12345" \
 *     -Dendpoint="https://nfe.sefaz.mt.gov.br/nfews/v2/services/NfeStatusServico4"
 */
public class StatusClientPfxTest {
    
    private static final Logger logger = Logger.getLogger(StatusClientPfxTest.class.getName());
    
    public static void main(String[] args) {
        configurarLog();
        
        try {
            // 1. Obter configurações
            String pfxPath = System.getProperty("pfx.path");
            String pfxPassword = System.getProperty("pfx.password");
            String endpoint = System.getProperty("endpoint");
            
            if (pfxPath == null || pfxPassword == null || endpoint == null) {
                logger.severe("Parâmetros obrigatórios não fornecidos!");
                logger.severe("Use: -Dpfx.path=... -Dpfx.password=... -Dendpoint=...");
                System.exit(1);
            }
            
            logger.info("=== TESTE PFX ===");
            logger.info("Path: " + pfxPath);
            logger.info("Endpoint: " + endpoint);
            
            // 2. Criar configuração
            PfxConfig config = new PfxConfig(pfxPath, pfxPassword.toCharArray());
            
            // 3. Criar SSLContext
            logger.info("Criando SSLContext...");
            SSLContext sslContext = ClientSslContextFactory.from(config);
            logger.info("✅ SSLContext criado com sucesso");
            
            // 4. Criar cliente e executar consulta
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
    
    private static void configurarLog() {
        Logger rootLogger = Logger.getLogger("");
        rootLogger.setLevel(Level.INFO);
        
        ConsoleHandler handler = new ConsoleHandler();
        handler.setLevel(Level.ALL);
        handler.setFormatter(new SimpleFormatter());
        rootLogger.addHandler(handler);
    }
}
