package tech.vcinf.teste.ws;

import org.springframework.boot.ApplicationArguments;
import org.springframework.boot.ApplicationRunner;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;

import javax.net.ssl.*;
import javax.xml.crypto.dsig.*;
import javax.xml.crypto.dsig.dom.DOMSignContext;
import javax.xml.crypto.dsig.keyinfo.KeyInfo;
import javax.xml.crypto.dsig.keyinfo.KeyInfoFactory;
import javax.xml.crypto.dsig.spec.C14NMethodParameterSpec;
import javax.xml.crypto.dsig.spec.TransformParameterSpec;
import javax.xml.parsers.DocumentBuilderFactory;
import javax.xml.transform.OutputKeys;
import javax.xml.transform.Transformer;
import javax.xml.transform.TransformerFactory;
import javax.xml.transform.dom.DOMSource;
import javax.xml.transform.stream.StreamResult;
import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.w3c.dom.NodeList;
import org.xml.sax.InputSource;

import java.io.*;
import java.net.URI;
import java.net.URL;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.*;
import java.security.cert.Certificate;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.time.Duration;
import java.util.*;
import java.util.logging.*;
import java.util.logging.Formatter;
import java.util.zip.GZIPInputStream;
import java.util.zip.GZIPOutputStream;

/**
 * MainApplication - Utilitário de Teste para Comunicação SEFAZ e Assinatura
 * XML.
 * 
 * Funcionalidades:
 * 1. Geração Automática de TrustStore (Cadeias ICP-Brasil e Servidores SEFAZ)
 * 2. Autenticação mTLS (Windows-MY ou Arquivo PFX)
 * 3. Assinatura Digital XML (Padrão DSig Enveloped)
 * - Suporte a NFe/CTe (SHA-1) e Reinf/eSocial (SHA-256)
 * - Normalização automática de ID (id, Id, ID)
 * 
 * Uso: Apenas para ambiente de DESENVOLVIMENTO e TESTE.
 */
@SpringBootApplication
public class MainApplication implements ApplicationRunner {

    // --- CONFIGURAÇÃO CENTRALIZADA ---
    static class Config {
        // [TOGGLE] Define a origem do certificado: TRUE = Windows Keystore, FALSE =
        // Arquivo PFX
        static final boolean USE_WINDOWS_KEYSTORE = false;

        // Configuração PFX (Arquivo)
        static final String PFX_PATH = "C:/certificado/129.pfx";
        static final String PFX_PASS = "12345";

        // Configuração Windows-MY (Thumbprint/Hash SHA-1)
        static final String WIN_THUMB = "4B753DC532B07E78686A113F90AED1960074AEEA";

        // Endpoints e Arquivos
        static final String ENDPOINT_NFE_STATUS = "https://nfe.sefaz.mt.gov.br/nfews/v2/services/NfeStatusServico4";
        static final String ENDPOINT_CTE_STATUS = "https://cte.sefaz.mt.gov.br/ctews2/services/CTeStatusServicoV4";
        static final String ENDPOINT_NFCE_STATUS = "https://nfce.sefaz.mt.gov.br/nfcews/services/NfeStatusServico4";
        static final String ENDPOINT_MDFE_STATUS = "https://mdfe.svrs.rs.gov.br/ws/MDFeStatusServico/MDFeStatusServico.asmx";
        static final String ENDPOINT_NFSE_DFE = "https://adn.nfse.gov.br/adn/DFe";// "https://adn.nfse.gov.br/DFe";
        static final String ENDPOINT_NFSE_CONTRIBUINTE_DFE = "https://adn.nfse.gov.br/contribuintes/DFe/000000000000001";
        static final String TRUSTSTORE_FILENAME = "cacerts_vcinf";
        static final String TRUSTSTORE_PASS = "changeit";

    }

    private static final Logger log = Logger.getLogger(MainApplication.class.getName());

    public static void main(String[] args) {
        // Configura logger limpo antes de subir o Spring
        configureCleanLogger();
        SpringApplication.run(MainApplication.class, args);
    }

    @Override
    public void run(ApplicationArguments args) {
        log.info(">>> INICIANDO AMBIENTE DE TESTES SEFAZ/JAVA <<<");

        try {
            // 1. GARANTIR TRUSTSTORE (Cadeias de Confiança)
            SecurityContextService.ensureTrustStore();

            // 2. CARREGAR IDENTIDADE (Chave Privada e Certificado)
            KeyStore.PrivateKeyEntry keyEntry;
            SSLContext sslContext;

            if (Config.USE_WINDOWS_KEYSTORE) {
                log.info("MODO: Certificado do Repositório Windows (Windows-MY)");
                keyEntry = SecurityContextService.loadWindowsKeyEntry(Config.WIN_THUMB);
                sslContext = SecurityContextService.createWindowsSslContext(keyEntry);
            } else {
                log.info("MODO: Certificado em Arquivo PFX");
                keyEntry = SecurityContextService.loadPfxKeyEntry(Config.PFX_PATH, Config.PFX_PASS);
                sslContext = SecurityContextService.createPfxSslContext(keyEntry);
            }

            // 3. TESTAR CONEXÃO MTLS (Consumo de WebService)
            log.info(">>> TESTE 1.0: Conexão mTLS (Nfe StatusServico ) <<<");
            WebServiceClient.testConsultaStatusNfe(sslContext);

            log.info(">>> TESTE 1.1: Conexão mTLS (Cte StatusServico ) <<<");
            WebServiceClient.testConsultaStatusCte(sslContext);

            log.info(">>> TESTE 1.2: Conexão mTLS (Nfce StatusServico ) <<<");
            WebServiceClient.testConsultaStatusNfce(sslContext);

            log.info(">>> TESTE 1.3: Conexão mTLS (Nfce StatusServico ) <<<");
            WebServiceClient.testConsultaStatusNfce(sslContext);

            log.info(">>> TESTE 1.4: Conexão mTLS (Mdfe StatusServico ) <<<");
            WebServiceClient.testConsultaStatusMdfe(sslContext);

            log.info(">>> TESTE 1.5: Conexão mTLS (NFSe DFe ) <<<");
            WebServiceClient.testNFSeDFe(sslContext);

            log.info(">>> TESTE 1.6: Conexão mTLS (Consulta Reinf) <<<");
            WebServiceClient.testReinfGet(sslContext,
                    "https://reinf.receita.economia.gov.br/consulta/lotes/1.202512.744590511");

            // 4. TESTAR ASSINATURA XML
            log.info(">>> TESTE 2: Assinatura Digital de XMLs <<<");

            // Teste NFe (SHA-1, Id CamelCase)
            processarAssinatura("NFe", FiscalDocumentRepository.getXmlNFe(), keyEntry);

            // Teste NFCe (SHA-1, Id CamelCase)
            processarAssinatura("NFCe", FiscalDocumentRepository.getXmlNFCe(), keyEntry);

            // Teste Reinf (SHA-256, id lowercase)
            processarAssinatura("Reinf", FiscalDocumentRepository.getXmlEfdReinf(), keyEntry);

            log.info(">>> FIM DO PROCESSAMENTO COM SUCESSO <<<");

        } catch (Exception e) {
            log.severe("ERRO FATAL NA APLICAÇÃO: " + e.getMessage());
            e.printStackTrace(); // Útil em dev para ver stacktrace completo
        }
    }

    private void processarAssinatura(String tipo, String xmlBruto, KeyStore.PrivateKeyEntry keyEntry) throws Exception {
        log.info("--- Assinando " + tipo + " ---");
        String xmlAssinado = XmlSignerService.sign(xmlBruto, keyEntry);

        // Salva arquivo
        String idDoc = XmlSignerService.extractIdFromSignedXml(xmlAssinado);
        String filename = tipo + "_" + (idDoc.isEmpty() ? System.currentTimeMillis() : idDoc) + ".xml";
        Path path = Paths.get(filename);
        Files.writeString(path, xmlAssinado, StandardCharsets.UTF_8);

        log.info("Arquivo salvo: " + path.toAbsolutePath());
    }

    // --- SERVIÇO DE SEGURANÇA (SSL, KEYSTORE, TRUSTSTORE) ---
    static class SecurityContextService {

        static void ensureTrustStore() throws Exception {
            File trustFile = new File(Config.TRUSTSTORE_FILENAME);
            if (trustFile.exists()) {
                log.info("TrustStore encontrado: " + Config.TRUSTSTORE_FILENAME);
                return; // Em produção real, validaria a idade do arquivo
            }

            log.info("Gerando TrustStore dinâmico...");
            KeyStore ks = KeyStore.getInstance(KeyStore.getDefaultType());
            Path javaCacerts = Paths.get(System.getProperty("java.home"), "lib", "security", "cacerts");

            try (InputStream is = Files.newInputStream(javaCacerts)) {
                ks.load(is, "changeit".toCharArray());
            }

            // Importa Raízes ICP-Brasil
            CertificateFactory cf = CertificateFactory.getInstance("X.509");
            List.of("v10", "v5", "v2").forEach(v -> {
                try (InputStream in = new URL(
                        "http://acraiz.icpbrasil.gov.br/credenciadas/RAIZ/ICP-Brasil" + v + ".crt").openStream()) {
                    ks.setCertificateEntry("icp-brasil-" + v, (X509Certificate) cf.generateCertificate(in));
                } catch (Exception e) {
                    log.warning("Falha baixar ICP-Brasil " + v + ": " + e.getMessage());
                }
            });

            // Captura Cadeia SEFAZ (SSL Handshake Grã-Fino)
            capturarCadeiaRemota("nfe.sefaz.mt.gov.br", ks);
            capturarCadeiaRemota("nfce.sefaz.mt.gov.br", ks);
            capturarCadeiaRemota("cte.sefaz.mt.gov.br", ks);
            capturarCadeiaRemota("adn.producaorestrita.nfse.gov.br", ks);
            capturarCadeiaRemota("adn.nfse.gov.br", ks);
            capturarCadeiaRemota("reinf.receita.economia.gov.br", ks);

            try (OutputStream os = Files.newOutputStream(trustFile.toPath())) {
                ks.store(os, Config.TRUSTSTORE_PASS.toCharArray());
            }
            log.info("TrustStore gerado com sucesso.");
        }

        private static void capturarCadeiaRemota(String host, KeyStore ks) {
            try {
                SSLContext ctx = SSLContext.getInstance("TLSv1.2");
                CapturingTrustManager ctm = new CapturingTrustManager();
                ctx.init(null, new TrustManager[] { ctm }, null);

                try (SSLSocket s = (SSLSocket) ctx.getSocketFactory().createSocket(host, 443)) {
                    s.setSoTimeout(5000);
                    SSLParameters p = s.getSSLParameters();
                    p.setServerNames(List.of(new SNIHostName(host)));
                    s.setSSLParameters(p);
                    s.startHandshake();
                } catch (IOException ignored) {
                } // Handshake falha propositalmente, mas captura a cadeia

                if (ctm.chain != null) {
                    for (int i = 0; i < ctm.chain.length; i++) {
                        ks.setCertificateEntry(host + "-chain-" + i, ctm.chain[i]);
                    }
                    log.info("Capturados " + ctm.chain.length + " certificados de " + host);
                }
            } catch (Exception e) {
                log.warning("Erro capturando cadeia de " + host + ": " + e.getMessage());
            }
        }

        // --- CARREGAMENTO DE CHAVES ---

        static KeyStore.PrivateKeyEntry loadPfxKeyEntry(String path, String pass) throws Exception {
            KeyStore ks = KeyStore.getInstance("PKCS12");
            try (InputStream in = Files.newInputStream(Paths.get(path))) {
                ks.load(in, pass.toCharArray());
            }
            return getKeyEntryFromStore(ks, pass);
        }

        static KeyStore.PrivateKeyEntry loadWindowsKeyEntry(String thumbprint) throws Exception {
            // Força o uso do provider SunMSCAPI para garantir compatibilidade nativa
            KeyStore ks = KeyStore.getInstance("Windows-MY", "SunMSCAPI");
            ks.load(null, null);

            String alias = findAliasByThumbprint(ks, thumbprint);
            if (alias == null)
                throw new RuntimeException("Certificado não encontrado no Windows: " + thumbprint);

            // CORREÇÃO: Usar getKey() em vez de getEntry()
            // O parâmetro de senha null aqui sinaliza ao Windows para usar a autenticação
            // nativa
            PrivateKey privateKey = (PrivateKey) ks.getKey(alias, null);

            if (privateKey == null) {
                throw new RuntimeException("Acesso à chave privada negado ou não encontrada.");
            }

            // Remonta a entrada manualmente
            java.security.cert.Certificate[] chain = ks.getCertificateChain(alias);
            return new KeyStore.PrivateKeyEntry(privateKey, chain);
        }

        static SSLContext createPfxSslContext(KeyStore.PrivateKeyEntry keyEntry) throws Exception {
            return createSslContextGeneric(keyEntry, Config.PFX_PASS);
        }

        // Método ESPECÍFICO para Windows (Evita cópia de chave)
        static SSLContext createWindowsSslContext(KeyStore.PrivateKeyEntry keyEntry) throws Exception {
            // 1. Carrega o KeyStore Windows-MY original (não crie um novo em memória)
            KeyStore windowsKs = KeyStore.getInstance("Windows-MY", "SunMSCAPI");
            windowsKs.load(null, null);

            // 2. Inicializa o KeyManagerFactory com o KeyStore do Windows completo
            KeyManagerFactory kmf = KeyManagerFactory.getInstance("SunX509");
            kmf.init(windowsKs, null); // Windows não usa senha aqui

            // 3. (Opcional) Se quiser forçar o alias específico, precisaria de um Wrapper
            // aqui.
            // Para este teste, vamos confiar que o KMF padrão vai encontrar a chave
            // ou que só existe um certificado válido de cliente.

            // Mas, como já temos o 'keyEntry' validado anteriormente (sabemos que existe e
            // tem acesso),
            // o uso direto do windowsKs é seguro.

            // 4. Carrega TrustStore (Cadeia de Confiança)
            KeyStore trust = KeyStore.getInstance(KeyStore.getDefaultType());
            try (InputStream in = Files.newInputStream(Paths.get(Config.TRUSTSTORE_FILENAME))) {
                trust.load(in, Config.TRUSTSTORE_PASS.toCharArray());
            }
            TrustManagerFactory tmf = TrustManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm());
            tmf.init(trust);

            SSLContext ctx = SSLContext.getInstance("TLSv1.2");
            ctx.init(kmf.getKeyManagers(), tmf.getTrustManagers(), null);
            return ctx;
        }

        private static SSLContext createSslContextGeneric(KeyStore.PrivateKeyEntry keyEntry, String pass)
                throws Exception {
            // Cria um KeyStore em memória apenas com a chave selecionada
            KeyStore identity = KeyStore.getInstance(KeyStore.getDefaultType());
            identity.load(null, null);
            identity.setKeyEntry("identity", keyEntry.getPrivateKey(), (pass != null ? pass.toCharArray() : null),
                    keyEntry.getCertificateChain());

            KeyManagerFactory kmf = KeyManagerFactory.getInstance("SunX509");
            kmf.init(identity, (pass != null ? pass.toCharArray() : null));

            // Carrega TrustStore
            KeyStore trust = KeyStore.getInstance(KeyStore.getDefaultType());
            try (InputStream in = Files.newInputStream(Paths.get(Config.TRUSTSTORE_FILENAME))) {
                trust.load(in, Config.TRUSTSTORE_PASS.toCharArray());
            }
            TrustManagerFactory tmf = TrustManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm());
            tmf.init(trust);

            SSLContext ctx = SSLContext.getInstance("TLSv1.2");
            ctx.init(kmf.getKeyManagers(), tmf.getTrustManagers(), null);
            return ctx;
        }

        // --- AUXILIARES ---

        private static KeyStore.PrivateKeyEntry getKeyEntryFromStore(KeyStore ks, String pass) throws Exception {
            Enumeration<String> aliases = ks.aliases();
            while (aliases.hasMoreElements()) {
                String alias = aliases.nextElement();
                if (ks.isKeyEntry(alias)) {
                    return (KeyStore.PrivateKeyEntry) ks.getEntry(alias,
                            new KeyStore.PasswordProtection(pass.toCharArray()));
                }
            }
            throw new RuntimeException("Nenhuma chave privada encontrada no KeyStore.");
        }

        private static String findAliasByThumbprint(KeyStore ks, String thumb) throws Exception {
            String target = thumb.replaceAll("[^0-9A-Fa-f]", "").toUpperCase();
            MessageDigest sha1 = MessageDigest.getInstance("SHA-1");
            Enumeration<String> aliases = ks.aliases();
            while (aliases.hasMoreElements()) {
                String alias = aliases.nextElement();
                X509Certificate c = (X509Certificate) ks.getCertificate(alias);
                if (c != null) {
                    byte[] digest = sha1.digest(c.getEncoded());
                    StringBuilder sb = new StringBuilder();
                    for (byte b : digest)
                        sb.append(String.format("%02X", b));
                    if (sb.toString().equals(target))
                        return alias;
                }
            }
            return null;
        }

        private static class CapturingTrustManager implements X509TrustManager {
            X509Certificate[] chain;

            public void checkServerTrusted(X509Certificate[] c, String a) {
                this.chain = c;
            }

            public void checkClientTrusted(X509Certificate[] c, String a) {
            }

            public X509Certificate[] getAcceptedIssuers() {
                return new X509Certificate[0];
            }
        }
    }

    // --- SERVIÇO DE ASSINATURA XML (DSIG) ---
    static class XmlSignerService {

        static String sign(String xmlBruto, KeyStore.PrivateKeyEntry keyEntry) throws Exception {
            // 1. Parse
            DocumentBuilderFactory dbf = DocumentBuilderFactory.newInstance();
            dbf.setNamespaceAware(true);
            Document doc = dbf.newDocumentBuilder().parse(new InputSource(new StringReader(xmlBruto)));

            // 2. Descobrir Elemento
            Element toSign = findElementToSign(doc);

            // 3. Normalizar ID (id, Id, ID)
            String idAttributeName = normalizeIdAttribute(toSign);
            String idValue = toSign.getAttribute(idAttributeName);

            // 4. Definir Algoritmo (Strategy)
            String digestMethod;
            String signatureMethod;

            // Regra: Reinf/eSocial = SHA256, Outros (NFe/CTe) = SHA1
            if (toSign.getNodeName().startsWith("evt") || toSign.getNodeName().startsWith("eSocial")) {
                digestMethod = DigestMethod.SHA256;
                signatureMethod = "http://www.w3.org/2001/04/xmldsig-more#rsa-sha256";
            } else {
                digestMethod = DigestMethod.SHA1;
                signatureMethod = SignatureMethod.RSA_SHA1;
            }

            // 5. Preparar Assinatura
            XMLSignatureFactory factory = XMLSignatureFactory.getInstance("DOM");

            // Contexto: Assinatura deve ser IRMÃ do elemento assinado (dentro do pai)
            DOMSignContext dsc = new DOMSignContext(keyEntry.getPrivateKey(), toSign.getParentNode());

            List<javax.xml.crypto.dsig.Transform> transforms = new ArrayList<>();
            transforms.add(
                    factory.newTransform(javax.xml.crypto.dsig.Transform.ENVELOPED, (TransformParameterSpec) null));
            transforms.add(factory.newTransform("http://www.w3.org/TR/2001/REC-xml-c14n-20010315",
                    (TransformParameterSpec) null));

            Reference ref = factory.newReference("#" + idValue,
                    factory.newDigestMethod(digestMethod, null),
                    transforms, null, null);

            SignedInfo si = factory.newSignedInfo(
                    factory.newCanonicalizationMethod(CanonicalizationMethod.INCLUSIVE, (C14NMethodParameterSpec) null),
                    factory.newSignatureMethod(signatureMethod, null),
                    Collections.singletonList(ref));

            KeyInfoFactory kif = factory.getKeyInfoFactory();
            KeyInfo ki = kif.newKeyInfo(
                    Collections.singletonList(kif.newX509Data(Collections.singletonList(keyEntry.getCertificate()))));

            // 6. Assinar
            XMLSignature signature = factory.newXMLSignature(si, ki);
            signature.sign(dsc);

            // 7. Serializar
            return convertDocumentToString(doc);
        }

        private static Element findElementToSign(Document doc) {
            String[] targetTags = { "infNFe", "infCte", "infNFSe", "evtFechaEvPer", "evtInfoEmpregador", "Reinf" };
            NodeList all = doc.getElementsByTagName("*");
            for (int i = 0; i < all.getLength(); i++) {
                Element el = (Element) all.item(i);
                for (String tag : targetTags) {
                    if (el.getNodeName().startsWith(tag) || el.getNodeName().startsWith("evt")) {
                        if (el.hasAttribute("Id") || el.hasAttribute("id") || el.hasAttribute("ID")) {
                            return el;
                        }
                    }
                }
            }
            throw new RuntimeException("Nenhum elemento assinável encontrado no XML.");
        }

        private static String normalizeIdAttribute(Element el) {
            String[] possibilities = { "id", "Id", "ID" };
            for (String attr : possibilities) {
                if (el.hasAttribute(attr)) {
                    el.setIdAttribute(attr, true);
                    return attr;
                }
            }
            throw new IllegalArgumentException("Elemento " + el.getNodeName() + " sem atributo ID válido.");
        }

        private static String convertDocumentToString(Document doc) throws Exception {
            Transformer tf = TransformerFactory.newInstance().newTransformer();
            tf.setOutputProperty(OutputKeys.INDENT, "no"); // Essencial para não quebrar hash
            StringWriter writer = new StringWriter();
            tf.transform(new DOMSource(doc), new StreamResult(writer));
            return writer.toString();
        }

        static String extractIdFromSignedXml(String xml) {
            // Regex simples apenas para extrair nome de arquivo, não usado na lógica de
            // assinatura
            java.util.regex.Matcher m = java.util.regex.Pattern.compile("(?:Id|id|ID)=\"([^\"]+)\"").matcher(xml);
            return m.find() ? m.group(1) : "";
        }
    }

    // --- CLIENTE WEB (TESTE) ---
    static class WebServiceClient {
        record ProcessamentoResult(String ultNSU, int qtdDocumentos) {
        }

        static void testConsultaStatusNfe(SSLContext ctx) {
            try {
                HttpClient client = HttpClient.newBuilder()
                        .sslContext(ctx)
                        .connectTimeout(Duration.ofSeconds(10))
                        .build();

                HttpRequest req = HttpRequest.newBuilder()
                        .uri(URI.create(Config.ENDPOINT_NFE_STATUS))
                        .header("Content-Type", "application/soap+xml; charset=utf-8")
                        .POST(HttpRequest.BodyPublishers.ofString(
                                FiscalDocumentRepository.getXml_ConsultaStatusNfe(),
                                StandardCharsets.UTF_8))
                        .build();

                HttpResponse<String> res = client.send(req, HttpResponse.BodyHandlers.ofString());
                log.info("STATUS WEBSERVICE: HTTP " + res.statusCode());
                if (res.statusCode() != 200) {
                    log.warning("Resposta Diferente de 200: " + res.body());
                }
            } catch (Exception e) {
                log.severe("FALHA NA CONEXÃO WEBSERVICE: " + e.getMessage());
            }
        }

        public static void testNFSeDFe(SSLContext sslContext) {
            try {
                HttpClient client = HttpClient.newBuilder()
                        .sslContext(sslContext)
                        .connectTimeout(Duration.ofSeconds(10))
                        .build();

                HttpRequest req = HttpRequest.newBuilder()
                        .uri(URI.create(Config.ENDPOINT_NFSE_CONTRIBUINTE_DFE))
                        .header("Accept", "application/json")
                        .GET()
                        .build();

                HttpResponse<String> res = client.send(req, HttpResponse.BodyHandlers.ofString());

                log.info("STATUS WEBSERVICE: HTTP " + res.statusCode());
                if (res.statusCode() != 200) {
                    log.warning("Resposta Diferente de 200: " + res.body());
                }

                String body = res.body();

                try {
                    String busca = "\"ArquivoXml\":\"";
                    int inicio = body.indexOf(busca) + busca.length();
                    int fim = body.indexOf("\"", inicio);
                    String base64Gzip = body.substring(inicio, fim);

                    // 2. Decode Base64
                    byte[] comprimido = java.util.Base64.getDecoder().decode(base64Gzip);

                    // 3. Decompressão GZIP (Nativo Java)
                    try (java.util.zip.GZIPInputStream gis = new java.util.zip.GZIPInputStream(
                            new java.io.ByteArrayInputStream(comprimido));
                            java.io.ByteArrayOutputStream baos = new java.io.ByteArrayOutputStream()) {

                        byte[] buffer = new byte[1024];
                        int len;
                        while ((len = gis.read(buffer)) > 0) {
                            baos.write(buffer, 0, len);
                        }

                        String xmlFinal = baos.toString("UTF-8");
                        log.info("XML DECODIFICADO: " + xmlFinal);
                    }
                } catch (Exception e) {
                    log.severe("Erro ao processar conteúdo: " + e.getMessage());
                }
            } catch (Exception e) {
                log.severe("FALHA NA CONEXÃO WEBSERVICE: " + e.getMessage());
            }
        }

        public static void testConsultaStatusMdfe(SSLContext sslContext) {
            try {
                HttpClient client = HttpClient.newBuilder()
                        .sslContext(sslContext)
                        .connectTimeout(Duration.ofSeconds(10))
                        .build();

                HttpRequest req = HttpRequest.newBuilder()
                        .uri(URI.create(Config.ENDPOINT_MDFE_STATUS))
                        .header("Content-Type", "application/soap+xml; charset=utf-8")
                        .POST(HttpRequest.BodyPublishers.ofString(
                                FiscalDocumentRepository.getXml_ConsultaStatusMdfe(),
                                StandardCharsets.UTF_8))
                        .build();

                HttpResponse<String> res = client.send(req, HttpResponse.BodyHandlers.ofString());
                log.info("STATUS WEBSERVICE: HTTP " + res.statusCode());
                if (res.statusCode() != 200) {
                    log.warning("Resposta Diferente de 200: " + res.body());
                }
            } catch (Exception e) {
                log.severe("FALHA NA CONEXÃO WEBSERVICE: " + e.getMessage());
            }
        }

        public static void testConsultaStatusNfce(SSLContext sslContext) {
            try {
                HttpClient client = HttpClient.newBuilder()
                        .sslContext(sslContext)
                        .connectTimeout(Duration.ofSeconds(10))
                        .build();

                HttpRequest req = HttpRequest.newBuilder()
                        .uri(URI.create(Config.ENDPOINT_NFCE_STATUS))
                        .header("Content-Type", "application/soap+xml; charset=utf-8")
                        .POST(HttpRequest.BodyPublishers.ofString(
                                FiscalDocumentRepository.getXml_ConsultaStatusNfce(),
                                StandardCharsets.UTF_8))
                        .build();

                HttpResponse<String> res = client.send(req, HttpResponse.BodyHandlers.ofString());
                log.info("STATUS WEBSERVICE: HTTP " + res.statusCode());
                if (res.statusCode() != 200) {
                    log.warning("Resposta Diferente de 200: " + res.body());
                }
            } catch (Exception e) {
                log.severe("FALHA NA CONEXÃO WEBSERVICE: " + e.getMessage());
            }
        }

        public static void testConsultaStatusCte(SSLContext sslContext) {
            try {
                HttpClient client = HttpClient.newBuilder()
                        .sslContext(sslContext)
                        .connectTimeout(Duration.ofSeconds(10))
                        .build();

                HttpRequest req = HttpRequest.newBuilder()
                        .uri(URI.create(Config.ENDPOINT_CTE_STATUS))
                        .header("Content-Type", "application/soap+xml; charset=utf-8")
                        .POST(HttpRequest.BodyPublishers.ofString(
                                FiscalDocumentRepository.getXml_ConsultaStatusCte(),
                                StandardCharsets.UTF_8))
                        .build();

                HttpResponse<String> res = client.send(req, HttpResponse.BodyHandlers.ofString());
                log.info("STATUS WEBSERVICE: HTTP " + res.statusCode());
                if (res.statusCode() != 200) {
                    log.warning("Resposta Diferente de 200: " + res.body());
                }
            } catch (Exception e) {
                log.severe("FALHA NA CONEXÃO WEBSERVICE: " + e.getMessage());
            }
        }

        static void testReinfGet(SSLContext ctx, String url) {
            log.info("[GET] Testando Consulta Reinf: " + url);
            try {
                HttpClient client = HttpClient.newBuilder()
                        .sslContext(ctx)
                        .connectTimeout(Duration.ofSeconds(15)) // Reinf as vezes é lento
                        .build();

                HttpRequest req = HttpRequest.newBuilder()
                        .uri(URI.create(url))
                        .GET()
                        .build();

                HttpResponse<String> res = client.send(req, HttpResponse.BodyHandlers.ofString());

                log.info("STATUS Reinf: HTTP " + res.statusCode());
                log.info("Corpo Resposta (Snippet): " +
                        res.body().substring(0, Math.min(res.body().length(), 200)).replace("\n", " "));

            } catch (Exception e) {
                log.severe("FALHA Reinf: " + e.getMessage());
                // Dica de troubleshooting comum para Reinf
                if (e.getMessage().contains("PKIX")) {
                    log.warning(
                            "DICA: Verifique se a cadeia 'reinf.receita.economia.gov.br' foi capturada no TrustStore.");
                }
            }
        }

    }

    // --- REPOSITÓRIO (MOCKS) ---
    static class FiscalDocumentRepository {
        static String getXml_ConsultaStatusNfe() {
            return "<?xml version=\"1.0\" encoding=\"utf-8\"?><soap12:Envelope xmlns:soap12=\"http://www.w3.org/2003/05/soap-envelope\"><soap12:Body><nfeDadosMsg xmlns=\"http://www.portalfiscal.inf.br/nfe/wsdl/NFeStatusServico4\"><consStatServ xmlns=\"http://www.portalfiscal.inf.br/nfe\" versao=\"4.00\"><tpAmb>1</tpAmb><cUF>51</cUF><xServ>STATUS</xServ></consStatServ></nfeDadosMsg></soap12:Body></soap12:Envelope>";
        }

        static String getXml_ConsultaStatusNfce() {
            return "<soap12:Envelope xmlns:soap12=\"http://www.w3.org/2003/05/soap-envelope\"><soap12:Body><nfeDadosMsg xmlns=\"http://www.portalfiscal.inf.br/nfe/wsdl/NFeStatusServico4\"><consStatServ xmlns=\"http://www.portalfiscal.inf.br/nfe\" versao=\"4.00\"><tpAmb>1</tpAmb><cUF>51</cUF><xServ>STATUS</xServ></consStatServ></nfeDadosMsg></soap12:Body></soap12:Envelope>";
        }

        static String getXml_ConsultaStatusMdfe() {
            return "<soap12:Envelope xmlns:soap12=\"http://www.w3.org/2003/05/soap-envelope\" xmlns:wsdl=\"http://www.portalfiscal.inf.br/mdfe/wsdl/MDFeStatusServico\"><soap12:Header><wsdl:mdfeCabecMsg><wsdl:cUF>51</wsdl:cUF><wsdl:versaoDados>3.00</wsdl:versaoDados></wsdl:mdfeCabecMsg></soap12:Header><soap12:Body><wsdl:mdfeDadosMsg><consStatServMDFe xmlns=\"http://www.portalfiscal.inf.br/mdfe\" versao=\"3.00\"><tpAmb>1</tpAmb><xServ>STATUS</xServ></consStatServMDFe></wsdl:mdfeDadosMsg></soap12:Body></soap12:Envelope>";
        }

        static String getXml_ConsultaStatusCte() {
            return "<?xml version=\"1.0\" encoding=\"utf-8\"?><soap12:Envelope xmlns:xsi=\"http://www.w3.org/2001/XMLSchema-instance\" xmlns:xsd=\"http://www.w3.org/2001/XMLSchema\" xmlns:soap12=\"http://www.w3.org/2003/05/soap-envelope\"><soap12:Body><cteDadosMsg xmlns=\"http://www.portalfiscal.inf.br/cte/wsdl/CTeStatusServicoV4\"><consStatServCTe versao=\"4.00\" xmlns=\"http://www.portalfiscal.inf.br/cte\"><tpAmb>1</tpAmb><cUF>51</cUF><xServ>STATUS</xServ></consStatServCTe></cteDadosMsg></soap12:Body></soap12:Envelope>";
        }

        static String getXmlNFe() {
            return "<NFe xmlns=\"http://www.portalfiscal.inf.br/nfe\"><infNFe Id=\"NFe51260200053960793987559200000073941594056729\" versao=\"4.00\"><ide><cUF>51</cUF><cNF>59405672</cNF><natOp>VENDA</natOp><mod>55</mod><serie>1</serie><nNF>100</nNF><dhEmi>2026-02-16T12:00:00-04:00</dhEmi><tpNF>1</tpNF><idDest>1</idDest><cMunFG>5107925</cMunFG><tpImp>1</tpImp><tpEmis>1</tpEmis><cDV>0</cDV><tpAmb>2</tpAmb><finNFe>1</finNFe><indFinal>1</indFinal><indPres>1</indPres><procEmi>0</procEmi><verProc>TESTE</verProc></ide><emit><CNPJ>00000000000000</CNPJ><xNome>EMITENTE TESTE</xNome><enderEmit><xLgr>RUA TESTE</xLgr><nro>100</nro><xBairro>CENTRO</xBairro><cMun>5107925</cMun><xMun>SORRISO</xMun><UF>MT</UF><CEP>78890000</CEP></enderEmit><IE>000000000</IE><CRT>3</CRT></emit><dest><CNPJ>99999999000191</CNPJ><xNome>NF-E EMITIDA EM AMBIENTE DE HOMOLOGACAO - SEM VALOR FISCAL</xNome><enderDest><xLgr>RUA TESTE</xLgr><nro>100</nro><xBairro>CENTRO</xBairro><cMun>5107925</cMun><xMun>SORRISO</xMun><UF>MT</UF><CEP>78890000</CEP></enderDest><indIEDest>9</indIEDest></dest><det nItem=\"1\"><prod><cProd>1</cProd><cEAN>SEM GTIN</cEAN><xProd>PRODUTO TESTE</xProd><NCM>00000000</NCM><CFOP>5102</CFOP><uCom>UN</uCom><qCom>1.0000</qCom><vUnCom>100.00</vUnCom><vProd>100.00</vProd><cEANTrib>SEM GTIN</cEANTrib><uTrib>UN</uTrib><qTrib>1.0000</qTrib><vUnTrib>100.00</vUnTrib><indTot>1</indTot></prod><imposto><ICMS><ICMS00><orig>0</orig><CST>00</CST><modBC>3</modBC><vBC>100.00</vBC><pICMS>17.00</pICMS><vICMS>17.00</vICMS></ICMS00></ICMS><PIS><PISNT><CST>07</CST></PISNT></PIS><COFINS><COFINSNT><CST>07</CST></COFINSNT></COFINS></imposto></det><total><ICMSTot><vBC>100.00</vBC><vICMS>17.00</vICMS><vICMSDeson>0.00</vICMSDeson><vFCP>0.00</vFCP><vBCST>0.00</vBCST><vST>0.00</vST><vFCPST>0.00</vFCPST><vFCPSTRet>0.00</vFCPSTRet><vProd>100.00</vProd><vFrete>0.00</vFrete><vSeg>0.00</vSeg><vDesc>0.00</vDesc><vII>0.00</vII><vIPI>0.00</vIPI><vIPIDevol>0.00</vIPIDevol><vPIS>0.00</vPIS><vCOFINS>0.00</vCOFINS><vOutro>0.00</vOutro><vNF>117.00</vNF><vTotTrib>0.00</vTotTrib></ICMSTot></total><transp><modFrete>9</modFrete></transp><pag><detPag><tPag>90</tPag><vPag>117.00</vPag></detPag></pag></infNFe></NFe>";
        }

        static String getXmlNFCe() {
            // Exemplo simplificado para NFCe
            return "<NFe xmlns=\"http://www.portalfiscal.inf.br/nfe\"><infNFe Id=\"NFe51260134602686000102650020000085091230458530\" versao=\"4.00\"><ide><cUF>51</cUF><cNF>23045853</cNF><natOp>VENDA</natOp><mod>65</mod><serie>1</serie><nNF>8509</nNF><dhEmi>2026-01-17T11:45:00-04:00</dhEmi><tpNF>1</tpNF><idDest>1</idDest><cMunFG>5107925</cMunFG><tpImp>4</tpImp><tpEmis>1</tpEmis><cDV>0</cDV><tpAmb>2</tpAmb><finNFe>1</finNFe><indFinal>1</indFinal><indPres>1</indPres><procEmi>0</procEmi><verProc>TESTE</verProc></ide><emit><CNPJ>34602686000102</CNPJ><xNome>EMITENTE NFCE</xNome><enderEmit><xLgr>RUA</xLgr><nro>1</nro><xBairro>B</xBairro><cMun>5107925</cMun><xMun>Sorriso</xMun><UF>MT</UF><CEP>78890000</CEP><fone>6635440000</fone></enderEmit><IE>140356347</IE><CRT>1</CRT></emit><det nItem=\"1\"><prod><cProd>1</cProd><cEAN>SEM GTIN</cEAN><xProd>PRODUTO NFCe</xProd><NCM>00000000</NCM><CFOP>5102</CFOP><uCom>UN</uCom><qCom>1.0000</qCom><vUnCom>10.00</vUnCom><vProd>10.00</vProd><cEANTrib>SEM GTIN</cEANTrib><uTrib>UN</uTrib><qTrib>1.0000</qTrib><vUnTrib>10.00</vUnTrib><indTot>1</indTot></prod><imposto><ICMS><ICMSSN102><orig>0</orig><CSOSN>102</CSOSN></ICMSSN102></ICMS></imposto></det><total><ICMSTot><vBC>0.00</vBC><vICMS>0.00</vICMS><vICMSDeson>0.00</vICMSDeson><vFCP>0.00</vFCP><vBCST>0.00</vBCST><vST>0.00</vST><vFCPST>0.00</vFCPST><vFCPSTRet>0.00</vFCPSTRet><vProd>10.00</vProd><vFrete>0.00</vFrete><vSeg>0.00</vSeg><vDesc>0.00</vDesc><vII>0.00</vII><vIPI>0.00</vIPI><vIPIDevol>0.00</vIPIDevol><vPIS>0.00</vPIS><vCOFINS>0.00</vCOFINS><vOutro>0.00</vOutro><vNF>10.00</vNF><vTotTrib>0.00</vTotTrib></ICMSTot></total><transp><modFrete>9</modFrete></transp><pag><detPag><tPag>01</tPag><vPag>10.00</vPag></detPag></pag></infNFe></NFe>";
        }

        static String getXmlEfdReinf() {
            // Exemplo com ID minúsculo (case sensitive test)
            return "<Reinf xmlns=\"http://www.reinf.esocial.gov.br/schemas/envioLoteEventosAssincrono/v1_00_00\"><envioLoteEventos><ideContribuinte><tpInsc>1</tpInsc><nrInsc>37042584</nrInsc></ideContribuinte><eventos><evento Id=\"ID1370425840000002026021217340600000\"><Reinf xmlns=\"http://www.reinf.esocial.gov.br/schemas/evtFechamento/v2_01_02\"><evtFechaEvPer id=\"ID1370425840000002026021217340600000\"><ideEvento><perApur>2026-01</perApur><tpAmb>1</tpAmb><procEmi>1</procEmi><verProc>2_01_02</verProc></ideEvento><ideContri><tpInsc>1</tpInsc><nrInsc>37042584</nrInsc></ideContri><ideRespInf><nmResp>RESPONSAVEL</nmResp><cpfResp>00000000000</cpfResp><telefone>0000000000</telefone><email/></ideRespInf><infoFech><evtServTm>N</evtServTm><evtServPr>N</evtServPr><evtAssDespRec>N</evtAssDespRec><evtAssDespRep>N</evtAssDespRep><evtComProd>N</evtComProd><evtCPRB>N</evtCPRB><evtAquis>N</evtAquis></infoFech></evtFechaEvPer></Reinf></evento></eventos></envioLoteEventos></Reinf>";
        }
    }

    private static void configureCleanLogger() {
        // Configura o console para mostrar apenas a mensagem, sem data/thread/classe
        // (estilo CLI)
        Logger root = Logger.getLogger("");
        for (Handler h : root.getHandlers())
            root.removeHandler(h);
        ConsoleHandler handler = new ConsoleHandler();
        handler.setFormatter(new Formatter() {
            @Override
            public String format(LogRecord record) {
                // Formato: [NÍVEL] Mensagem
                return String.format("[%s] %s%n", record.getLevel(), record.getMessage());
            }
        });
        handler.setLevel(Level.INFO);
        root.addHandler(handler);
    }

    // --- DICAS DE MIGRAÇÃO E INSTALAÇÃO DE CERTIFICADOS ---

    // Migra um PFX legado (RC2/SHA1) para o formato moderno (AES-256/SHA-256).
    // O JDK 11+ aplica a criptografia forte automaticamente ao salvar.

    static void upgradePfx(String pathAntigo, String pathNovo, char[] password)
            throws Exception {
        KeyStore ks = KeyStore.getInstance("PKCS12");
        try (FileInputStream fis = new FileInputStream(pathAntigo)) {
            ks.load(fis, password);
        }
        
        try (FileOutputStream fos = new FileOutputStream(pathNovo)) {
            ks.store(fos, password);
        }
        log.info("PFX migrado com sucesso: " + pathNovo);
    }

    // DICA EXTRA (NÃO IMPLEMENTADA): Instalação de PFX diretamente no Windows-MY
    /**
     * Instala um PFX no repositório pessoal do usuário Windows (Windows-MY).
     * Requer SunMSCAPI — funciona apenas em Windows.
     */
    static void instalarNoWindows(String pfxPath, String pfxPass) throws Exception {
        // 1. Carrega o PFX do disco
        KeyStore pfxStore = KeyStore.getInstance("PKCS12");
        try (InputStream in = Files.newInputStream(Paths.get(pfxPath))) {
            pfxStore.load(in, pfxPass.toCharArray());
        }

        // 2. Abre o KeyStore do Windows (com permissão de escrita)
        KeyStore winStore = KeyStore.getInstance("Windows-MY", "SunMSCAPI");
        winStore.load(null, null);

        // 3. Itera sobre o PFX e importa as chaves
        Enumeration<String> aliases = pfxStore.aliases();
        while (aliases.hasMoreElements()) {
            String alias = aliases.nextElement();
            if (pfxStore.isKeyEntry(alias)) {
                Key key = pfxStore.getKey(alias, pfxPass.toCharArray());
                Certificate[] chain = pfxStore.getCertificateChain(alias);

                // Define no Windows (Alias original + sufixo para evitar colisão?)
                winStore.setKeyEntry(alias, key, null, chain); // Senha null = proteção nativa
                log.info("Certificado importado para Windows-MY: " + alias);
            }
        }
    }

}
