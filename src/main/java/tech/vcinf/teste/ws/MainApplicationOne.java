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
 * MainApplicationOne - Utilitário de Teste para Comunicação SEFAZ e Assinatura
 * XML.
 *
 * Funcionalidades:
 * 1. Geração Automática de TrustStore (Cadeias ICP-Brasil e Servidores SEFAZ)
 * 2. Autenticação mTLS (Windows-MY ou Arquivo PFX)
 * 3. Assinatura Digital XML (Padrão DSig Enveloped)
 * - Suporte a NFe/CTe (SHA-1) e Reinf/eSocial (SHA-256)
 * - Normalização automática de ID (id, Id, ID)
 * 4. Conversão Objeto <-> XML (XmlMapper, Java puro)
 *
 * Uso: Apenas para ambiente de DESENVOLVIMENTO e TESTE.
 */
// @SpringBootApplication
public class MainApplicationOne /* implements ApplicationRunner */ {

    private static final Logger log = Logger.getLogger(MainApplicationOne.class.getName());

    // =========================================================================
    // --- Entrypoints
    // =========================================================================

    public static void main(String[] args) {
        configureCleanLogger();
        SpringApplication.run(MainApplicationOne.class, args);
    }

    // @Override
    public void run(/* ApplicationArguments args */) {
        log.info(">>> INICIANDO AMBIENTE DE TESTES SEFAZ/JAVA <<<");

        try {
            SecurityContextService.ensureTrustStore();

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

            log.info(">>> TESTE 1.0: Conexão mTLS (Nfe StatusServico) <<<");
            WebServiceClient.testConsultaStatusNfe(sslContext);

            log.info(">>> TESTE 1.1: Conexão mTLS (Cte StatusServico) <<<");
            WebServiceClient.testConsultaStatusCte(sslContext);

            log.info(">>> TESTE 1.2: Conexão mTLS (Nfce StatusServico) <<<");
            WebServiceClient.testConsultaStatusNfce(sslContext);

            log.info(">>> TESTE 1.3: Conexão mTLS (Nfce StatusServico) <<<");
            WebServiceClient.testConsultaStatusNfce(sslContext);

            log.info(">>> TESTE 1.4: Conexão mTLS (Mdfe StatusServico) <<<");
            WebServiceClient.testConsultaStatusMdfe(sslContext);

            log.info(">>> TESTE 1.5: Conexão mTLS (NFSe DFe) <<<");
            WebServiceClient.testNFSeDFe(sslContext);

            log.info(">>> TESTE 1.6: Conexão mTLS (Consulta Reinf) <<<");
            WebServiceClient.testReinfGet(sslContext,
                    "https://reinf.receita.economia.gov.br/consulta/lotes/1.202512.744590511");

            log.info(">>> TESTE 2: Assinatura Digital de XMLs <<<");
            processarAssinatura("NFe", FiscalDocumentRepository.getXmlNFe(), keyEntry);
            processarAssinatura("NFCe", FiscalDocumentRepository.getXmlNFCe(), keyEntry);
            processarAssinatura("Reinf", FiscalDocumentRepository.getXmlEfdReinf(), keyEntry);

            log.info(">>> TESTE 3: Conversão Objeto <-> XML (XmlMapper) <<<");
            testarXmlMapper();

            log.info(">>> FIM DO PROCESSAMENTO COM SUCESSO <<<");

        } catch (Exception e) {
            log.severe("ERRO FATAL NA APLICAÇÃO: " + e.getMessage());
            e.printStackTrace();
        }
    }

    private void processarAssinatura(String tipo, String xmlBruto, KeyStore.PrivateKeyEntry keyEntry) throws Exception {
        log.info("--- Assinando " + tipo + " ---");
        String xmlAssinado = XmlSignerService.sign(xmlBruto, keyEntry);
        String idDoc = XmlSignerService.extractIdFromSignedXml(xmlAssinado);
        String filename = tipo + "_" + (idDoc.isEmpty() ? System.currentTimeMillis() : idDoc) + ".xml";
        Path path = Paths.get(filename);
        Files.writeString(path, xmlAssinado, StandardCharsets.UTF_8);
        log.info("Arquivo salvo: " + path.toAbsolutePath());
    }

    private static void testarXmlMapper() {
        try {
            ConsStatServ req = new ConsStatServ("4.00", "2", "51");
            String xml = XmlMapper.toXml(req);
            log.info("[ConsStatServ] Objeto → XML:\n" + xml);
            ConsStatServ parsed = XmlMapper.fromXml(xml, ConsStatServ.class);
            log.info("[ConsStatServ] XML → Objeto: " + parsed);
        } catch (Exception e) {
            log.severe("FALHA Teste ConsStatServ: " + e.getMessage());
        }

        try {
            String xmlNFe = FiscalDocumentRepository.getXmlNFe();
            DocumentBuilderFactory dbf = DocumentBuilderFactory.newInstance();
            dbf.setNamespaceAware(true);
            org.w3c.dom.Document doc = dbf.newDocumentBuilder()
                    .parse(new InputSource(new StringReader(xmlNFe)));
            NodeList ideNodes = doc.getElementsByTagNameNS("*", "ide");
            if (ideNodes.getLength() > 0) {
                NFeIde ide = XmlMapper.fromXml(elementToString((Element) ideNodes.item(0)), NFeIde.class);
                log.info("[NFe ide] XML → Objeto: " + ide);
                log.info("[NFe ide] Objeto → XML:\n" + XmlMapper.toXml(ide));
            }
        } catch (Exception e) {
            log.severe("FALHA Teste NFe ide: " + e.getMessage());
        }

        try {
            NFeIde ide = new NFeIde();
            ide.cUF = "51";
            ide.natOp = "VENDA";
            ide.mod = "55";
            ide.serie = "1";
            ide.nNF = "999";
            ide.dhEmi = "2026-02-17T10:00:00-04:00";
            ide.tpAmb = "2";
            NFeSimples nfe = new NFeSimples(ide);
            String xml = XmlMapper.toXml(nfe);
            log.info("[NFeSimples] Objeto → XML:\n" + xml);
            log.info("[NFeSimples] XML → Objeto: " + XmlMapper.fromXml(xml, NFeSimples.class));
        } catch (Exception e) {
            log.severe("FALHA Teste NFeSimples: " + e.getMessage());
        }
    }

    // =========================================================================
    // --- Configuração Centralizada
    // =========================================================================

    static class Config {

        /** TRUE = Windows Keystore, FALSE = Arquivo PFX */
        static final boolean USE_WINDOWS_KEYSTORE = false;

        // -------- PFX (Arquivo) --------
        static final String PFX_PATH = "C:/certificado/129.pfx";
        static final String PFX_PASS = "12345";

        // -------- Windows-MY (Thumbprint SHA-1) --------
        static final String WIN_THUMB = "4B753DC532B07E78686A113F90AED1960074AEEA";

        // -------- Endpoints SEFAZ --------
        static final String ENDPOINT_NFE_STATUS = "https://nfe.sefaz.mt.gov.br/nfews/v2/services/NfeStatusServico4";
        static final String ENDPOINT_CTE_STATUS = "https://cte.sefaz.mt.gov.br/ctews2/services/CTeStatusServicoV4";
        static final String ENDPOINT_NFCE_STATUS = "https://nfce.sefaz.mt.gov.br/nfcews/services/NfeStatusServico4";
        static final String ENDPOINT_MDFE_STATUS = "https://mdfe.svrs.rs.gov.br/ws/MDFeStatusServico/MDFeStatusServico.asmx";
        static final String ENDPOINT_NFSE_DFE = "https://adn.nfse.gov.br/adn/DFe";
        static final String ENDPOINT_NFSE_CONTRIBUINTE_DFE = "https://adn.nfse.gov.br/contribuintes/DFe/000000000000001";

        // -------- TrustStore --------
        static final String TRUSTSTORE_FILENAME = "cacerts_vcinf";
        static final String TRUSTSTORE_PASS = "changeit";
    }

    // =========================================================================
    // --- Serviço de Segurança (SSL, KeyStore, TrustStore)
    // =========================================================================

    static class SecurityContextService {

        // -------- TrustStore --------

        static void ensureTrustStore() throws Exception {
            File trustFile = new File(Config.TRUSTSTORE_FILENAME);
            if (trustFile.exists()) {
                log.info("TrustStore encontrado: " + Config.TRUSTSTORE_FILENAME);
                return;
            }

            log.info("Gerando TrustStore dinâmico...");
            KeyStore ks = KeyStore.getInstance(KeyStore.getDefaultType());
            Path javaCacerts = Paths.get(System.getProperty("java.home"), "lib", "security", "cacerts");
            try (InputStream is = Files.newInputStream(javaCacerts)) {
                ks.load(is, "changeit".toCharArray());
            }

            CertificateFactory cf = CertificateFactory.getInstance("X.509");
            List.of("v10", "v5", "v2").forEach(v -> {
                try (InputStream in = new URL(
                        "http://acraiz.icpbrasil.gov.br/credenciadas/RAIZ/ICP-Brasil" + v + ".crt").openStream()) {
                    ks.setCertificateEntry("icp-brasil-" + v, (X509Certificate) cf.generateCertificate(in));
                } catch (Exception e) {
                    log.warning("Falha baixar ICP-Brasil " + v + ": " + e.getMessage());
                }
            });

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

        /** Captura a cadeia de certificados via SSL handshake intencional. */
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
                }

                if (ctm.chain != null) {
                    for (int i = 0; i < ctm.chain.length; i++)
                        ks.setCertificateEntry(host + "-chain-" + i, ctm.chain[i]);
                    log.info("Capturados " + ctm.chain.length + " certificados de " + host);
                }
            } catch (Exception e) {
                log.warning("Erro capturando cadeia de " + host + ": " + e.getMessage());
            }
        }

        // -------- Carregamento de Chaves --------

        static KeyStore.PrivateKeyEntry loadPfxKeyEntry(String path, String pass) throws Exception {
            KeyStore ks = KeyStore.getInstance("PKCS12");
            try (InputStream in = Files.newInputStream(Paths.get(path))) {
                ks.load(in, pass.toCharArray());
            }
            return getKeyEntryFromStore(ks, pass);
        }

        /** Usa SunMSCAPI para autenticação nativa; senha null delega ao Windows. */
        static KeyStore.PrivateKeyEntry loadWindowsKeyEntry(String thumbprint) throws Exception {
            KeyStore ks = KeyStore.getInstance("Windows-MY", "SunMSCAPI");
            ks.load(null, null);

            String alias = findAliasByThumbprint(ks, thumbprint);
            if (alias == null)
                throw new RuntimeException("Certificado não encontrado no Windows: " + thumbprint);

            PrivateKey privateKey = (PrivateKey) ks.getKey(alias, null);
            if (privateKey == null)
                throw new RuntimeException("Acesso à chave privada negado ou não encontrada.");

            java.security.cert.Certificate[] chain = ks.getCertificateChain(alias);
            return new KeyStore.PrivateKeyEntry(privateKey, chain);
        }

        // -------- Criação de SSLContext --------

        static SSLContext createPfxSslContext(KeyStore.PrivateKeyEntry keyEntry) throws Exception {
            return createSslContextGeneric(keyEntry, Config.PFX_PASS);
        }

        /** Usa o Windows-MY diretamente para evitar cópia da chave privada. */
        static SSLContext createWindowsSslContext(KeyStore.PrivateKeyEntry keyEntry) throws Exception {
            KeyStore windowsKs = KeyStore.getInstance("Windows-MY", "SunMSCAPI");
            windowsKs.load(null, null);

            KeyManagerFactory kmf = KeyManagerFactory.getInstance("SunX509");
            kmf.init(windowsKs, null);

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
            KeyStore identity = KeyStore.getInstance(KeyStore.getDefaultType());
            identity.load(null, null);
            identity.setKeyEntry("identity", keyEntry.getPrivateKey(),
                    (pass != null ? pass.toCharArray() : null), keyEntry.getCertificateChain());

            KeyManagerFactory kmf = KeyManagerFactory.getInstance("SunX509");
            kmf.init(identity, (pass != null ? pass.toCharArray() : null));

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

        // -------- Auxiliares --------

        private static KeyStore.PrivateKeyEntry getKeyEntryFromStore(KeyStore ks, String pass) throws Exception {
            Enumeration<String> aliases = ks.aliases();
            while (aliases.hasMoreElements()) {
                String alias = aliases.nextElement();
                if (ks.isKeyEntry(alias))
                    return (KeyStore.PrivateKeyEntry) ks.getEntry(alias,
                            new KeyStore.PasswordProtection(pass.toCharArray()));
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

        /**
         * TrustManager que captura a cadeia sem validar, para importação no TrustStore.
         */
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

    // =========================================================================
    // --- Serviço de Assinatura XML (DSig Enveloped)
    // =========================================================================

    static class XmlSignerService {

        /** Assina o XML aplicando SHA-1 (NFe/CTe) ou SHA-256 (Reinf/eSocial). */
        static String sign(String xmlBruto, KeyStore.PrivateKeyEntry keyEntry) throws Exception {
            DocumentBuilderFactory dbf = DocumentBuilderFactory.newInstance();
            dbf.setNamespaceAware(true);
            Document doc = dbf.newDocumentBuilder().parse(new InputSource(new StringReader(xmlBruto)));

            Element toSign = findElementToSign(doc);
            String idAttributeName = normalizeIdAttribute(toSign);
            String idValue = toSign.getAttribute(idAttributeName);

            String digestMethod;
            String signatureMethod;
            if (toSign.getNodeName().startsWith("evt") || toSign.getNodeName().startsWith("eSocial")) {
                digestMethod = DigestMethod.SHA256;
                signatureMethod = "http://www.w3.org/2001/04/xmldsig-more#rsa-sha256";
            } else {
                digestMethod = DigestMethod.SHA1;
                signatureMethod = SignatureMethod.RSA_SHA1;
            }

            XMLSignatureFactory factory = XMLSignatureFactory.getInstance("DOM");
            DOMSignContext dsc = new DOMSignContext(keyEntry.getPrivateKey(), toSign.getParentNode());

            List<javax.xml.crypto.dsig.Transform> transforms = new ArrayList<>();
            transforms.add(
                    factory.newTransform(javax.xml.crypto.dsig.Transform.ENVELOPED, (TransformParameterSpec) null));
            transforms.add(factory.newTransform("http://www.w3.org/TR/2001/REC-xml-c14n-20010315",
                    (TransformParameterSpec) null));

            Reference ref = factory.newReference("#" + idValue,
                    factory.newDigestMethod(digestMethod, null), transforms, null, null);

            SignedInfo si = factory.newSignedInfo(
                    factory.newCanonicalizationMethod(CanonicalizationMethod.INCLUSIVE, (C14NMethodParameterSpec) null),
                    factory.newSignatureMethod(signatureMethod, null),
                    Collections.singletonList(ref));

            KeyInfoFactory kif = factory.getKeyInfoFactory();
            KeyInfo ki = kif.newKeyInfo(
                    Collections.singletonList(kif.newX509Data(Collections.singletonList(keyEntry.getCertificate()))));

            factory.newXMLSignature(si, ki).sign(dsc);

            return convertDocumentToString(doc);
        }

        /**
         * Extrai o primeiro ID do XML assinado — usado apenas para nomear o arquivo de
         * saída.
         */
        static String extractIdFromSignedXml(String xml) {
            java.util.regex.Matcher m = java.util.regex.Pattern.compile("(?:Id|id|ID)=\"([^\"]+)\"").matcher(xml);
            return m.find() ? m.group(1) : "";
        }

        // -------- Auxiliares --------

        private static Element findElementToSign(Document doc) {
            String[] targetTags = { "infNFe", "infCte", "infNFSe", "evtFechaEvPer", "evtInfoEmpregador", "Reinf" };
            NodeList all = doc.getElementsByTagName("*");
            for (int i = 0; i < all.getLength(); i++) {
                Element el = (Element) all.item(i);
                for (String tag : targetTags) {
                    if (el.getNodeName().startsWith(tag) || el.getNodeName().startsWith("evt")) {
                        if (el.hasAttribute("Id") || el.hasAttribute("id") || el.hasAttribute("ID"))
                            return el;
                    }
                }
            }
            throw new RuntimeException("Nenhum elemento assinável encontrado no XML.");
        }

        private static String normalizeIdAttribute(Element el) {
            for (String attr : new String[] { "id", "Id", "ID" }) {
                if (el.hasAttribute(attr)) {
                    el.setIdAttribute(attr, true);
                    return attr;
                }
            }
            throw new IllegalArgumentException("Elemento " + el.getNodeName() + " sem atributo ID válido.");
        }

        private static String convertDocumentToString(Document doc) throws Exception {
            Transformer tf = TransformerFactory.newInstance().newTransformer();
            tf.setOutputProperty(OutputKeys.INDENT, "no");
            StringWriter writer = new StringWriter();
            tf.transform(new DOMSource(doc), new StreamResult(writer));
            return writer.toString();
        }
    }

    // =========================================================================
    // --- Cliente WebService (Testes mTLS)
    // =========================================================================

    static class WebServiceClient {

        record ProcessamentoResult(String ultNSU, int qtdDocumentos) {
        }

        static void testConsultaStatusNfe(SSLContext ctx) {
            try {
                HttpClient client = HttpClient.newBuilder().sslContext(ctx).connectTimeout(Duration.ofSeconds(10))
                        .build();
                HttpRequest req = HttpRequest.newBuilder()
                        .uri(URI.create(Config.ENDPOINT_NFE_STATUS))
                        .header("Content-Type", "application/soap+xml; charset=utf-8")
                        .POST(HttpRequest.BodyPublishers.ofString(FiscalDocumentRepository.getXml_ConsultaStatusNfe(),
                                StandardCharsets.UTF_8))
                        .build();
                HttpResponse<String> res = client.send(req, HttpResponse.BodyHandlers.ofString());
                log.info("STATUS WEBSERVICE: HTTP " + res.statusCode());
                if (res.statusCode() != 200)
                    log.warning("Resposta Diferente de 200: " + res.body());
            } catch (Exception e) {
                log.severe("FALHA NA CONEXÃO WEBSERVICE: " + e.getMessage());
            }
        }

        static void testConsultaStatusCte(SSLContext sslContext) {
            try {
                HttpClient client = HttpClient.newBuilder().sslContext(sslContext)
                        .connectTimeout(Duration.ofSeconds(10)).build();
                HttpRequest req = HttpRequest.newBuilder()
                        .uri(URI.create(Config.ENDPOINT_CTE_STATUS))
                        .header("Content-Type", "application/soap+xml; charset=utf-8")
                        .POST(HttpRequest.BodyPublishers.ofString(FiscalDocumentRepository.getXml_ConsultaStatusCte(),
                                StandardCharsets.UTF_8))
                        .build();
                HttpResponse<String> res = client.send(req, HttpResponse.BodyHandlers.ofString());
                log.info("STATUS WEBSERVICE: HTTP " + res.statusCode());
                if (res.statusCode() != 200)
                    log.warning("Resposta Diferente de 200: " + res.body());
            } catch (Exception e) {
                log.severe("FALHA NA CONEXÃO WEBSERVICE: " + e.getMessage());
            }
        }

        static void testConsultaStatusNfce(SSLContext sslContext) {
            try {
                HttpClient client = HttpClient.newBuilder().sslContext(sslContext)
                        .connectTimeout(Duration.ofSeconds(10)).build();
                HttpRequest req = HttpRequest.newBuilder()
                        .uri(URI.create(Config.ENDPOINT_NFCE_STATUS))
                        .header("Content-Type", "application/soap+xml; charset=utf-8")
                        .POST(HttpRequest.BodyPublishers.ofString(FiscalDocumentRepository.getXml_ConsultaStatusNfce(),
                                StandardCharsets.UTF_8))
                        .build();
                HttpResponse<String> res = client.send(req, HttpResponse.BodyHandlers.ofString());
                log.info("STATUS WEBSERVICE: HTTP " + res.statusCode());
                if (res.statusCode() != 200)
                    log.warning("Resposta Diferente de 200: " + res.body());
            } catch (Exception e) {
                log.severe("FALHA NA CONEXÃO WEBSERVICE: " + e.getMessage());
            }
        }

        static void testConsultaStatusMdfe(SSLContext sslContext) {
            try {
                HttpClient client = HttpClient.newBuilder().sslContext(sslContext)
                        .connectTimeout(Duration.ofSeconds(10)).build();
                HttpRequest req = HttpRequest.newBuilder()
                        .uri(URI.create(Config.ENDPOINT_MDFE_STATUS))
                        .header("Content-Type", "application/soap+xml; charset=utf-8")
                        .POST(HttpRequest.BodyPublishers.ofString(FiscalDocumentRepository.getXml_ConsultaStatusMdfe(),
                                StandardCharsets.UTF_8))
                        .build();
                HttpResponse<String> res = client.send(req, HttpResponse.BodyHandlers.ofString());
                log.info("STATUS WEBSERVICE: HTTP " + res.statusCode());
                if (res.statusCode() != 200)
                    log.warning("Resposta Diferente de 200: " + res.body());
            } catch (Exception e) {
                log.severe("FALHA NA CONEXÃO WEBSERVICE: " + e.getMessage());
            }
        }

        static void testNFSeDFe(SSLContext sslContext) {
            try {
                HttpClient client = HttpClient.newBuilder().sslContext(sslContext)
                        .connectTimeout(Duration.ofSeconds(10)).build();
                HttpRequest req = HttpRequest.newBuilder()
                        .uri(URI.create(Config.ENDPOINT_NFSE_CONTRIBUINTE_DFE))
                        .header("Accept", "application/json")
                        .GET()
                        .build();
                HttpResponse<String> res = client.send(req, HttpResponse.BodyHandlers.ofString());
                log.info("STATUS WEBSERVICE: HTTP " + res.statusCode());
                if (res.statusCode() != 200)
                    log.warning("Resposta Diferente de 200: " + res.body());

                String body = res.body();
                try {
                    String busca = "\"ArquivoXml\":\"";
                    int inicio = body.indexOf(busca) + busca.length();
                    int fim = body.indexOf("\"", inicio);
                    byte[] comprimido = java.util.Base64.getDecoder().decode(body.substring(inicio, fim));
                    try (java.util.zip.GZIPInputStream gis = new java.util.zip.GZIPInputStream(
                            new java.io.ByteArrayInputStream(comprimido));
                            java.io.ByteArrayOutputStream baos = new java.io.ByteArrayOutputStream()) {
                        byte[] buffer = new byte[1024];
                        int len;
                        while ((len = gis.read(buffer)) > 0)
                            baos.write(buffer, 0, len);
                        log.info("XML DECODIFICADO: " + baos.toString("UTF-8"));
                    }
                } catch (Exception e) {
                    log.severe("Erro ao processar conteúdo: " + e.getMessage());
                }
            } catch (Exception e) {
                log.severe("FALHA NA CONEXÃO WEBSERVICE: " + e.getMessage());
            }
        }

        static void testReinfGet(SSLContext ctx, String url) {
            log.info("[GET] Testando Consulta Reinf: " + url);
            try {
                HttpClient client = HttpClient.newBuilder().sslContext(ctx).connectTimeout(Duration.ofSeconds(15))
                        .build();
                HttpRequest req = HttpRequest.newBuilder().uri(URI.create(url)).GET().build();
                HttpResponse<String> res = client.send(req, HttpResponse.BodyHandlers.ofString());
                log.info("STATUS Reinf: HTTP " + res.statusCode());
                log.info("Corpo Resposta (Snippet): " +
                        res.body().substring(0, Math.min(res.body().length(), 200)).replace("\n", " "));
            } catch (Exception e) {
                log.severe("FALHA Reinf: " + e.getMessage());
                if (e.getMessage().contains("PKIX"))
                    log.warning(
                            "DICA: Verifique se a cadeia 'reinf.receita.economia.gov.br' foi capturada no TrustStore.");
            }
        }
    }

    // =========================================================================
    // --- Repositório de Documentos (Mocks XML)
    // =========================================================================

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
            return "<NFe xmlns=\"http://www.portalfiscal.inf.br/nfe\"><infNFe Id=\"NFe51260134602686000102650020000085091230458530\" versao=\"4.00\"><ide><cUF>51</cUF><cNF>23045853</cNF><natOp>VENDA</natOp><mod>65</mod><serie>1</serie><nNF>8509</nNF><dhEmi>2026-01-17T11:45:00-04:00</dhEmi><tpNF>1</tpNF><idDest>1</idDest><cMunFG>5107925</cMunFG><tpImp>4</tpImp><tpEmis>1</tpEmis><cDV>0</cDV><tpAmb>2</tpAmb><finNFe>1</finNFe><indFinal>1</indFinal><indPres>1</indPres><procEmi>0</procEmi><verProc>TESTE</verProc></ide><emit><CNPJ>34602686000102</CNPJ><xNome>EMITENTE NFCE</xNome><enderEmit><xLgr>RUA</xLgr><nro>1</nro><xBairro>B</xBairro><cMun>5107925</cMun><xMun>Sorriso</xMun><UF>MT</UF><CEP>78890000</CEP><fone>6635440000</fone></enderEmit><IE>140356347</IE><CRT>1</CRT></emit><det nItem=\"1\"><prod><cProd>1</cProd><cEAN>SEM GTIN</cEAN><xProd>PRODUTO NFCe</xProd><NCM>00000000</NCM><CFOP>5102</CFOP><uCom>UN</uCom><qCom>1.0000</qCom><vUnCom>10.00</vUnCom><vProd>10.00</vProd><cEANTrib>SEM GTIN</cEANTrib><uTrib>UN</uTrib><qTrib>1.0000</qTrib><vUnTrib>10.00</vUnTrib><indTot>1</indTot></prod><imposto><ICMS><ICMSSN102><orig>0</orig><CSOSN>102</CSOSN></ICMSSN102></ICMS></imposto></det><total><ICMSTot><vBC>0.00</vBC><vICMS>0.00</vICMS><vICMSDeson>0.00</vICMSDeson><vFCP>0.00</vFCP><vBCST>0.00</vBCST><vST>0.00</vST><vFCPST>0.00</vFCPST><vFCPSTRet>0.00</vFCPSTRet><vProd>10.00</vProd><vFrete>0.00</vFrete><vSeg>0.00</vSeg><vDesc>0.00</vDesc><vII>0.00</vII><vIPI>0.00</vIPI><vIPIDevol>0.00</vIPIDevol><vPIS>0.00</vPIS><vCOFINS>0.00</vCOFINS><vOutro>0.00</vOutro><vNF>10.00</vNF><vTotTrib>0.00</vTotTrib></ICMSTot></total><transp><modFrete>9</modFrete></transp><pag><detPag><tPag>01</tPag><vPag>10.00</vPag></detPag></pag></infNFe></NFe>";
        }

        static String getXmlEfdReinf() {
            return "<Reinf xmlns=\"http://www.reinf.esocial.gov.br/schemas/envioLoteEventosAssincrono/v1_00_00\"><envioLoteEventos><ideContribuinte><tpInsc>1</tpInsc><nrInsc>37042584</nrInsc></ideContribuinte><eventos><evento Id=\"ID1370425840000002026021217340600000\"><Reinf xmlns=\"http://www.reinf.esocial.gov.br/schemas/evtFechamento/v2_01_02\"><evtFechaEvPer id=\"ID1370425840000002026021217340600000\"><ideEvento><perApur>2026-01</perApur><tpAmb>1</tpAmb><procEmi>1</procEmi><verProc>2_01_02</verProc></ideEvento><ideContri><tpInsc>1</tpInsc><nrInsc>37042584</nrInsc></ideContri><ideRespInf><nmResp>RESPONSAVEL</nmResp><cpfResp>00000000000</cpfResp><telefone>0000000000</telefone><email/></ideRespInf><infoFech><evtServTm>N</evtServTm><evtServPr>N</evtServPr><evtAssDespRec>N</evtAssDespRec><evtAssDespRep>N</evtAssDespRep><evtComProd>N</evtComProd><evtCPRB>N</evtCPRB><evtAquis>N</evtAquis></infoFech></evtFechaEvPer></Reinf></evento></eventos></envioLoteEventos></Reinf>";
        }
    }

    // =========================================================================
    // --- XmlMapper: Conversão Objeto <-> XML (Java puro, sem bibliotecas)
    // =========================================================================
    //
    // Como usar:
    // String xml = XmlMapper.toXml(objeto);
    // MinhaClasse obj = XmlMapper.fromXml(xml, MinhaClasse.class);
    //
    // Anote seus POJOs com:
    // @XmlRootElement(name="tagRaiz", namespace="http://...") — na classe
    // @XmlElement(name="tagXml", namespace="http://...") — campo filho
    // @XmlAttribute(name="atributo") — campo atributo
    // @XmlList — campo List<T>

    @java.lang.annotation.Retention(java.lang.annotation.RetentionPolicy.RUNTIME)
    @java.lang.annotation.Target(java.lang.annotation.ElementType.TYPE)
    @interface XmlRootElement {
        String name() default "";

        String namespace() default "";
    }

    @java.lang.annotation.Retention(java.lang.annotation.RetentionPolicy.RUNTIME)
    @java.lang.annotation.Target(java.lang.annotation.ElementType.FIELD)
    @interface XmlElement {
        String name() default "";

        String namespace() default "";

        boolean required() default false;
    }

    @java.lang.annotation.Retention(java.lang.annotation.RetentionPolicy.RUNTIME)
    @java.lang.annotation.Target(java.lang.annotation.ElementType.FIELD)
    @interface XmlAttribute {
        String name() default "";
    }

    @java.lang.annotation.Retention(java.lang.annotation.RetentionPolicy.RUNTIME)
    @java.lang.annotation.Target(java.lang.annotation.ElementType.FIELD)
    @interface XmlList {
    }

    static class XmlMapper {

        // -------- Objeto → XML --------

        static String toXml(Object obj) throws Exception {
            DocumentBuilderFactory dbf = DocumentBuilderFactory.newInstance();
            dbf.setNamespaceAware(true);
            Document doc = dbf.newDocumentBuilder().newDocument();
            doc.appendChild(buildElement(doc, null, obj));
            return documentToString(doc);
        }

        private static Element buildElement(Document doc, String forcedTagName, Object obj) throws Exception {
            Class<?> clazz = obj.getClass();
            String tagName = forcedTagName;
            String ns = "";
            if (clazz.isAnnotationPresent(XmlRootElement.class)) {
                XmlRootElement re = clazz.getAnnotation(XmlRootElement.class);
                if (tagName == null || tagName.isEmpty())
                    tagName = re.name().isEmpty() ? clazz.getSimpleName() : re.name();
                ns = re.namespace();
            }
            if (tagName == null || tagName.isEmpty())
                tagName = clazz.getSimpleName();

            Element el = ns.isEmpty() ? doc.createElement(tagName) : doc.createElementNS(ns, tagName);

            for (java.lang.reflect.Field field : getAllFields(clazz)) {
                field.setAccessible(true);
                Object value = field.get(obj);
                if (value == null)
                    continue;

                if (field.isAnnotationPresent(XmlAttribute.class)) {
                    XmlAttribute ann = field.getAnnotation(XmlAttribute.class);
                    el.setAttribute(ann.name().isEmpty() ? field.getName() : ann.name(), value.toString());
                    continue;
                }

                if (field.isAnnotationPresent(XmlList.class) && value instanceof java.util.List<?> list) {
                    XmlElement ann = field.getAnnotation(XmlElement.class);
                    String childNs = (ann != null && !ann.namespace().isEmpty()) ? ann.namespace() : "";
                    for (Object item : list) {
                        String itemTag = (ann != null && !ann.name().isEmpty()) ? ann.name()
                                : item.getClass().getSimpleName();
                        if (isPrimitive(item)) {
                            Element child = childNs.isEmpty() ? doc.createElement(itemTag)
                                    : doc.createElementNS(childNs, itemTag);
                            child.setTextContent(item.toString());
                            el.appendChild(child);
                        } else {
                            el.appendChild(buildElement(doc, itemTag, item));
                        }
                    }
                    continue;
                }

                if (field.isAnnotationPresent(XmlElement.class)) {
                    XmlElement ann = field.getAnnotation(XmlElement.class);
                    String childTag = ann.name().isEmpty() ? field.getName() : ann.name();
                    String childNs = ann.namespace();
                    if (isPrimitive(value)) {
                        Element child = childNs.isEmpty() ? doc.createElement(childTag)
                                : doc.createElementNS(childNs, childTag);
                        child.setTextContent(value.toString());
                        el.appendChild(child);
                    } else {
                        el.appendChild(buildElement(doc, childTag, value));
                    }
                }
            }
            return el;
        }

        // -------- XML → Objeto --------

        static <T> T fromXml(String xml, Class<T> clazz) throws Exception {
            DocumentBuilderFactory dbf = DocumentBuilderFactory.newInstance();
            dbf.setNamespaceAware(true);
            Document doc = dbf.newDocumentBuilder().parse(new InputSource(new StringReader(xml)));
            return parseElement(doc.getDocumentElement(), clazz);
        }

        @SuppressWarnings("unchecked")
        private static <T> T parseElement(Element el, Class<T> clazz) throws Exception {
            T obj = clazz.getDeclaredConstructor().newInstance();

            for (java.lang.reflect.Field field : getAllFields(clazz)) {
                field.setAccessible(true);

                if (field.isAnnotationPresent(XmlAttribute.class)) {
                    XmlAttribute ann = field.getAnnotation(XmlAttribute.class);
                    String attrName = ann.name().isEmpty() ? field.getName() : ann.name();
                    if (el.hasAttribute(attrName))
                        field.set(obj, convertValue(el.getAttribute(attrName), field.getType()));
                    continue;
                }

                if (field.isAnnotationPresent(XmlList.class)) {
                    XmlElement ann = field.getAnnotation(XmlElement.class);
                    String childTag = (ann != null && !ann.name().isEmpty()) ? ann.name() : field.getName();
                    java.lang.reflect.ParameterizedType pt = (java.lang.reflect.ParameterizedType) field
                            .getGenericType();
                    Class<?> itemType = (Class<?>) pt.getActualTypeArguments()[0];
                    java.util.List<Object> list = new java.util.ArrayList<>();
                    NodeList children = el.getChildNodes();
                    for (int i = 0; i < children.getLength(); i++) {
                        if (children.item(i) instanceof Element child && child.getLocalName() != null
                                && child.getLocalName().equals(childTag)) {
                            list.add(isPrimitiveClass(itemType)
                                    ? convertValue(child.getTextContent(), itemType)
                                    : parseElement(child, itemType));
                        }
                    }
                    field.set(obj, list);
                    continue;
                }

                if (field.isAnnotationPresent(XmlElement.class)) {
                    XmlElement ann = field.getAnnotation(XmlElement.class);
                    String childTag = ann.name().isEmpty() ? field.getName() : ann.name();
                    NodeList children = el.getChildNodes();
                    for (int i = 0; i < children.getLength(); i++) {
                        if (children.item(i) instanceof Element child) {
                            String localName = child.getLocalName() != null ? child.getLocalName() : child.getTagName();
                            if (localName.equals(childTag)) {
                                field.set(obj, isPrimitiveClass(field.getType())
                                        ? convertValue(child.getTextContent(), field.getType())
                                        : parseElement(child, field.getType()));
                                break;
                            }
                        }
                    }
                }
            }
            return obj;
        }

        // -------- Auxiliares internos --------

        private static java.util.List<java.lang.reflect.Field> getAllFields(Class<?> clazz) {
            java.util.List<java.lang.reflect.Field> fields = new java.util.ArrayList<>();
            for (Class<?> cur = clazz; cur != null && cur != Object.class; cur = cur.getSuperclass())
                fields.addAll(java.util.Arrays.asList(cur.getDeclaredFields()));
            return fields;
        }

        private static boolean isPrimitive(Object v) {
            return isPrimitiveClass(v.getClass());
        }

        private static boolean isPrimitiveClass(Class<?> c) {
            return c.isPrimitive() || c == String.class || c == Integer.class || c == Long.class
                    || c == Double.class || c == Float.class || c == Boolean.class || c == java.math.BigDecimal.class;
        }

        @SuppressWarnings("unchecked")
        private static <T> T convertValue(String text, Class<T> type) {
            if (type == String.class)
                return (T) text;
            if (type == int.class || type == Integer.class)
                return (T) Integer.valueOf(text.trim());
            if (type == long.class || type == Long.class)
                return (T) Long.valueOf(text.trim());
            if (type == double.class || type == Double.class)
                return (T) Double.valueOf(text.trim());
            if (type == boolean.class || type == Boolean.class)
                return (T) Boolean.valueOf(text.trim());
            if (type == java.math.BigDecimal.class)
                return (T) new java.math.BigDecimal(text.trim());
            return (T) text;
        }

        private static String documentToString(Document doc) throws Exception {
            Transformer tf = TransformerFactory.newInstance().newTransformer();
            tf.setOutputProperty(OutputKeys.INDENT, "yes");
            tf.setOutputProperty("{http://xml.apache.org/xslt}indent-amount", "2");
            tf.setOutputProperty(OutputKeys.ENCODING, "UTF-8");
            StringWriter sw = new StringWriter();
            tf.transform(new DOMSource(doc), new StreamResult(sw));
            return sw.toString();
        }
    }

    // =========================================================================
    // --- JsonMapper: Conversão Objeto <-> JSON (Java puro, sem bibliotecas)
    // =========================================================================
    //
    // Como usar:
    // String json = JsonMapper.toJson(objeto);
    // MinhaClasse obj = JsonMapper.fromJson(json, MinhaClasse.class);
    //
    // Anote seus POJOs com:
    // @JsonProperty(name="chave") — campo → chave JSON (obrigatório para mapear)
    // @JsonIgnore — exclui o campo da serialização

    @java.lang.annotation.Retention(java.lang.annotation.RetentionPolicy.RUNTIME)
    @java.lang.annotation.Target(java.lang.annotation.ElementType.FIELD)
    @interface JsonProperty {
        String name() default "";
    }

    @java.lang.annotation.Retention(java.lang.annotation.RetentionPolicy.RUNTIME)
    @java.lang.annotation.Target(java.lang.annotation.ElementType.FIELD)
    @interface JsonIgnore {
    }

    static class JsonMapper {

        // -------- Objeto → JSON --------

        static String toJson(Object obj) throws Exception {
            if (obj == null)
                return "null";
            if (obj instanceof String s)
                return "\"" + escapeString(s) + "\"";
            if (obj instanceof Number || obj instanceof Boolean)
                return obj.toString();
            if (obj instanceof java.util.List<?> list)
                return listToJson(list);
            return objectToJson(obj);
        }

        private static String objectToJson(Object obj) throws Exception {
            Class<?> clazz = obj.getClass();
            StringBuilder sb = new StringBuilder("{");
            boolean first = true;

            for (java.lang.reflect.Field field : getAllFields(clazz)) {
                if (field.isAnnotationPresent(JsonIgnore.class))
                    continue;
                if (!field.isAnnotationPresent(JsonProperty.class))
                    continue;

                field.setAccessible(true);
                Object value = field.get(obj);
                if (value == null)
                    continue;

                JsonProperty ann = field.getAnnotation(JsonProperty.class);
                String key = ann.name().isEmpty() ? field.getName() : ann.name();

                if (!first)
                    sb.append(",");
                sb.append("\"").append(escapeString(key)).append("\":").append(toJson(value));
                first = false;
            }

            sb.append("}");
            return sb.toString();
        }

        private static String listToJson(java.util.List<?> list) throws Exception {
            StringBuilder sb = new StringBuilder("[");
            for (int i = 0; i < list.size(); i++) {
                if (i > 0)
                    sb.append(",");
                sb.append(toJson(list.get(i)));
            }
            sb.append("]");
            return sb.toString();
        }

        // -------- JSON → Objeto --------

        static <T> T fromJson(String json, Class<T> clazz) throws Exception {
            Object parsed = new JsonParser(json.trim()).parseValue();
            if (!(parsed instanceof java.util.Map))
                throw new IllegalArgumentException("JSON raiz deve ser um objeto {}");
            @SuppressWarnings("unchecked")
            java.util.Map<String, Object> map = (java.util.Map<String, Object>) parsed;
            return populateObject(map, clazz);
        }

        @SuppressWarnings("unchecked")
        private static <T> T populateObject(java.util.Map<String, Object> map, Class<T> clazz) throws Exception {
            T obj = clazz.getDeclaredConstructor().newInstance();

            for (java.lang.reflect.Field field : getAllFields(clazz)) {
                if (field.isAnnotationPresent(JsonIgnore.class))
                    continue;
                if (!field.isAnnotationPresent(JsonProperty.class))
                    continue;

                JsonProperty ann = field.getAnnotation(JsonProperty.class);
                String key = ann.name().isEmpty() ? field.getName() : ann.name();
                if (!map.containsKey(key))
                    continue;

                field.setAccessible(true);
                Object raw = map.get(key);

                if (raw == null) {
                    field.set(obj, null);
                } else if (raw instanceof java.util.Map<?, ?> nested) {
                    field.set(obj, populateObject((java.util.Map<String, Object>) nested, field.getType()));
                } else if (raw instanceof java.util.List<?> rawList && isListField(field)) {
                    Class<?> itemType = getListItemType(field);
                    java.util.List<Object> result = new java.util.ArrayList<>();
                    for (Object item : rawList) {
                        if (item instanceof java.util.Map<?, ?> nestedItem)
                            result.add(populateObject((java.util.Map<String, Object>) nestedItem, itemType));
                        else
                            result.add(convertPrimitive(item, itemType));
                    }
                    field.set(obj, result);
                } else {
                    field.set(obj, convertPrimitive(raw, field.getType()));
                }
            }
            return obj;
        }

        // -------- Parser de JSON --------

        /** Tokenizer/parser recursivo-descendente para JSON. */
        private static class JsonParser {
            private final String src;
            private int pos;

            JsonParser(String src) {
                this.src = src;
                this.pos = 0;
            }

            Object parseValue() {
                skipWhitespace();
                if (pos >= src.length())
                    throw new IllegalArgumentException("JSON inesperadamente vazio na posição " + pos);
                char c = src.charAt(pos);
                if (c == '{')
                    return parseObject();
                if (c == '[')
                    return parseArray();
                if (c == '"')
                    return parseString();
                if (c == 't')
                    return parseLiteral("true", Boolean.TRUE);
                if (c == 'f')
                    return parseLiteral("false", Boolean.FALSE);
                if (c == 'n')
                    return parseLiteral("null", null);
                if (c == '-' || Character.isDigit(c))
                    return parseNumber();
                throw new IllegalArgumentException("Token inesperado '" + c + "' na posição " + pos);
            }

            private java.util.Map<String, Object> parseObject() {
                java.util.Map<String, Object> map = new java.util.LinkedHashMap<>();
                pos++; // consume '{'
                skipWhitespace();
                if (peek() == '}') {
                    pos++;
                    return map;
                }

                do {
                    skipWhitespace();
                    String key = parseString();
                    skipWhitespace();
                    expect(':');
                    skipWhitespace();
                    Object value = parseValue();
                    map.put(key, value);
                    skipWhitespace();
                } while (peek() == ',' && pos++ >= 0);

                expect('}');
                return map;
            }

            private java.util.List<Object> parseArray() {
                java.util.List<Object> list = new java.util.ArrayList<>();
                pos++; // consume '['
                skipWhitespace();
                if (peek() == ']') {
                    pos++;
                    return list;
                }

                do {
                    skipWhitespace();
                    list.add(parseValue());
                    skipWhitespace();
                } while (peek() == ',' && pos++ >= 0);

                expect(']');
                return list;
            }

            private String parseString() {
                expect('"');
                StringBuilder sb = new StringBuilder();
                while (pos < src.length()) {
                    char c = src.charAt(pos++);
                    if (c == '"')
                        return sb.toString();
                    if (c == '\\') {
                        char esc = src.charAt(pos++);
                        switch (esc) {
                            case '"' -> sb.append('"');
                            case '\\' -> sb.append('\\');
                            case '/' -> sb.append('/');
                            case 'n' -> sb.append('\n');
                            case 'r' -> sb.append('\r');
                            case 't' -> sb.append('\t');
                            case 'b' -> sb.append('\b');
                            case 'f' -> sb.append('\f');
                            case 'u' -> {
                                String hex = src.substring(pos, pos + 4);
                                sb.append((char) Integer.parseInt(hex, 16));
                                pos += 4;
                            }
                            default -> sb.append(esc);
                        }
                    } else {
                        sb.append(c);
                    }
                }
                throw new IllegalArgumentException("String JSON não fechada");
            }

            private Number parseNumber() {
                int start = pos;
                if (peek() == '-')
                    pos++;
                while (pos < src.length()
                        && (Character.isDigit(src.charAt(pos)) || src.charAt(pos) == '.' || src.charAt(pos) == 'e'
                                || src.charAt(pos) == 'E' || src.charAt(pos) == '+' || src.charAt(pos) == '-'))
                    pos++;
                String raw = src.substring(start, pos);
                return raw.contains(".") || raw.contains("e") || raw.contains("E")
                        ? Double.parseDouble(raw)
                        : Long.parseLong(raw);
            }

            private Object parseLiteral(String literal, Object value) {
                if (src.startsWith(literal, pos)) {
                    pos += literal.length();
                    return value;
                }
                throw new IllegalArgumentException("Literal inválido na posição " + pos);
            }

            private void skipWhitespace() {
                while (pos < src.length() && Character.isWhitespace(src.charAt(pos)))
                    pos++;
            }

            private char peek() {
                return pos < src.length() ? src.charAt(pos) : 0;
            }

            private void expect(char c) {
                if (pos >= src.length() || src.charAt(pos) != c)
                    throw new IllegalArgumentException("Esperado '" + c + "' na posição " + pos);
                pos++;
            }
        }

        // -------- Auxiliares internos --------

        private static java.util.List<java.lang.reflect.Field> getAllFields(Class<?> clazz) {
            java.util.List<java.lang.reflect.Field> fields = new java.util.ArrayList<>();
            for (Class<?> cur = clazz; cur != null && cur != Object.class; cur = cur.getSuperclass())
                fields.addAll(java.util.Arrays.asList(cur.getDeclaredFields()));
            return fields;
        }

        private static boolean isListField(java.lang.reflect.Field field) {
            return java.util.List.class.isAssignableFrom(field.getType());
        }

        private static Class<?> getListItemType(java.lang.reflect.Field field) {
            java.lang.reflect.ParameterizedType pt = (java.lang.reflect.ParameterizedType) field.getGenericType();
            return (Class<?>) pt.getActualTypeArguments()[0];
        }

        @SuppressWarnings("unchecked")
        private static <T> T convertPrimitive(Object value, Class<T> type) {
            if (type == String.class)
                return (T) value.toString();
            if (type == int.class || type == Integer.class)
                return (T) Integer.valueOf(((Number) value).intValue());
            if (type == long.class || type == Long.class)
                return (T) Long.valueOf(((Number) value).longValue());
            if (type == double.class || type == Double.class)
                return (T) Double.valueOf(((Number) value).doubleValue());
            if (type == boolean.class || type == Boolean.class)
                return (T) value;
            if (type == java.math.BigDecimal.class)
                return (T) new java.math.BigDecimal(value.toString());
            return (T) value;
        }

        private static String escapeString(String s) {
            StringBuilder sb = new StringBuilder();
            for (char c : s.toCharArray()) {
                switch (c) {
                    case '"' -> sb.append("\\\"");
                    case '\\' -> sb.append("\\\\");
                    case '\n' -> sb.append("\\n");
                    case '\r' -> sb.append("\\r");
                    case '\t' -> sb.append("\\t");
                    case '\b' -> sb.append("\\b");
                    case '\f' -> sb.append("\\f");
                    default -> {
                        if (c < 0x20)
                            sb.append(String.format("\\u%04x", (int) c));
                        else
                            sb.append(c);
                    }
                }
            }
            return sb.toString();
        }
    }

    // =========================================================================
    // --- Modelos Fiscais Anotados
    // =========================================================================

    /** Consulta de Status de Serviço — NFe / CTe / NFCe. */
    @XmlRootElement(name = "consStatServ", namespace = "http://www.portalfiscal.inf.br/nfe")
    static class ConsStatServ {
        @XmlAttribute(name = "versao")
        String versao;
        @XmlElement(name = "tpAmb")
        String tpAmb;
        @XmlElement(name = "cUF")
        String cUF;
        @XmlElement(name = "xServ")
        String xServ;

        ConsStatServ() {
        }

        ConsStatServ(String versao, String tpAmb, String cUF) {
            this.versao = versao;
            this.tpAmb = tpAmb;
            this.cUF = cUF;
            this.xServ = "STATUS";
        }

        @Override
        public String toString() {
            return "ConsStatServ{versao='" + versao + "', tpAmb='" + tpAmb + "', cUF='" + cUF + "', xServ='" + xServ
                    + "'}";
        }
    }

    /** Identificação da NFe — subconjunto para demonstração. */
    @XmlRootElement(name = "ide")
    static class NFeIde {
        @XmlElement(name = "cUF")
        String cUF;
        @XmlElement(name = "natOp")
        String natOp;
        @XmlElement(name = "mod")
        String mod;
        @XmlElement(name = "serie")
        String serie;
        @XmlElement(name = "nNF")
        String nNF;
        @XmlElement(name = "dhEmi")
        String dhEmi;
        @XmlElement(name = "tpAmb")
        String tpAmb;

        NFeIde() {
        }

        @Override
        public String toString() {
            return "NFeIde{mod='" + mod + "', serie='" + serie + "', nNF='" + nNF + "', cUF='" + cUF + "', dhEmi='"
                    + dhEmi + "'}";
        }
    }

    /** NFe simplificada contendo apenas ide — para demonstração de aninhamento. */
    @XmlRootElement(name = "NFe", namespace = "http://www.portalfiscal.inf.br/nfe")
    static class NFeSimples {
        @XmlElement(name = "ide")
        NFeIde ide;

        NFeSimples() {
        }

        NFeSimples(NFeIde ide) {
            this.ide = ide;
        }

        @Override
        public String toString() {
            return "NFeSimples{ide=" + ide + "}";
        }
    }

    // =========================================================================
    // --- Utilitários Internos
    // =========================================================================

    /** Serializa um Element DOM isolado para String sem declaração XML. */
    private static String elementToString(Element el) throws Exception {
        Transformer tf = TransformerFactory.newInstance().newTransformer();
        tf.setOutputProperty(OutputKeys.OMIT_XML_DECLARATION, "yes");
        StringWriter sw = new StringWriter();
        tf.transform(new DOMSource(el), new StreamResult(sw));
        return sw.toString();
    }

    /**
     * Configura o console para exibir apenas [NÍVEL] Mensagem, sem metadados do
     * JUL.
     */
    private static void configureCleanLogger() {
        Logger root = Logger.getLogger("");
        for (Handler h : root.getHandlers())
            root.removeHandler(h);
        ConsoleHandler handler = new ConsoleHandler();
        handler.setFormatter(new Formatter() {
            @Override
            public String format(LogRecord record) {
                return String.format("[%s] %s%n", record.getLevel(), record.getMessage());
            }
        });
        handler.setLevel(Level.INFO);
        root.addHandler(handler);
    }

    // =========================================================================
    // --- Utilitários de Manutenção de Certificados
    // =========================================================================

    /**
     * Migra um PFX legado (RC2/SHA-1) para o formato moderno (AES-256/SHA-256).
     * O JDK 11+ aplica a criptografia forte automaticamente ao salvar.
     */
    static void upgradePfx(String pathAntigo, String pathNovo, char[] password) throws Exception {
        KeyStore ks = KeyStore.getInstance("PKCS12");
        try (FileInputStream fis = new FileInputStream(pathAntigo)) {
            ks.load(fis, password);
        }
        try (FileOutputStream fos = new FileOutputStream(pathNovo)) {
            ks.store(fos, password);
        }
        log.info("PFX migrado com sucesso: " + pathNovo);
    }

    /**
     * Instala um PFX no repositório pessoal do usuário Windows (Windows-MY).
     * Requer SunMSCAPI — funciona apenas em Windows.
     */
    static void instalarNoWindows(String pfxPath, String pfxPass) throws Exception {
        KeyStore pfxStore = KeyStore.getInstance("PKCS12");
        try (InputStream in = Files.newInputStream(Paths.get(pfxPath))) {
            pfxStore.load(in, pfxPass.toCharArray());
        }

        KeyStore winStore = KeyStore.getInstance("Windows-MY", "SunMSCAPI");
        winStore.load(null, null);

        Enumeration<String> aliases = pfxStore.aliases();
        while (aliases.hasMoreElements()) {
            String alias = aliases.nextElement();
            if (pfxStore.isKeyEntry(alias)) {
                Key key = pfxStore.getKey(alias, pfxPass.toCharArray());
                Certificate[] chain = pfxStore.getCertificateChain(alias);
                winStore.setKeyEntry(alias, key, null, chain);
                log.info("Certificado importado para Windows-MY: " + alias);
            }
        }
    }
}