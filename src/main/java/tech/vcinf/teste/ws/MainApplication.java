package tech.vcinf.teste.ws;

import org.springframework.boot.ApplicationArguments;
import org.springframework.boot.ApplicationRunner;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;

import javax.net.ssl.*;
import java.io.*;
import java.net.URI;
import java.net.URL;
import java.net.http.*;
import java.nio.charset.StandardCharsets;
import java.nio.file.*;
import java.security.KeyStore;
import java.security.MessageDigest;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.time.Duration;
import java.util.Enumeration;
import java.util.List;
import java.util.logging.Logger;

@SpringBootApplication
public class MainApplication implements ApplicationRunner {
    private static final Logger log = Logger.getLogger(MainApplication.class.getName());

    // --- CONFIGURAÇÕES ---
    private static final String PFX_PATH = "C:/certificado/407.pfx";
    private static final String PFX_PASS = "12345";
    private static final String WIN_THUMB = "C48514B5EDF842D34C322A1AAFAF8F6FDA3117A7";
    private static final String ENDPOINT  = "https://nfe.sefaz.mt.gov.br/nfews/v2/services/NfeStatusServico4";
    private static final String CACERT_FILE = "cacerts_vcinf"; // Nome do arquivo local

    @Override
    public void run(ApplicationArguments args) {
        log.info(">>> INICIANDO AMBIENTE SSL/TLS...");

        // 1. FASE DE GERAÇÃO: Cria o TrustStore com as cadeias da SEFAZ e ICP-Brasil
        gerarTrustStore();

        // 2. FASE DE TESTE: Executa as chamadas mTLS
        log.info(">>> INICIANDO TESTES DE REQUISIÇÃO...");
        executarTeste("WINDOWS-MY", criarSslContextWindows(WIN_THUMB));
        executarTeste("PFX-ARQUIVO", criarSslContextPfx(PFX_PATH, PFX_PASS));
    }

    // ========== MÉTODOS DE GERAÇÃO (ANTIGO CACERTUTIL) ==========

    private void gerarTrustStore() {
        try {
            log.info("Gerando TrustStore local: " + CACERT_FILE);
            Path base = Paths.get(System.getProperty("java.home"), "lib", "security", "cacerts");
            KeyStore ks = KeyStore.getInstance(KeyStore.getDefaultType());
            
            try (InputStream is = Files.newInputStream(base)) { ks.load(is, "changeit".toCharArray()); }

            // Importa Raízes ICP-Brasil
            CertificateFactory cf = CertificateFactory.getInstance("X.509");
            List.of("v10", "v5", "v2").forEach(v -> {
                try (InputStream in = new URL("http://acraiz.icpbrasil.gov.br/credenciadas/RAIZ/ICP-Brasil" + v + ".crt").openStream()) {
                    ks.setCertificateEntry("icp-" + v, (X509Certificate) cf.generateCertificate(in));
                } catch (Exception e) { log.warning("Falha ao baixar ICP " + v); }
            });

            // Captura dinâmica dos hosts SEFAZ
            List.of("nfe.sefaz.mt.gov.br", "nfce.sefaz.mt.gov.br").forEach(host -> {
                try { capturarCadeia(host, ks); } catch (Exception e) { log.warning("Erro no host: " + host); }
            });

            try (OutputStream os = Files.newOutputStream(Paths.get(CACERT_FILE))) { ks.store(os, "changeit".toCharArray()); }
            log.info("TrustStore gerado com sucesso!");
        } catch (Exception e) { log.severe("Erro ao gerar TrustStore: " + e.getMessage()); }
    }

    private void capturarCadeia(String host, KeyStore ks) throws Exception {
        SSLContext ctx = SSLContext.getInstance("TLSv1.2");
        CapturingTrustManager ctm = new CapturingTrustManager();
        ctx.init(null, new TrustManager[]{ctm}, null);
        try (SSLSocket s = (SSLSocket) ctx.getSocketFactory().createSocket(host, 443)) {
            s.setSoTimeout(5000);
            SSLParameters p = s.getSSLParameters();
            p.setServerNames(List.of(new SNIHostName(host)));
            s.setSSLParameters(p);
            s.startHandshake();
        } catch (IOException ignored) {}
        if (ctm.chain != null) {
            for (int i = 0; i < ctm.chain.length; i++) ks.setCertificateEntry(host + "-" + i, ctm.chain[i]);
        }
    }

    // ========== MÉTODOS DE SSL (CONTEXTO) ==========

    private SSLContext criarSslContextWindows(String thumb) {
        try {
            KeyStore ks = KeyStore.getInstance("Windows-MY");
            ks.load(null, null);
            String alias = buscarAlias(ks, thumb);
            return (alias != null) ? finalizarSsl(ks, null) : null;
        } catch (Exception e) { return null; }
    }

    private SSLContext criarSslContextPfx(String p, String s) {
        try {
            KeyStore ks = KeyStore.getInstance("PKCS12");
            try (InputStream in = Files.newInputStream(Paths.get(p))) { ks.load(in, s.toCharArray()); }
            return finalizarSsl(ks, s);
        } catch (Exception e) { return null; }
    }

    private SSLContext finalizarSsl(KeyStore identity, String pass) throws Exception {
        KeyStore trust = KeyStore.getInstance(KeyStore.getDefaultType());
        try (InputStream in = Files.newInputStream(Paths.get(CACERT_FILE))) { trust.load(in, "changeit".toCharArray()); }

        KeyManagerFactory kmf = KeyManagerFactory.getInstance("SunX509");
        kmf.init(identity, pass != null ? pass.toCharArray() : null);
        TrustManagerFactory tmf = TrustManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm());
        tmf.init(trust);

        SSLContext ctx = SSLContext.getInstance("TLSv1.2");
        ctx.init(kmf.getKeyManagers(), tmf.getTrustManagers(), null);
        return ctx;
    }

    // ========== EXECUÇÃO E AUXILIARES ==========

    private void executarTeste(String label, SSLContext ctx) {
        if (ctx == null) { log.severe(label + " | Falha no contexto."); return; }
        try {
            HttpClient client = HttpClient.newBuilder().sslContext(ctx).connectTimeout(Duration.ofSeconds(15)).build();
            HttpRequest req = HttpRequest.newBuilder().uri(URI.create(ENDPOINT))
                    .header("Content-Type", "application/soap+xml; charset=utf-8")
                    .POST(HttpRequest.BodyPublishers.ofString(getXml(), StandardCharsets.UTF_8)).build();

            HttpResponse<String> res = client.send(req, HttpResponse.BodyHandlers.ofString());
            log.info(label + " | HTTP " + res.statusCode() + " | Sucesso!");
        } catch (Exception e) { log.warning(label + " | Erro: " + e.getMessage()); }
    }

    private String buscarAlias(KeyStore ks, String thumb) throws Exception {
        String target = thumb.replaceAll("[^0-9A-Fa-f]", "").toUpperCase();
        MessageDigest sha1 = MessageDigest.getInstance("SHA-1");
        Enumeration<String> al = ks.aliases();
        while (al.hasMoreElements()) {
            String a = al.nextElement();
            X509Certificate c = (X509Certificate) ks.getCertificate(a);
            if (c != null && hex(sha1.digest(c.getEncoded())).equals(target)) return a;
        }
        return null;
    }

    private String hex(byte[] bytes) {
        StringBuilder sb = new StringBuilder();
        for (byte b : bytes) sb.append(String.format("%02X", b));
        return sb.toString();
    }

    private String getXml() {
        return "<?xml version=\"1.0\" encoding=\"utf-8\"?><soap12:Envelope xmlns:soap12=\"http://www.w3.org/2003/05/soap-envelope\"><soap12:Body><nfeDadosMsg xmlns=\"http://www.portalfiscal.inf.br/nfe/wsdl/NFeStatusServico4\"><consStatServ xmlns=\"http://www.portalfiscal.inf.br/nfe\" versao=\"4.00\"><tpAmb>1</tpAmb><cUF>51</cUF><xServ>STATUS</xServ></consStatServ></nfeDadosMsg></soap12:Body></soap12:Envelope>";
    }

    private static class CapturingTrustManager implements X509TrustManager {
        private X509Certificate[] chain;
        public void checkServerTrusted(X509Certificate[] c, String a) { this.chain = c; }
        public void checkClientTrusted(X509Certificate[] c, String a) {}
        public X509Certificate[] getAcceptedIssuers() { return new X509Certificate[0]; }
    }

    public static void main(String[] args) { SpringApplication.run(MainApplication.class, args); }
}