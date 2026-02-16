package tech.vcinf.teste.ws.gerador;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.boot.ApplicationArguments;
import org.springframework.boot.ApplicationRunner;
import org.springframework.stereotype.Component;

import javax.net.ssl.*;
import java.io.*;
import java.net.URL;
import java.net.URLConnection;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.KeyStore;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.Arrays;
import java.util.List;

@Component
public class CacertUtil {

    private static final Logger logger = LoggerFactory.getLogger(CacertUtil.class);
    private static final String SENHA = "changeit";
    private static final List<String> ICP_BRASIL_URLS = Arrays.asList(
            "http://acraiz.icpbrasil.gov.br/credenciadas/RAIZ/ICP-Brasilv10.crt",
            "http://acraiz.icpbrasil.gov.br/credenciadas/RAIZ/ICP-Brasilv5.crt",
            "http://acraiz.icpbrasil.gov.br/credenciadas/RAIZ/ICP-Brasilv2.crt");

    public static void createTrustStore() {
        logger.info("Iniciando Gerador de TrustStore Integrado (Hosts + ICP-Brasil)...");

        List<String> hosts = List.of("nfe.sefaz.mt.gov.br", "nfce.sefaz.mt.gov.br", "mdfe.svrs.rs.gov.br");
        Path pathOrigem = Paths.get(System.getProperty("java.home"), "lib", "security", "cacerts");
        Path pathDestino = Paths.get("cacerts");

        try {
            KeyStore ks = loadKeyStore(pathOrigem);

            // 1. Baixar e incluir Raízes ICP-Brasil
            for (String url : ICP_BRASIL_URLS) {
                importarRaizIcp(url, ks);
            }

            // 2. Capturar certificados dos Hosts (SEFAZ)
            for (String host : hosts) {
                importarCertificadosHost(host, ks);
            }

            saveKeyStore(ks, pathDestino);

            logger.info("Processo concluído com sucesso. Arquivo: {}", pathDestino.toAbsolutePath());

        } catch (Exception e) {
            logger.error("Falha no gerador: ", e);
        }
    }

    private static void importarRaizIcp(String urlStr, KeyStore ks) {
        try {
            logger.info("Baixando Raiz ICP: {}...", urlStr);
            URL url = new URL(urlStr);
            URLConnection conn = url.openConnection();
            conn.setConnectTimeout(5000);
            conn.setReadTimeout(5000);

            try (InputStream in = conn.getInputStream()) {
                CertificateFactory cf = CertificateFactory.getInstance("X.509");
                X509Certificate cert = (X509Certificate) cf.generateCertificate(in);
                String alias = "icp-brasil-" + urlStr.substring(urlStr.lastIndexOf("v"), urlStr.lastIndexOf("."));
                ks.setCertificateEntry(alias, cert);
                logger.info("Raiz {} adicionada ao KeyStore.", alias);
            }
        } catch (Exception e) {
            logger.warn("Não foi possível baixar a raiz {}: {}", urlStr, e.getMessage());
        }
    }

    private static void importarCertificadosHost(String host, KeyStore ks) {
        try {
            logger.info("Conectando ao host SEFAZ: {}...", host);
            SSLContext context = SSLContext.getInstance("TLSv1.2");
            CapturingTrustManager ctm = new CapturingTrustManager();
            context.init(null, new TrustManager[] { ctm }, null);

            SSLSocketFactory factory = context.getSocketFactory();
            try (SSLSocket socket = (SSLSocket) factory.createSocket(host, 443)) {
                socket.setSoTimeout(10000);
                SSLParameters params = socket.getSSLParameters();
                params.setServerNames(List.of(new SNIHostName(host)));
                socket.setSSLParameters(params);
                socket.startHandshake();
            } catch (IOException ignored) {
            }

            if (ctm.chain != null) {
                for (int i = 0; i < ctm.chain.length; i++) {
                    ks.setCertificateEntry(host + "-" + i, ctm.chain[i]);
                }
                logger.info("Cadeia do host {} importada.", host);
            }
        } catch (Exception e) {
            logger.error("Erro no host {}: {}", host, e.getMessage());
        }
    }

    private static KeyStore loadKeyStore(Path path) throws Exception {
        KeyStore ks = KeyStore.getInstance(KeyStore.getDefaultType());
        try (InputStream in = Files.newInputStream(path)) {
            ks.load(in, SENHA.toCharArray());
        }
        return ks;
    }

    private static void saveKeyStore(KeyStore ks, Path path) throws Exception {
        try (OutputStream out = Files.newOutputStream(path)) {
            ks.store(out, SENHA.toCharArray());
        }
    }

    private static class CapturingTrustManager implements X509TrustManager {
        private X509Certificate[] chain;

        @Override
        public void checkServerTrusted(X509Certificate[] chain, String authType) {
            this.chain = chain;
        }

        @Override
        public void checkClientTrusted(X509Certificate[] chain, String authType) {
        }

        @Override
        public X509Certificate[] getAcceptedIssuers() {
            return new X509Certificate[0];
        }
    }

}