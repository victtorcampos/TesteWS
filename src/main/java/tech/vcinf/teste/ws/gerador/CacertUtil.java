package tech.vcinf.teste.ws.gerador;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Component;

import javax.net.ssl.*;
import java.io.*;
import java.net.URL;
import java.nio.file.*;
import java.security.KeyStore;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.List;

@Component
public class CacertUtil {
    private static final Logger log = LoggerFactory.getLogger(CacertUtil.class);
    private static final String PASS = "changeit";

    // Links oficiais das Raízes da ICP-Brasil
    private static final List<String> ICP_URLS = List.of(
            "http://acraiz.icpbrasil.gov.br/credenciadas/RAIZ/ICP-Brasilv10.crt",
            "http://acraiz.icpbrasil.gov.br/credenciadas/RAIZ/ICP-Brasilv5.crt",
            "http://acraiz.icpbrasil.gov.br/credenciadas/RAIZ/ICP-Brasilv2.crt");

    // Hosts da SEFAZ para captura dinâmica de certificados
    private static final List<String> HOSTS = List.of(
            "nfe.sefaz.mt.gov.br",
            "nfce.sefaz.mt.gov.br",
            "mdfe.svrs.rs.gov.br");

    public static void createTrustStore() {
        log.info("Gerando TrustStore customizado...");
        Path cacertsDefault = Paths.get(System.getProperty("java.home"), "lib", "security", "cacerts");
        Path novoCacert = Paths.get("cacerts");

        try {
            // 1. Carrega o KeyStore base da JDK
            KeyStore ks = KeyStore.getInstance(KeyStore.getDefaultType());
            try (InputStream is = Files.newInputStream(cacertsDefault)) {
                ks.load(is, PASS.toCharArray());
            }

            // 2. Importa Raízes ICP-Brasil (Certificados Estáticos via HTTP)
            CertificateFactory cf = CertificateFactory.getInstance("X.509");
            for (String url : ICP_URLS) {
                try (InputStream in = new URL(url).openStream()) {
                    X509Certificate cert = (X509Certificate) cf.generateCertificate(in);
                    ks.setCertificateEntry("icp-" + url.substring(url.length() - 7, url.length() - 4), cert);
                } catch (Exception e) {
                    log.warn("Falha ao baixar raiz: " + url);
                }
            }

            // 3. Importa Cadeias dos Hosts (Captura Dinâmica via Handshake)
            for (String host : HOSTS) {
                capturarCadeiaHost(host, ks);
            }

            // 4. Salva o arquivo final no diretório da aplicação
            try (OutputStream os = Files.newOutputStream(novoCacert)) {
                ks.store(os, PASS.toCharArray());
            }
            log.info("Sucesso! TrustStore criado em: " + novoCacert.toAbsolutePath());

        } catch (Exception e) {
            log.error("Erro crítico na geração: " + e.getMessage());
        }
    }

    private static void capturarCadeiaHost(String host, KeyStore ks) {
        try {
            SSLContext ctx = SSLContext.getInstance("TLSv1.2");
            CapturingTrustManager ctm = new CapturingTrustManager();
            ctx.init(null, new TrustManager[] { ctm }, null);

            // Tenta o handshake apenas para disparar o CapturingTrustManager
            try (SSLSocket socket = (SSLSocket) ctx.getSocketFactory().createSocket(host, 443)) {
                socket.setSoTimeout(5000);
                SSLParameters params = socket.getSSLParameters();
                params.setServerNames(List.of(new SNIHostName(host)));
                socket.setSSLParameters(params);
                socket.startHandshake();
            } catch (IOException ignored) {
            } // Frequentemente fecha após enviar certs

            if (ctm.chain != null) {
                for (int i = 0; i < ctm.chain.length; i++) {
                    ks.setCertificateEntry(host + "-" + i, ctm.chain[i]);
                }
            }
        } catch (Exception e) {
            log.warn("Erro ao capturar host " + host);
        }
    }

    // Classe interna para interceptar os certificados durante o handshake
    private static class CapturingTrustManager implements X509TrustManager {
        private X509Certificate[] chain;

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