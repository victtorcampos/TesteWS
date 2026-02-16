package tech.vcinf.teste.ws.http;

import javax.net.ssl.KeyManagerFactory;
import javax.net.ssl.SSLContext;
import javax.net.ssl.TrustManagerFactory;
import java.io.InputStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.KeyStore;
import java.security.SecureRandom;

public class SslContextUtils {

    /**
     * Cria um contexto SSL configurado para Autenticação Mútua (mTLS).
     * 
     * @param pfxPath        Caminho para o certificado A1 (.pfx ou .p12)
     * @param senha          Senha do certificado
     * @param trustStorePath Caminho para o arquivo gerado pelo CacertUtil
     * @return SSLContext configurado
     */
    public static SSLContext criarContexto(String pfxPath, String senha, String trustStorePath) {
        try { 
            char[] passwordArray = senha.toCharArray();

            // 1. Carregar o Certificado Cliente (KeyStore - QUEM EU SOU)
            KeyStore keyStore = KeyStore.getInstance("PKCS12");
            try (InputStream is = Files.newInputStream(Paths.get(pfxPath))) {
                keyStore.load(is, passwordArray);
            }

            KeyManagerFactory kmf = KeyManagerFactory.getInstance(KeyManagerFactory.getDefaultAlgorithm());
            kmf.init(keyStore, passwordArray);

            // 2. Carregar o TrustStore (EM QUEM EU CONFIO - O cacerts que você gerou)
            KeyStore trustStore = KeyStore.getInstance(KeyStore.getDefaultType());
            try (InputStream is = Files.newInputStream(Paths.get(trustStorePath))) {
                trustStore.load(is, "changeit".toCharArray());
            }

            TrustManagerFactory tmf = TrustManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm());
            tmf.init(trustStore);

            // 3. Inicializar o Contexto com TLS 1.2 (Padrão SEFAZ)
            SSLContext sslContext = SSLContext.getInstance("TLSv1.2");
            sslContext.init(kmf.getKeyManagers(), tmf.getTrustManagers(), new SecureRandom());

            return sslContext;

        } catch (Exception e) {
            throw new RuntimeException("Falha ao criar SSLContext para SEFAZ: " + e.getMessage(), e);
        }
    }
}