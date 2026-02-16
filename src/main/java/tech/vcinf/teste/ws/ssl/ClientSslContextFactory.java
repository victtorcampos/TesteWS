package tech.vcinf.teste.ws.ssl;

import tech.vcinf.teste.ws.cert.ClientCertificateConfig;
import tech.vcinf.teste.ws.cert.PfxConfig;
import tech.vcinf.teste.ws.cert.WindowsMyConfig;

import javax.net.ssl.KeyManagerFactory;
import javax.net.ssl.SSLContext;
import javax.net.ssl.TrustManagerFactory;
import java.io.InputStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.KeyStore;
import java.security.MessageDigest;
import java.security.cert.X509Certificate;
import java.util.Enumeration;
import java.util.logging.Level;
import java.util.logging.Logger;

/**
 * Fábrica de SSLContext para certificados de cliente A1.
 * Suporta Windows Certificate Store (Windows-MY) e arquivos PKCS#12 (.pfx).
 */
public final class ClientSslContextFactory {
    
    private static final Logger logger = Logger.getLogger(ClientSslContextFactory.class.getName());
    
    private ClientSslContextFactory() {
        throw new UnsupportedOperationException("Classe utilitária não pode ser instanciada");
    }
    
    /**
     * Cria um SSLContext a partir da configuração de certificado fornecida.
     * 
     * @param config Configuração do certificado (WindowsMyConfig ou PfxConfig)
     * @return SSLContext configurado para mTLS
     * @throws RuntimeException se ocorrer erro ao criar o contexto
     */
    public static SSLContext from(ClientCertificateConfig config) {
        logger.info("Criando SSLContext para tipo: " + config.getType());
        
        // Usar if/instanceof (Java 17) em vez de pattern matching switch (Java 21+)
        if (config instanceof WindowsMyConfig w) {
            return fromWindowsStore(w);
        }
        if (config instanceof PfxConfig p) {
            return fromPfx(p);
        }
        throw new IllegalArgumentException("Tipo de certificado não suportado: " + config);
    }
    
    /**
     * Cria SSLContext a partir do Windows Certificate Store (Windows-MY).
     */
    private static SSLContext fromWindowsStore(WindowsMyConfig config) {
        try {
            // 1. Carregar KeyStore do Windows
            KeyStore ks = KeyStore.getInstance("Windows-MY");
            ks.load(null, null);
            
            // 2. Buscar certificado por thumbprint
            String alias = findAliasByThumbprint(ks, config.thumbprint());
            if (alias == null) {
                throw new IllegalStateException(
                    "Certificado não encontrado no Windows Store com thumbprint: " + config.thumbprint()
                );
            }
            
            logger.info("Certificado encontrado com alias: " + alias);
            
            // 3. Validar chave privada
            if (ks.getKey(alias, null) == null) {
                throw new IllegalStateException(
                    "Chave privada não disponível para alias: " + alias + " (possível chave não exportável)"
                );
            }
            
            // 4. Logar informações do certificado
            X509Certificate cert = (X509Certificate) ks.getCertificate(alias);
            logger.info("Subject: " + cert.getSubjectX500Principal().getName());
            logger.info("Validade: " + cert.getNotBefore() + " até " + cert.getNotAfter());
            
            // 5. Inicializar KeyManagerFactory (senha NULL para Windows-MY)
            KeyManagerFactory kmf = KeyManagerFactory.getInstance("SunX509");
            kmf.init(ks, null); // CRITICO: senha null para Windows Store
            
            // 6. Inicializar TrustManagerFactory com truststore padrão
            TrustManagerFactory tmf = TrustManagerFactory.getInstance(
                TrustManagerFactory.getDefaultAlgorithm()
            );
            tmf.init((KeyStore) null); // usa cacerts da JVM
            
            // 7. Criar SSLContext
            SSLContext ctx = SSLContext.getInstance("TLS");
            ctx.init(kmf.getKeyManagers(), tmf.getTrustManagers(), null);
            
            logger.info("SSLContext criado com sucesso para Windows-MY");
            return ctx;
            
        } catch (Exception e) {
            logger.log(Level.SEVERE, "Erro ao criar SSLContext do Windows Store", e);
            throw new RuntimeException("Falha ao criar SSLContext do Windows Store: " + e.getMessage(), e);
        }
    }
    
    /**
     * Cria SSLContext a partir de arquivo PKCS#12 (.pfx).
     */
    private static SSLContext fromPfx(PfxConfig config) {
        try {
            // 1. Carregar KeyStore do arquivo
            KeyStore ks = KeyStore.getInstance("PKCS12");
            try (InputStream in = Files.newInputStream(Path.of(config.path()))) {
                ks.load(in, config.password());
            }
            
            // 2. Logar informações do primeiro certificado encontrado
            String firstAlias = ks.aliases().nextElement();
            X509Certificate cert = (X509Certificate) ks.getCertificate(firstAlias);
            logger.info("Certificado carregado - Alias: " + firstAlias);
            logger.info("Subject: " + cert.getSubjectX500Principal().getName());
            logger.info("Validade: " + cert.getNotBefore() + " até " + cert.getNotAfter());
            
            // 3. Inicializar KeyManagerFactory
            KeyManagerFactory kmf = KeyManagerFactory.getInstance("SunX509");
            kmf.init(ks, config.password());
            
            // 4. Inicializar TrustManagerFactory com truststore padrão
            TrustManagerFactory tmf = TrustManagerFactory.getInstance(
                TrustManagerFactory.getDefaultAlgorithm()
            );
            tmf.init((KeyStore) null); // usa cacerts da JVM
            
            // 5. Criar SSLContext
            SSLContext ctx = SSLContext.getInstance("TLS");
            ctx.init(kmf.getKeyManagers(), tmf.getTrustManagers(), null);
            
            logger.info("SSLContext criado com sucesso para PKCS12");
            return ctx;
            
        } catch (Exception e) {
            logger.log(Level.SEVERE, "Erro ao criar SSLContext do arquivo PFX", e);
            throw new RuntimeException("Falha ao criar SSLContext do arquivo PFX: " + e.getMessage(), e);
        }
    }
    
    /**
     * Busca alias do certificado no KeyStore pelo thumbprint SHA-1.
     * 
     * @param ks KeyStore onde buscar
     * @param thumbprintHex Thumbprint em formato hexadecimal (com ou sem espaços/dois-pontos)
     * @return alias do certificado, ou null se não encontrado
     */
    private static String findAliasByThumbprint(KeyStore ks, String thumbprintHex) throws Exception {
        String normalizedTarget = thumbprintHex.replaceAll("[^0-9A-Fa-f]", "").toUpperCase();
        MessageDigest sha1 = MessageDigest.getInstance("SHA-1");
        
        Enumeration<String> aliases = ks.aliases();
        while (aliases.hasMoreElements()) {
            String alias = aliases.nextElement();
            X509Certificate cert = (X509Certificate) ks.getCertificate(alias);
            if (cert != null) {
                byte[] encoded = cert.getEncoded();
                byte[] digest = sha1.digest(encoded);
                String certThumbprint = bytesToHex(digest);
                
                if (certThumbprint.equals(normalizedTarget)) {
                    return alias;
                }
            }
        }
        return null;
    }
    
    /**
     * Converte array de bytes para string hexadecimal.
     */
    private static String bytesToHex(byte[] bytes) {
        StringBuilder sb = new StringBuilder();
        for (byte b : bytes) {
            sb.append(String.format("%02X", b));
        }
        return sb.toString();
    }
}
