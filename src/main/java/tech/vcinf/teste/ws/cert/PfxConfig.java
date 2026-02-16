package tech.vcinf.teste.ws.cert;

/**
 * Configuração para certificado em arquivo PKCS#12 (.pfx/.p12).
 * 
 * @param path     Caminho para o arquivo .pfx (ex: "C:\\certificado\\cert.pfx")
 * @param password Senha do certificado
 */
public record PfxConfig(String path, char[] password) implements ClientCertificateConfig {
    
    public PfxConfig {
        if (path == null || path.isBlank()) {
            throw new IllegalArgumentException("Path do certificado não pode ser nulo ou vazio");
        }
        if (password == null || password.length == 0) {
            throw new IllegalArgumentException("Senha do certificado não pode ser nula ou vazia");
        }
    }
    
    @Override
    public CertificateType getType() {
        return CertificateType.PKCS12_FILE;
    }
}
