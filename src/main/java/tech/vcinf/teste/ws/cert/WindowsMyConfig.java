package tech.vcinf.teste.ws.cert;

/**
 * Configuração para certificado armazenado no Windows Certificate Store (Windows-MY).
 * 
 * @param thumbprint SHA-1 thumbprint do certificado (hex string, ex: "C48514B5EDF842D34C322A1AAFAF8F6FDA3117A7")
 */
public record WindowsMyConfig(String thumbprint) implements ClientCertificateConfig {
    
    public WindowsMyConfig {
        if (thumbprint == null || thumbprint.isBlank()) {
            throw new IllegalArgumentException("Thumbprint não pode ser nulo ou vazio");
        }
    }
    
    @Override
    public CertificateType getType() {
        return CertificateType.WINDOWS_MY;
    }
}
