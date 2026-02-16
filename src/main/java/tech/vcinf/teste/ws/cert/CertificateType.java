package tech.vcinf.teste.ws.cert;

/**
 * Tipos de origem de certificado suportados.
 */
public enum CertificateType {
    /** Certificado instalado no Windows Certificate Store (Windows-MY) */
    WINDOWS_MY,
    
    /** Certificado em arquivo PKCS#12 (.pfx/.p12) */
    PKCS12_FILE
}
