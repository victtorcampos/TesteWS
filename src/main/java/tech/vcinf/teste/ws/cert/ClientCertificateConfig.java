package tech.vcinf.teste.ws.cert;

/**
 * Interface selada que representa a configuração de um certificado de cliente.
 * Apenas WindowsMyConfig e PfxConfig podem implementar esta interface.
 */
public sealed interface ClientCertificateConfig 
    permits WindowsMyConfig, PfxConfig {
    
    /**
 * Retorna o tipo de certificado representado por esta configuração.
     */
    CertificateType getType();
}
