# Implement_000_v2 – Simplificação Máxima

## Objetivo

Consolidar **TODA** a implementação de certificado mTLS em um **único arquivo**: `MainApplication.java`.

**Princípio**: código de estudo deve ser direto, sem abstrações desnecessárias. Tudo visível em um só lugar.

---

## Estado Atual (Implement_000)

### Estrutura de pacotes:
```
tech.vcinf.teste.ws/
├── MainApplication.java          (entry point)
├── cert/                         (4 arquivos)
│   ├── CertificateType.java
│   ├── ClientCertificateConfig.java
│   ├── WindowsMyConfig.java
│   └── PfxConfig.java
├── ssl/                          (1 arquivo)
│   └── ClientSslContextFactory.java
├── client/                       (1 arquivo)
│   └── StatusClient.java
└── test/                         (2 arquivos - não usados)
    ├── StatusClientPfxTest.java
    └── StatusClientWindowsMyTest.java
```

**Total**: 9 arquivos Java

### Problemas identificados:
1. **Excesso de abstração** para um projeto de estudo simples
2. **Navegação entre arquivos** dificulta leitura linear
3. **Classes de teste separadas** não são usadas (MainApplication é o teste)
4. **Records e sealed interfaces** adicionam complexidade sem benefício real neste contexto

---

## Estado Desejado (v2)

### Estrutura de pacotes:
```
tech.vcinf.teste.ws/
└── MainApplication.java          (Único arquivo - tudo aqui)
```

**Total**: 1 arquivo Java

### Conteúdo do `MainApplication.java`:

```java
package tech.vcinf.teste.ws;

import org.springframework.boot.ApplicationArguments;
import org.springframework.boot.ApplicationRunner;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;

import javax.net.ssl.*;
import java.io.InputStream;
import java.net.URI;
import java.net.http.*;
import java.nio.charset.StandardCharsets;
import java.nio.file.*;
import java.security.*;
import java.security.cert.X509Certificate;
import java.time.Duration;
import java.util.Enumeration;
import java.util.logging.*;

@SpringBootApplication
public class MainApplication implements ApplicationRunner {
    
    private static final Logger logger = Logger.getLogger(MainApplication.class.getName());
    
    // ========== CONFIGURAÇÕES ==========
    private static final String TIPO_TESTE = "PFX"; // "PFX" ou "WINDOWS_MY"
    
    // PFX
    private static final String PFX_PATH = "C:\\\\certificado\\\\407.pfx";
    private static final String PFX_PASSWORD = "12345";
    
    // Windows Store
    private static final String WINDOWS_THUMBPRINT = "C48514B5EDF842D34C322A1AAFAF8F6FDA3117A7";
    
    // Endpoint
    private static final String ENDPOINT = "https://nfe.sefaz.mt.gov.br/nfews/v2/services/NfeStatusServico4";
    // ====================================
    
    @Override
    public void run(ApplicationArguments args) {
        // Testar baseado na configuração
    }
    
    // ========== MÉTODOS DE CRIAÇÃO DE SSLContext ==========
    
    private SSLContext criarSslContextPfx(String pfxPath, String senha) {
        // Lógica completa inline
    }
    
    private SSLContext criarSslContextWindowsMy(String thumbprint) {
        // Lógica completa inline
    }
    
    private String buscarAliasPorThumbprint(KeyStore ks, String thumbprint) {
        // Busca SHA-1
    }
    
    // ========== MÉTODOS HTTP ==========
    
    private String enviarConsultaStatus(SSLContext sslContext, String endpoint, String xml) {
        // HttpClient inline
    }
    
    private String criarXmlConsultaStatus() {
        // XML SOAP
    }
    
    // ========== UTILITÁRIOS ==========
    
    private String bytesToHex(byte[] bytes) {
        // Conversão hex
    }
    
    public static void main(String[] args) {
        SpringApplication.run(MainApplication.class, args);
    }
}
```

---

## Roadmap de Simplificação

### Fase 1: Consolidar lógica SSL

- [ ] Mover métodos de `ClientSslContextFactory` para `MainApplication`:
  - [ ] `criarSslContextPfx()` (inline do método `fromPfx`)
  - [ ] `criarSslContextWindowsMy()` (inline do método `fromWindowsStore`)
  - [ ] `buscarAliasPorThumbprint()` (inline)
  - [ ] `bytesToHex()` (inline)

### Fase 2: Consolidar lógica HTTP

- [ ] Mover lógica de `StatusClient` para `MainApplication`:
  - [ ] `enviarConsultaStatus()` (cria HttpClient inline, envia POST, retorna body)

### Fase 3: Remover pacotes desnecessários

- [ ] Deletar pacote `cert/` (4 arquivos)
- [ ] Deletar pacote `ssl/` (1 arquivo)
- [ ] Deletar pacote `client/` (1 arquivo)
- [ ] Deletar pacote `test/` (2 arquivos)
- [ ] Deletar pacote `gerador/` (se ainda existir)
- [ ] Deletar pacote `http/` antigo (se ainda existir)

### Fase 4: Ajustar imports

- [ ] Remover imports de classes internas deletadas
- [ ] Adicionar imports do JDK necessários (`javax.net.ssl.*`, `java.net.http.*`, etc.)

### Fase 5: Validar e testar

- [ ] Compilar: `mvn clean compile`
- [ ] Executar: `mvn spring-boot:run`
- [ ] Validar que teste PFX funciona
- [ ] Validar que teste Windows-MY funciona (em Windows)

---

## Benefícios da Simplificação

### ✅ Vantagens

1. **Leitura linear**: todo código em um arquivo, sem navegação
2. **Aprendizado**: estudante vê todo fluxo de uma vez
3. **Debug simplificado**: breakpoints em um único arquivo
4. **Sem over-engineering**: zero abstrações desnecessárias
5. **Menos arquivos**: 1 arquivo vs 9 arquivos

### ⚠️ Desvantagens (aceitas)

1. **Arquivo maior**: ~300-400 linhas (ainda gerenciável)
2. **Reusabilidade zero**: código não é reutilizável (mas esse não é o objetivo)
3. **Não segue Clean Architecture**: correto, porque é um projeto de **estudo**, não produção

---

## Estrutura Final Esperada

### Seções do `MainApplication.java`:

1. **Package e imports**
2. **@SpringBootApplication** annotation
3. **Constantes de configuração** (topo da classe)
4. **run()** (entry point do teste)
5. **Métodos de SSL**:
   - `criarSslContextPfx()`
   - `criarSslContextWindowsMy()`
   - `buscarAliasPorThumbprint()`
6. **Métodos HTTP**:
   - `enviarConsultaStatus()`
   - `criarXmlConsultaStatus()`
7. **Utilitários**:
   - `bytesToHex()`
8. **main()** (Spring Boot entry point)

---

## Checklist de Execução

- [ ] Criar backup do estado atual (branch já é o backup)
- [ ] Copiar lógica de `ClientSslContextFactory` para `MainApplication`
- [ ] Copiar lógica de `StatusClient` para `MainApplication`
- [ ] Ajustar nomes de métodos (remover prefixos desnecessários)
- [ ] Remover todos os `static` dos métodos auxiliares (agora são de instância)
- [ ] Deletar arquivos obsoletos
- [ ] Compilar e testar
- [ ] Atualizar documentação (README se houver)

---

## Execução Após Implementação

### Passo 1: Editar configurações no topo do arquivo
```java
private static final String TIPO_TESTE = "PFX"; // ou "WINDOWS_MY"
private static final String PFX_PATH = "C:\\\\certificado\\\\407.pfx";
private static final String PFX_PASSWORD = "12345";
```

### Passo 2: Executar
```bash
mvn spring-boot:run
```

### Passo 3: Observar logs
```
==================================================
TESTE DE CERTIFICADO mTLS - PFX
==================================================

📝 Configuração:
  Arquivo: C:\\certificado\\407.pfx
  Endpoint: https://nfe.sefaz.mt.gov.br/...

🔑 Criando SSLContext do arquivo PFX...
✅ SSLContext criado!

🚀 Enviando consulta de status...

✅ SUCESSO!
  Tamanho da resposta: 532 bytes

==================================================
🎉 TESTE CONCLUÍDO COM SUCESSO!
==================================================
```

---

## Comparação Final

| Aspecto | v1 (Atual) | v2 (Proposto) |
|---------|------------|---------------|
| Arquivos Java | 9 | 1 |
| Pacotes | 5 | 1 |
| Linhas de código | ~1500 (distribuídas) | ~400 (concentradas) |
| Navegação | Múltiplos arquivos | Um arquivo |
| Abstrações | Records, Sealed, Factory | Zero |
| Curva de aprendizado | Média | Baixa |
| Manutenção | Modular | Inline |
| Objetivo | Arquitetura limpa | Estudo direto |

---

> ⚠️ **Aguardando autorização para implementar a simplificação v2.**
