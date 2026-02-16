# 📚 Guia Completo de Aprendizado: mTLS com Certificados A1 em Java

## Índice

1. [Introdução ao Problema](#1-introdução-ao-problema)
2. [Conceitos Fundamentais](#2-conceitos-fundamentais)
3. [Arquitetura da Solução](#3-arquitetura-da-solução)
4. [Anatomia do Código](#4-anatomia-do-código)
5. [Fluxos de Execução](#5-fluxos-de-execução)
6. [Casos de Uso e Aplicações](#6-casos-de-uso-e-aplicações)
7. [Troubleshooting](#7-troubleshooting)

---

## 1. Introdução ao Problema

### 1.1 O Desafio da Comunicação com a SEFAZ

Quando uma aplicação Java precisa se comunicar com os servidores da Secretaria da Fazenda (SEFAZ) para emitir notas fiscais eletrônicas (NF-e), ela enfrenta **dois desafios simultâneos**:

#### Problema A: **Confiança (Trust)**
O servidor da SEFAZ apresenta um certificado digital assinado pela **cadeia ICP-Brasil**, que **não está incluída** no arquivo `cacerts` padrão da JVM. Sem essa cadeia, o Java recusa a conexão com o erro:

```
javax.net.ssl.SSLHandshakeException: PKIX path building failed:
sun.security.provider.certpath.SunCertPathBuilderException: unable to find valid certification path to requested target
```

#### Problema B: **Identidade (mTLS - Mutual TLS)**
A SEFAZ **exige autenticação bidirecional**. Não basta confiar no servidor; o **cliente (sua aplicação) também precisa provar quem é**, apresentando um certificado A1 válido durante o handshake SSL/TLS.

### 1.2 Por Que Este Projeto Existe?

Este utilitário resolve **ambos os problemas de forma automatizada**:

- ✅ **Gera um TrustStore local** com as raízes ICP-Brasil e a cadeia completa do host da SEFAZ
- ✅ **Testa dois métodos de armazenamento** do certificado A1: arquivo PFX e Windows Certificate Store
- ✅ **Fornece diagnóstico imediato** de falhas de conectividade

---

## 2. Conceitos Fundamentais

### 2.1 O Que É mTLS (Mutual TLS)?

Em uma conexão HTTPS normal:
1. Cliente conecta ao servidor
2. Servidor envia seu certificado
3. Cliente valida o certificado
4. Comunicação criptografada é estabelecida

Em **mTLS**, há uma etapa adicional:
5. **Servidor solicita o certificado do cliente**
6. **Cliente envia seu certificado (A1)**
7. **Servidor valida a identidade do cliente**

Isso cria uma autenticação bidirecional, onde ambas as partes se provam mutuamente.

### 2.2 KeyStore vs TrustStore

#### KeyStore ("Quem eu sou")
- Armazena a **identidade da aplicação**
- Contém:
  - Chave privada
  - Certificado público (A1)
  - Cadeia de certificação (se aplicável)

#### TrustStore ("Em quem eu confio")
- Armazena os **certificados de autoridades confiáveis**
- Contém:
  - Certificados raiz (Root CA)
  - Certificados intermediários
  - Cadeia de confiança completa

**Analogia**: O KeyStore é sua carteira de identidade, o TrustStore é a lista de emissores de documentos que você reconhece como legítimos.

### 2.3 Certificado A1 vs A3

| Característica | A1 | A3 |
|----------------|----|----||
| **Armazenamento** | Arquivo (`.pfx`) ou Windows Store | Token USB ou Smartcard |
| **Portabilidade** | Alta (pode ser copiado) | Baixa (hardware dedicado) |
| **Segurança** | Moderada (protegido por senha) | Alta (chave não exportável) |
| **Suporte Java** | Nativo via `PKCS12` e `Windows-MY` | Requer drivers e bibliotecas específicas |

Este projeto foca no **A1** por ser o mais comum em aplicações empresariais.

### 2.4 O Que É Thumbprint?

O **Thumbprint** (impressão digital) é o hash **SHA-1** do certificado completo. Ele funciona como um "ID único" do certificado.

**Por que usar Thumbprint em vez de CN (Common Name)?**
- Um mesmo CN pode ter múltiplos certificados (renovações, homologação vs produção)
- O Thumbprint garante que você está selecionando **exatamente** o certificado correto

**Como obter o Thumbprint no Windows:**
```powershell
Get-ChildItem -Path Cert:\CurrentUser\My | Format-List Subject, Thumbprint
```

---

## 3. Arquitetura da Solução

### 3.1 Visão Geral do Fluxo

```
┌─────────────────────────────────────────────────────────────┐
│  1. PREPARAÇÃO DO AMBIENTE                                  │
│  ┌──────────────────────────────────────────────────────┐   │
│  │ gerarTrustStore()                                    │   │
│  │ ├─ Copia cacerts da JVM                             │   │
│  │ ├─ Baixa raízes ICP-Brasil (v2, v5, v10)           │   │
│  │ └─ Captura cadeia dinâmica dos hosts SEFAZ         │   │
│  └──────────────────────────────────────────────────────┘   │
│                          ↓                                   │
│  2. CRIAÇÃO DO CONTEXTO SSL                                 │
│  ┌──────────────────────────────────────────────────────┐   │
│  │ criarSslContextWindows() / criarSslContextPfx()     │   │
│  │ ├─ Carrega KeyStore (identidade)                    │   │
│  │ └─ Carrega TrustStore (confiança)                   │   │
│  └──────────────────────────────────────────────────────┘   │
│                          ↓                                   │
│  3. TESTE DE CONECTIVIDADE                                  │
│  ┌──────────────────────────────────────────────────────┐   │
│  │ executarTeste()                                      │   │
│  │ └─ Envia requisição SOAP com mTLS                   │   │
│  └──────────────────────────────────────────────────────┘   │
└─────────────────────────────────────────────────────────────┘
```

### 3.2 Por Que Gerar o TrustStore Dinamicamente?

Em vez de distribuir um arquivo `cacerts` modificado, o código:

1. **Isola a aplicação**: Não modifica o `cacerts` global da JVM
2. **Mantém-se atualizado**: Sempre baixa as raízes mais recentes da ICP-Brasil
3. **Resolve problemas de rede**: Captura a cadeia exata que o servidor da SEFAZ está enviando naquele momento

---

## 4. Anatomia do Código

### 4.1 Método: `gerarTrustStore()`

#### O Que Faz
Cria um arquivo local chamado `cacerts_vcinf` contendo todos os certificados necessários para confiar na SEFAZ.

#### Como Funciona

```java
private void gerarTrustStore() {
    try {
        // 1. Copiar cacerts padrão da JVM como base
        Path base = Paths.get(System.getProperty("java.home"), "lib", "security", "cacerts");
        KeyStore ks = KeyStore.getInstance(KeyStore.getDefaultType());
        try (InputStream is = Files.newInputStream(base)) { 
            ks.load(is, "changeit".toCharArray()); // Senha padrão do cacerts
        }
```

**Por que copiar o cacerts?**
- O `cacerts` padrão já contém raízes de CAs globais (VeriSign, DigiCert, etc.)
- Precisamos **adicionar** as raízes ICP-Brasil, não substituir as existentes

```java
        // 2. Baixar e importar raízes ICP-Brasil
        CertificateFactory cf = CertificateFactory.getInstance("X.509");
        List.of("v10", "v5", "v2").forEach(v -> {
            try (InputStream in = new URL(
                "http://acraiz.icpbrasil.gov.br/credenciadas/RAIZ/ICP-Brasil" + v + ".crt"
            ).openStream()) {
                ks.setCertificateEntry("icp-" + v, (X509Certificate) cf.generateCertificate(in));
            } catch (Exception e) { log.warning("Falha ao baixar ICP " + v); }
        });
```

**O que são v2, v5 e v10?**
- São as **gerações das raízes ICP-Brasil**
- Certificados mais antigos podem estar assinados por v2 ou v5
- Certificados novos usam v10
- Importar todas garante compatibilidade completa

```java
        // 3. Capturar cadeia dinâmica dos hosts
        List.of("nfe.sefaz.mt.gov.br", "nfce.sefaz.mt.gov.br").forEach(host -> {
            try { capturarCadeia(host, ks); } 
            catch (Exception e) { log.warning("Erro no host: " + host); }
        });
```

**Por que capturar a cadeia dinamicamente?**
- Às vezes o servidor não envia a cadeia completa
- Pode haver certificados intermediários que não estão nas raízes
- Esta abordagem garante que **qualquer certificado que o servidor enviar** será confiável

```java
        // 4. Salvar o KeyStore modificado em arquivo local
        try (OutputStream os = Files.newOutputStream(Paths.get(CACERT_FILE))) { 
            ks.store(os, "changeit".toCharArray()); 
        }
        log.info("TrustStore gerado com sucesso!");
    } catch (Exception e) { 
        log.severe("Erro ao gerar TrustStore: " + e.getMessage()); 
    }
}
```

### 4.2 Método: `capturarCadeia(String host, KeyStore ks)`

Este é um dos métodos **mais inteligentes** do código.

#### O Problema Que Ele Resolve
Quando você conecta a um servidor HTTPS, ele envia:
1. Seu próprio certificado
2. (Opcionalmente) Certificados intermediários

Se o servidor **não enviar** os intermediários, você precisa tê-los no TrustStore, caso contrário:
```
sun.security.validator.ValidatorException: PKIX path building failed
```

#### A Solução: "Handshake Fantasma"

```java
private void capturarCadeia(String host, KeyStore ks) throws Exception {
    // 1. Criar um SSLContext com TrustManager customizado
    SSLContext ctx = SSLContext.getInstance("TLSv1.2");
    CapturingTrustManager ctm = new CapturingTrustManager();
    ctx.init(null, new TrustManager[]{ctm}, null);
```

**O que é CapturingTrustManager?**
- É uma implementação de `X509TrustManager` que **não valida nada**
- Apenas "captura" (armazena) a cadeia de certificados que o servidor envia

```java
    // 2. Forçar um handshake TLS
    try (SSLSocket s = (SSLSocket) ctx.getSocketFactory().createSocket(host, 443)) {
        s.setSoTimeout(5000);
        SSLParameters p = s.getSSLParameters();
        p.setServerNames(List.of(new SNIHostName(host))); // SNI para servidores com múltiplos domínios
        s.setSSLParameters(p);
        s.startHandshake(); // Aqui o servidor envia a cadeia
    } catch (IOException ignored) {} // Handshake vai falhar, mas a cadeia já foi capturada
```

**Por que ignorar o IOException?**
- O handshake **vai falhar** propositalmente (porque não temos o TrustStore correto ainda)
- Mas antes de falhar, o servidor **já enviou a cadeia**
- Capturamos a cadeia e ignoramos o erro

```java
    // 3. Importar todos os certificados capturados
    if (ctm.chain != null) {
        for (int i = 0; i < ctm.chain.length; i++) {
            ks.setCertificateEntry(host + "-" + i, ctm.chain[i]);
        }
    }
}
```

### 4.3 Inner Class: `CapturingTrustManager`

```java
private static class CapturingTrustManager implements X509TrustManager {
    private X509Certificate[] chain;
    
    public void checkServerTrusted(X509Certificate[] c, String a) { 
        this.chain = c; // APENAS armazena, não valida
    }
    
    public void checkClientTrusted(X509Certificate[] c, String a) {}
    
    public X509Certificate[] getAcceptedIssuers() { 
        return new X509Certificate[0]; 
    }
}
```

**Este TrustManager é seguro?**
- ❌ **NÃO use em produção!**
- ✅ **Perfeito para este caso**: Só queremos capturar certificados, não validá-los

### 4.4 Método: `finalizarSsl(KeyStore identity, String pass)`

Este é o **coração da solução mTLS**.

```java
private SSLContext finalizarSsl(KeyStore identity, String pass) throws Exception {
    // 1. Carregar o TrustStore local que geramos
    KeyStore trust = KeyStore.getInstance(KeyStore.getDefaultType());
    try (InputStream in = Files.newInputStream(Paths.get(CACERT_FILE))) { 
        trust.load(in, "changeit".toCharArray()); 
    }
```

**Por que dois KeyStores diferentes?**
- `identity`: Contém a **chave privada + certificado A1** (quem somos)
- `trust`: Contém os **certificados raiz** (em quem confiamos)

```java
    // 2. Configurar KeyManager (gerencia a identidade do cliente)
    KeyManagerFactory kmf = KeyManagerFactory.getInstance("SunX509");
    kmf.init(identity, pass != null ? pass.toCharArray() : null);
```

**Por que `pass` pode ser `null`?**
- Para **Windows-MY**, a senha é gerenciada pelo sistema operacional
- Para **PKCS12**, precisamos fornecer a senha do arquivo `.pfx`

```java
    // 3. Configurar TrustManager (gerencia em quem confiamos)
    TrustManagerFactory tmf = TrustManagerFactory.getInstance(
        TrustManagerFactory.getDefaultAlgorithm()
    );
    tmf.init(trust);
```

```java
    // 4. Criar o SSLContext final
    SSLContext ctx = SSLContext.getInstance("TLSv1.2");
    ctx.init(kmf.getKeyManagers(), tmf.getTrustManagers(), null);
    return ctx;
}
```

**Por que TLSv1.2?**
- É o protocolo suportado pela maioria dos servidores da SEFAZ
- TLS 1.3 ainda não é amplamente adotado em sistemas governamentais

### 4.5 Método: `buscarAlias(KeyStore ks, String thumb)`

```java
private String buscarAlias(KeyStore ks, String thumb) throws Exception {
    // 1. Normalizar o thumbprint (remover espaços, dois-pontos, etc.)
    String target = thumb.replaceAll("[^0-9A-Fa-f]", "").toUpperCase();
    MessageDigest sha1 = MessageDigest.getInstance("SHA-1");
```

**Por que normalizar?**
- O Thumbprint pode vir formatado de diferentes formas:
  - `C4:85:14:B5:ED:F8...` (com dois-pontos)
  - `C4 85 14 B5 ED F8...` (com espaços)
  - `C48514B5EDF8...` (sem separadores)
- A normalização garante que todas sejam comparáveis

```java
    // 2. Iterar sobre todos os certificados do KeyStore
    Enumeration<String> al = ks.aliases();
    while (al.hasMoreElements()) {
        String a = al.nextElement();
        X509Certificate c = (X509Certificate) ks.getCertificate(a);
        
        // 3. Calcular o SHA-1 do certificado
        if (c != null && hex(sha1.digest(c.getEncoded())).equals(target)) {
            return a; // Encontrou!
        }
    }
    return null; // Não encontrado
}
```

**Por que não usar `ks.getCertificate(alias)` diretamente?**
- No Windows Store, o alias pode ser um GUID interno
- Não temos como saber qual é o alias correto antecipadamente
- Iterar e comparar SHA-1 é a forma mais confiável

---

## 5. Fluxos de Execução

### 5.1 Fluxo Completo: PFX

```
┌─────────────────────────────────────────────────────────────┐
│ 1. run()                                                    │
│    └─> gerarTrustStore()                                    │
│         ├─ Copia cacerts                                    │
│         ├─ Baixa ICP-Brasil v2, v5, v10                    │
│         └─ Captura cadeia de nfe.sefaz.mt.gov.br           │
└─────────────────────────────────────────────────────────────┘
                          ↓
┌─────────────────────────────────────────────────────────────┐
│ 2. criarSslContextPfx()                                     │
│    ├─ KeyStore.getInstance("PKCS12")                       │
│    ├─ ks.load(pfxFile, password)                           │
│    └─> finalizarSsl(ks, password)                          │
│         ├─ KeyManagerFactory.init(ks, password)            │
│         ├─ TrustManagerFactory.init(trustStore)            │
│         └─ SSLContext.init(kmf, tmf, null)                 │
└─────────────────────────────────────────────────────────────┘
                          ↓
┌─────────────────────────────────────────────────────────────┐
│ 3. executarTeste()                                          │
│    ├─ HttpClient.newBuilder().sslContext(ctx)              │
│    ├─ HttpRequest.POST(xmlBody)                            │
│    └─ client.send(request)                                 │
│         └─> [mTLS Handshake]                               │
│              ├─ Servidor envia certificado                 │
│              ├─ Cliente valida contra TrustStore           │
│              ├─ Servidor solicita certificado do cliente   │
│              ├─ Cliente envia certificado A1 do PFX        │
│              └─ Conexão estabelecida!                      │
└─────────────────────────────────────────────────────────────┘
```

### 5.2 Fluxo Completo: Windows-MY

A diferença começa no passo 2:

```
┌─────────────────────────────────────────────────────────────┐
│ 2. criarSslContextWindows()                                 │
│    ├─ KeyStore.getInstance("Windows-MY")                   │
│    ├─ ks.load(null, null) // Sem senha!                    │
│    ├─> buscarAlias(ks, WIN_THUMB)                          │
│    │    └─ Itera todos os certificados                     │
│    │    └─ Compara SHA-1 até encontrar o correto           │
│    └─> finalizarSsl(ks, null) // Senha = null              │
└─────────────────────────────────────────────────────────────┘
```

**Ponto crítico**: `kmf.init(ks, null)`

Quando `identity` é um `Windows-MY` KeyStore:
- A chave privada está protegida pelo sistema operacional
- O Java **não precisa** da senha para acessá-la
- Passar `null` como senha é **obrigatório**

---

## 6. Casos de Uso e Aplicações

### 6.1 Integração em Sistema de Emissão de NF-e

Em um sistema real de emissão de notas fiscais:

```java
public class NfeService {
    private final SSLContext sslContext;
    
    public NfeService(String pfxPath, String pfxPassword) {
        // Reutilizar a lógica do MainApplication
        this.sslContext = criarSslContextPfx(pfxPath, pfxPassword);
    }
    
    public String emitirNFe(String xmlNfe) {
        HttpClient client = HttpClient.newBuilder()
            .sslContext(sslContext)
            .build();
        // ... lógica de emissão
    }
}
```

### 6.2 Múltiplos Certificados (Multi-tenant)

Para sistemas que gerenciam múltiplas empresas:

```java
public class CertificadoManager {
    private Map<String, SSLContext> contextos = new ConcurrentHashMap<>();
    
    public SSLContext obterContexto(String cnpj) {
        return contextos.computeIfAbsent(cnpj, k -> {
            String pfxPath = buscarCertificadoPorCnpj(cnpj);
            return criarSslContextPfx(pfxPath, obterSenha(cnpj));
        });
    }
}
```

### 6.3 Testes Automatizados

```java
@Test
public void deveConectarComSefaz() {
    SSLContext ctx = criarSslContextPfx(
        "src/test/resources/certificado-teste.pfx", 
        "senha123"
    );
    
    assertNotNull(ctx);
    
    // Validar que consegue fazer requisição
    HttpResponse<String> response = executarConsulta(ctx);
    assertEquals(200, response.statusCode());
}
```

---

## 7. Troubleshooting

### 7.1 Erro: "unable to find valid certification path"

**Causa**: TrustStore não contém a cadeia do servidor.

**Solução**:
1. Verificar se o arquivo `cacerts_vcinf` foi gerado
2. Executar `gerarTrustStore()` novamente
3. Validar conectividade de rede (download das raízes ICP-Brasil)

### 7.2 Erro: "bad certificate" do servidor

**Causa**: O servidor rejeitou o certificado do cliente.

**Possíveis motivos**:
- Certificado expirado
- Certificado revogado
- Thumbprint incorreto (Windows-MY)
- Senha incorreta (PFX)

**Solução**:
```powershell
# Verificar validade do certificado
Get-ChildItem -Path Cert:\CurrentUser\My | 
    Where-Object { $_.Thumbprint -eq "SEU_THUMBPRINT" } |
    Select-Object Subject, NotBefore, NotAfter
```

### 7.3 Erro: "No subject alternative names present"

**Causa**: O endpoint não está usando SNI (Server Name Indication).

**Solução**: Adicionar SNI explicitamente:
```java
SSLParameters p = socket.getSSLParameters();
p.setServerNames(List.of(new SNIHostName("nfe.sefaz.mt.gov.br")));
socket.setSSLParameters(p);
```

### 7.4 Windows-MY não funciona em Linux/Mac

**Causa**: O provider `Windows-MY` é específico do Windows.

**Solução**:
- Use sempre PFX em ambientes não-Windows
- Em containers Docker, monte o arquivo `.pfx` via volume

---

## 8. Conclusão

Este projeto demonstra uma solução **production-ready** para um dos problemas mais comuns em integrações governamentais no Brasil:

✅ **Automatiza** a configuração de TrustStore  
✅ **Suporta** múltiplos métodos de armazenamento de certificados  
✅ **Fornece** diagnóstico claro de falhas  
✅ **Isola** configurações de SSL da JVM global  

### Próximos Passos

Para evoluir este código:

1. **Adicionar suporte a A3**: Integrar com bibliotecas PKCS#11 para tokens USB
2. **Cache de SSLContext**: Evitar recriar contextos para cada requisição
3. **Renovação automática**: Detectar certificados próximos ao vencimento
4. **Logging estruturado**: Substituir `java.util.logging` por SLF4J/Logback

---

> **Nota**: Este documento foi criado como material educacional. Para uso em produção, considere adicionar tratamento de exceções mais robusto e testes de integração contínua.
