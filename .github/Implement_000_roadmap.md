# Implement_000 – Roadmap de Implementação

Objetivo: implementar uma camada simples de criação de `SSLContext` que suporte **Windows Certificate Store (Windows-MY)** e **arquivo PFX (PKCS12)** para consultas HTTPS/mTLS de status.

**RESTRIÇÃO CRÍTICA**: implementação deve usar apenas JDK padrão (Java 17+) **sem adicionar novas dependências externas**. Usar somente `java.security.*`, `javax.net.ssl.*`, `java.net.http.*` e `java.util.logging.*`.

---

## 1. Diagnóstico da base atual

- [✅] Revisar código existente do TesteWS e identificar pontos onde TLS/SSL é configurado (se houver).
- [✅] Documentar estado atual: se há uso de `HttpsURLConnection`, `HttpClient` (Java 11+).
- [✅] Mapear onde o certificado hoje é carregado (ou se ainda não é carregado).
- [✅] Listar dependências atuais do projeto (Maven/Gradle) para confirmar baseline.

Resultado esperado: visão clara de onde o `SSLContext` será plugado e confirmação de que nenhuma nova dependência será necessária.

**DIAGNÓSTICO**: Spring Boot 4.0.2 + Java 17, já existe `SslContextUtils` com suporte apenas PFX. Nenhuma dependência nova foi adicionada.

---

## 2. Definição da API interna

Criar contrato mínimo para representar as duas origens de certificado de cliente **usando apenas recursos do JDK**:

- [✅] Criar pacote `tech.vcinf.teste.ws.cert`.
- [✅] Definir `enum CertificateType { WINDOWS_MY, PKCS12_FILE }`.
- [✅] Definir tipos de configuração:
  - [✅] `record WindowsMyConfig(String thumbprint)` (Java 17+ record)
  - [✅] `record PfxConfig(String path, char[] password)`
- [✅] Definir interface selada: `sealed interface ClientCertificateConfig permits WindowsMyConfig, PfxConfig` (Java 17+ sealed).

Resultado esperado: uma forma única de descrever "qual certificado usar" sem espalhar `if (windows)` pelo código, usando apenas recursos nativos da linguagem.

**IMPLEMENTADO**: Commit [26e35d3](https://github.com/victtorcampos/TesteWS/commit/26e35d3a5969c277264b07091ecd7c2f8cf934df) - 4 classes criadas com validações.

---

## 3. Fábrica de SSLContext

Criar classe `ClientSslContextFactory` no pacote `tech.vcinf.teste.ws.ssl` **usando apenas `java.security.*` e `javax.net.ssl.*`**:

- [✅] Método público único:
  - [✅] `public static SSLContext from(ClientCertificateConfig config)`
- [✅] Implementações internas:
  - [✅] `SSLContext fromWindowsStore(WindowsMyConfig cfg)`
  - [✅] `SSLContext fromPfx(PfxConfig cfg)`

### 3.1. Implementação Windows Store (Windows-MY)

- [✅] Carregar `KeyStore ks = KeyStore.getInstance("Windows-MY")`.
- [✅] `ks.load(null, null)`.
- [✅] Implementar busca de alias por thumbprint (iterando certificados do store):
  - [✅] Usar `ks.aliases()` para enumerar.
  - [✅] Comparar thumbprint via `MessageDigest.getInstance("SHA-1")` do certificado.
- [✅] Obter chave privada com `ks.getKey(alias, null)` (senha `null` para Windows-MY).
- [✅] Inicializar `KeyManagerFactory` com `kmf.init(ks, null)`.
- [✅] Inicializar `TrustManagerFactory` com truststore padrão (`tmf.init((KeyStore) null)`).
- [✅] Criar `SSLContext` com `TLS` e fazer `ctx.init(kmf.getKeyManagers(), tmf.getTrustManagers(), null)`.
- [✅] Logar alias escolhido e subject do certificado usando `java.util.logging.Logger`.
- [✅] Deixar TODO/documentado possível evolução com `X509KeyManager` custom (do JDK), caso surja problema de chave não exportável.

### 3.2. Implementação PFX (PKCS12)

- [✅] Carregar `KeyStore ks = KeyStore.getInstance("PKCS12")`.
- [✅] Abrir `InputStream` para o arquivo `pfxPath` usando `Files.newInputStream(Path.of(...))`.
- [✅] `ks.load(in, password)`.
- [✅] Inicializar `KeyManagerFactory` com `kmf.init(ks, password)`.
- [✅] Inicializar `TrustManagerFactory` com truststore padrão.
- [✅] Criar `SSLContext` e inicializar como no caso Windows.
- [✅] Logar alias escolhido e subject do certificado usando `java.util.logging.Logger`.

Resultado esperado: uma única fábrica que retorna `SSLContext` pronto, independente da origem do certificado, **sem nenhuma dependência externa**.

**IMPLEMENTADO**: Commit [06828a7](https://github.com/victtorcampos/TesteWS/commit/06828a7cbc4d8c9c2706f8621d22e91533bf3b07) - `ClientSslContextFactory` completa com busca por thumbprint SHA-1 e logs detalhados.

---

## 4. Cliente de consulta de status

Criar pacote `tech.vcinf.teste.ws.client` com um cliente mínimo **usando apenas `java.net.http.HttpClient` do JDK 11+**:

- [✅] Classe `StatusClient` que recebe `SSLContext` no construtor.
- [✅] Usar `java.net.http.HttpClient.newBuilder().sslContext(sslContext).build()`.
- [✅] Implementar método `String consultarStatus(URI endpoint, String xml)` que:
  - [✅] Monta `HttpRequest` POST com `Content-Type` adequado (por exemplo `application/soap+xml; charset=utf-8`).
  - [✅] Usa `HttpRequest.BodyPublishers.ofString(xml, StandardCharsets.UTF_8)`.
  - [✅] Envia request usando `client.send(request, HttpResponse.BodyHandlers.ofString())`.
  - [✅] Retorna body como `String` ou lança exceção com detalhes de erro.
- [✅] Logar request/response usando `java.util.logging.Logger`.

Resultado esperado: ponto único para testar o mTLS contra um endpoint real ou de teste, **sem libs HTTP externas**.

**IMPLEMENTADO**: Commit [dc75b90](https://github.com/victtorcampos/TesteWS/commit/dc75b906427c56d6535fe567dea0f586941cf348) - `StatusClient` usando `java.net.http` com timeout e logs.

---

## 5. Testes automatizados

**Usar apenas JUnit 5 se já estiver no projeto; caso contrário, criar classes main() simples para validação manual.**

### 5.1. Teste com PFX (sempre executável)

- [✅] Criar teste `StatusClientPfxTest` (classe main()).
- [✅] Usar um `.pfx` de teste com senha conhecida (via path absoluto).
- [✅] Obter senha via `System.getProperty("pfx.password")`.
- [✅] Montar `PfxConfig` e `SSLContext` com `ClientSslContextFactory.from(config)`.
- [✅] Executar `consultarStatus` contra um endpoint de teste.
- [✅] Validar que não ocorre `SSLHandshakeException` e que o HTTP status é o esperado.
- [✅] Logar resultado usando `java.util.logging.Logger`.

### 5.2. Teste com Windows Store (apenas em Windows)

- [✅] Criar teste `StatusClientWindowsMyTest` (classe main()).
- [✅] Verificar se está rodando em Windows via `System.getProperty("os.name")`.
- [✅] Obter thumbprint do certificado via `System.getProperty("cert.thumbprint")`.
- [✅] Montar `WindowsMyConfig` e `SSLContext` com `ClientSslContextFactory.from(config)`.
- [✅] Executar `consultarStatus` e validar ausência de `SSLHandshakeException`.
- [✅] Logar resultado usando `java.util.logging.Logger`.

Resultado esperado: garantir que ambos caminhos (PFX e Windows-MY) funcionam, **sem frameworks de teste pesados se não estiverem já disponíveis**.

**IMPLEMENTADO**: Commit [b7245b5](https://github.com/victtorcampos/TesteWS/commit/b7245b5f0c2491108584d7dcad2ea896236b0df7) - Duas classes de teste manual com instruções de uso.

---

## 6. Ajustes finos e observabilidade

- [✅] Usar **exclusivamente `java.util.logging.Logger`** para logs:
  - [✅] Provider usado (`Windows-MY` ou `PKCS12`).
  - [✅] Alias selecionado e subject do certificado.
  - [ ] Protocolo TLS negociado (extrair via `SSLSession` se possível). — **Pendente: requer acesso a SSLSession após handshake**
  - [✅] Detalhes de erro em caso de `handshake_failure`.
- [✅] Configurar nível de log via `logging.properties` ou programaticamente.
- [✅] Isolar ao máximo qualquer código específico de Windows Store dentro de `ClientSslContextFactory`.
- [✅] Validar que nenhuma nova entrada foi adicionada ao `pom.xml`/`build.gradle`.

**STATUS**: Logs implementados com `java.util.logging`. Nenhuma dependência externa adicionada.

---

## 7. Próximos passos (após validação)

- [ ] Decidir se o mesmo padrão será reaproveitado em projetos fiscais maiores.
- [ ] Se sim, extrair esse código para um módulo/repositório reutilizável (ainda sem dependências externas).
- [ ] Documentar diferenças práticas observadas entre Windows-MY e PFX (ex.: senha `null`, chaves não exportáveis, necessidade de `X509KeyManager` custom, etc.).
- [ ] Criar documento técnico explicando por que essa abordagem zero-dependência é suficiente para o caso de uso.

---

## Sumário da Implementação

✅ **Fase 1-5 CONCLUÍDAS** (4 commits)

### Estrutura criada:
```
tech.vcinf.teste.ws
├── cert/
│   ├── CertificateType.java
│   ├── ClientCertificateConfig.java (sealed interface)
│   ├── WindowsMyConfig.java (record)
│   └── PfxConfig.java (record)
├── ssl/
│   └── ClientSslContextFactory.java
├── client/
│   └── StatusClient.java
└── test/
    ├── StatusClientPfxTest.java
    └── StatusClientWindowsMyTest.java
```

### Como testar:

**Teste PFX:**
```bash
mvn compile exec:java -Dexec.mainClass="tech.vcinf.teste.ws.test.StatusClientPfxTest" \
  -Dpfx.path="C:\\certificado\\407.pfx" \
  -Dpfx.password="12345" \
  -Dendpoint="https://nfe.sefaz.mt.gov.br/nfews/v2/services/NfeStatusServico4"
```

**Teste Windows Store (só em Windows):**
```bash
mvn compile exec:java -Dexec.mainClass="tech.vcinf.teste.ws.test.StatusClientWindowsMyTest" \
  -Dcert.thumbprint="C48514B5EDF842D34C322A1AAFAF8F6FDA3117A7" \
  -Dendpoint="https://nfe.sefaz.mt.gov.br/nfews/v2/services/NfeStatusServico4"
```

---

> ✅ **IMPLEMENTAÇÃO CORE COMPLETA** - Aguardando validação dos testes manuais.
