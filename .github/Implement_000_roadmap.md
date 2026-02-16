# Implement_000 – Roadmap de Implementação

Objetivo: implementar uma camada simples de criação de `SSLContext` que suporte **Windows Certificate Store (Windows-MY)** e **arquivo PFX (PKCS12)** para consultas HTTPS/mTLS de status.

---

## 1. Diagnóstico da base atual

- [ ] Revisar código existente do TesteWS e identificar pontos onde TLS/SSL é configurado (se houver).
- [ ] Documentar estado atual: se há uso de `HttpsURLConnection`, `HttpClient` (Java 11+).
- [ ] Mapear onde o certificado hoje é carregado (ou se ainda não é carregado).

Resultado esperado: visão clara de onde o `SSLContext` será plugado.

---

## 2. Definição da API interna

Criar contrato mínimo para representar as duas origens de certificado de cliente:

- [ ] Criar pacote `br.com.victor.testews.cert`.
- [ ] Definir `enum CertificateType { WINDOWS_MY, PKCS12_FILE }` (se precisar).
- [ ] Definir tipos de configuração:
  - [ ] `record WindowsMyConfig(String thumbprint)`
  - [ ] `record PfxConfig(String path, char[] password)`
- [ ] Definir interface selada opcional: `sealed interface ClientCertificateConfig permits WindowsMyConfig, PfxConfig`.

Resultado esperado: uma forma única de descrever "qual certificado usar" sem espalhar `if (windows)` pelo código.

---

## 3. Fábrica de SSLContext

Criar classe `ClientSslContextFactory` no pacote `br.com.victor.testews.ssl`:

- [ ] Método público único:
  - [ ] `public static SSLContext from(ClientCertificateConfig config)`
- [ ] Implementações internas:
  - [ ] `SSLContext fromWindowsStore(WindowsMyConfig cfg)`
  - [ ] `SSLContext fromPfx(PfxConfig cfg)`

### 3.1. Implementação Windows Store (Windows-MY)

- [ ] Carregar `KeyStore ks = KeyStore.getInstance("Windows-MY")`.
- [ ] `ks.load(null, null)`.
- [ ] Implementar busca de alias por thumbprint (iterando certificados do store).
- [ ] Obter chave privada com `ks.getKey(alias, null)` (senha `null` para Windows-MY).
- [ ] Inicializar `KeyManagerFactory` com `kmf.init(ks, null)`.
- [ ] Inicializar `TrustManagerFactory` com truststore padrão (`tmf.init((KeyStore) null)`).
- [ ] Criar `SSLContext` com `TLS` e fazer `ctx.init(kmf.getKeyManagers(), tmf.getTrustManagers(), null)`.
- [ ] Logar alias escolhido e subject do certificado para facilitar debug.
- [ ] Deixar TODO/documentado possível evolução com `X509KeyManager` custom, caso surja problema de chave não exportável.

### 3.2. Implementação PFX (PKCS12)

- [ ] Carregar `KeyStore ks = KeyStore.getInstance("PKCS12")`.
- [ ] Abrir `InputStream` para o arquivo `pfxPath`.
- [ ] `ks.load(in, password)`.
- [ ] Inicializar `KeyManagerFactory` com `kmf.init(ks, password)`.
- [ ] Inicializar `TrustManagerFactory` com truststore padrão.
- [ ] Criar `SSLContext` e inicializar como no caso Windows.
- [ ] Logar alias escolhido e subject do certificado.

Resultado esperado: uma única fábrica que retorna `SSLContext` pronto, independente da origem do certificado.

---

## 4. Cliente de consulta de status

Criar pacote `br.com.victor.testews.http` com um cliente mínimo:

- [ ] Classe `StatusClient` que recebe `SSLContext` no construtor.
- [ ] Usar `java.net.http.HttpClient` (Java 11+) com `.sslContext(sslContext)`.
- [ ] Implementar método `String consultarStatus(URI endpoint, String xml)` que:
  - [ ] Monta `HttpRequest` POST com `Content-Type` adequado (por exemplo `application/soap+xml; charset=utf-8`).
  - [ ] Envia request usando `client.send`.
  - [ ] Retorna body como `String` ou lança exceção com detalhes de erro.

Resultado esperado: ponto único para testar o mTLS contra um endpoint real ou de teste.

---

## 5. Testes automatizados

### 5.1. Teste com PFX (sempre executável)

- [ ] Criar teste `StatusClientPfxTest` (JUnit 5).
- [ ] Usar um `.pfx` de teste com senha conhecida (por exemplo via `src/test/resources` e variável de ambiente para a senha).
- [ ] Montar `PfxConfig` e `SSLContext` com `ClientSslContextFactory.from(config)`.
- [ ] Executar `consultarStatus` contra um endpoint de teste ou mock.
- [ ] Validar que não ocorre `SSLHandshakeException` e que o HTTP status é o esperado.

### 5.2. Teste com Windows Store (apenas em Windows)

- [ ] Criar teste `StatusClientWindowsMyTest`.
- [ ] Anotar com `@EnabledOnOs(OS.WINDOWS)`.
- [ ] Obter thumbprint do certificado via variável de ambiente ou propriedade de sistema.
- [ ] Montar `WindowsMyConfig` e `SSLContext` com `ClientSslContextFactory.from(config)`.
- [ ] Executar `consultarStatus` e validar ausência de `SSLHandshakeException`.

Resultado esperado: garantir que ambos caminhos (PFX e Windows-MY) funcionam, com possibilidade de rodar em CI usando apenas o teste PFX.

---

## 6. Ajustes finos e observabilidade

- [ ] Adicionar logs mínimos (via `slf4j-simple` ou `java.util.logging`) para:
  - [ ] Provider usado (`Windows-MY` ou `PKCS12`).
  - [ ] Alias selecionado e subject do certificado.
  - [ ] Algoritmos de protocolo negociados em caso de falha (`handshake_failure`).
- [ ] Isolar ao máximo qualquer código específico de Windows Store dentro de `ClientSslContextFactory`.

---

## 7. Próximos passos (após validação)

- [ ] Decidir se o mesmo padrão será reaproveitado em projetos fiscais maiores.
- [ ] Se sim, extrair esse código para um módulo/repositório reutilizável.
- [ ] Documentar diferenças práticas observadas entre Windows-MY e PFX (ex.: senha `null`, chaves não exportáveis, etc.).

---

> OBS: Aguarde sua autorização explícita antes de começar a codar de fato seguindo este roadmap.
