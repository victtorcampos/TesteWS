# Implement_000_v2 – Simplificação Máxima

## Objetivo

Consolidar **TODA** a implementação de certificado mTLS em um **único arquivo**: `MainApplication.java`.

**Princípio**: código de estudo deve ser direto, sem abstrações desnecessárias. Tudo visível em um só lugar.

---

## 1. Consolidação Completa (Único Arquivo)

### tech.vcinf.teste.ws/
- [✅] `MainApplication.java` (Agora contém toda a lógica SSL e HTTP)

---

## Roadmap de Simplificação

### Fase 1: Consolidar lógica SSL
- [✅] Mover métodos de `ClientSslContextFactory` para `MainApplication`:
  - [✅] `criarSslContextPfx()`
  - [✅] `criarSslContextWindowsMy()`
  - [✅] `buscarAliasPorThumbprint()`
  - [✅] `bytesToHex()`

### Fase 2: Consolidar lógica HTTP
- [✅] Mover lógica de `StatusClient` para `MainApplication`:
  - [✅] `enviarConsultaStatus()` (cria HttpClient inline, envia POST, retorna body)

### Fase 3: Remover pacotes desnecessários
- [✅] Deletar pacote `cert/` (4 arquivos)
- [✅] Deletar pacote `ssl/` (1 arquivo)
- [✅] Deletar pacote `client/` (1 arquivo)
- [✅] Deletar pacote `test/` (2 arquivos)

### Fase 4: Ajustar imports
- [✅] Remover imports de classes internas deletadas
- [✅] Adicionar imports do JDK necessários

### Fase 5: Validar e testar
- [ ] Compilar: `mvn clean compile`
- [ ] Executar: `mvn spring-boot:run`

---

> ✅ **Fase 4 CONCLUÍDA.** Imports ajustados.
