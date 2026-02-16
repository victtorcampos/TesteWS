# Documentação: Utilitário de Teste mTLS SEFAZ

## 1. Visão Geral

O `MainApplication` é uma ferramenta de diagnóstico desenvolvida para validar a comunicação segura (mTLS) entre aplicações Java e os servidores da SEFAZ (Secretaria da Fazenda). Ele resolve automaticamente os dois problemas mais comuns em comunicações governamentais:

1. **Falta de Confiança (Trust)**: Gera um arquivo de certificados local incluindo a cadeia ICP-Brasil e certificados dinâmicos do host.
2. **Identidade (mTLS)**: Testa simultaneamente certificados em arquivo (`.pfx`) e certificados instalados no Windows Store (`Windows-MY`).

---

## 2. Arquitetura do Processo

O ciclo de vida da aplicação segue duas fases obrigatórias:

### Fase A: Preparação do Ambiente (Gerar TrustStore)

Antes de qualquer requisição, o método `gerarTrustStore()`:

* Copia o `cacerts` padrão da JRE como base.
* Faz o download das raízes **ICP-Brasil (v2, v5 e v10)** via HTTP.
* Realiza um "handshake fantasma" com os hosts da SEFAZ para capturar e importar a cadeia de certificados do servidor em tempo de execução.

### Fase B: Teste de Conectividade

A aplicação tenta realizar uma chamada SOAP `NfeStatusServico` utilizando:

* **Windows-MY**: Busca o certificado pelo **Thumbprint** (SHA-1) no repositório do Windows.
* **PFX**: Carrega o certificado A1 diretamente de um caminho local.

---

## 3. Configurações Técnicas

As variáveis de ambiente estão hardcoded no topo da classe para facilitar testes rápidos:

| Variável | Descrição | Exemplo / Valor |
| --- | --- | --- |
| `PFX_PATH` | Caminho físico do certificado A1. | `C:/certificado/407.pfx` |
| `PFX_PASS` | Senha do arquivo PFX. | `12345` |
| `WIN_THUMB` | Impressão digital do certificado no Windows. | `C48514B5EDF...` |
| `ENDPOINT` | URL do Web Service de Status da SEFAZ. | `https://nfe.sefaz.mt.gov.br/...` |
| `CACERT_FILE` | Nome do arquivo TrustStore temporário. | `cacerts_vcinf` |

---

## 4. Detalhes dos Métodos Principais

### `finalizarSsl(KeyStore identity, String pass)`

Este é o núcleo de segurança da aplicação. Ele unifica a identidade (quem a aplicação é) com a confiança (em quem a aplicação confia).

* **Protocolo**: Força o uso de `TLSv1.2` para garantir compatibilidade com a SEFAZ.
* **TrustManager**: Inicializado com o arquivo gerado localmente, evitando erros de `SunCertPathBuilderException`.

### `buscarAlias(KeyStore ks, String thumb)`

Diferente de abordagens baseadas em nomes, este método itera sobre todos os certificados da Windows Store, calcula o Hash SHA-1 de cada um e compara com o `WIN_THUMB`. Isso garante que o certificado correto seja selecionado mesmo que existam múltiplos certificados para o mesmo CN (Common Name).

### `CapturingTrustManager` (Inner Class)

Uma implementação customizada de `X509TrustManager` que, em vez de validar o servidor, apenas "captura" a cadeia de certificados enviada por ele durante o handshake para que possamos salvá-la no nosso TrustStore local.

---

## 5. Dependências (Maven)

O projeto utiliza o **Spring Boot 4.0.2** (conforme logs) e **Java 17**.

```xml
<dependencies>
    <dependency>
        <groupId>org.springframework.boot</groupId>
        <artifactId>spring-boot-starter</artifactId>
    </dependency>
    <dependency>
        <groupId>org.projectlombok</groupId>
        <artifactId>lombok</artifactId>
        <optional>true</optional>
    </dependency>
</dependencies>

```

---

## 6. Análise de Execução (Logs)

Com base no log fornecido, o comportamento esperado é:

1. **0.0s**: Inicialização do Spring Context.
2. **0.7s**: Início da geração do TrustStore local.
3. **1.6s**: Confirmação de que o arquivo `cacerts_vcinf` foi populado e gravado.
4. **2.1s**: Sucesso na requisição mTLS via Windows Store (HTTP 200).
5. **2.3s**: Sucesso na requisição mTLS via Arquivo PFX (HTTP 200).

---

## 7. Requisitos para Sucesso

* **Permissões**: O usuário que executa a aplicação deve ter permissão de escrita na pasta raiz (para gerar o arquivo `cacerts_vcinf`).
* **Acesso Externo**: Deve haver conectividade HTTP (porta 80) para baixar as raízes da ICP-Brasil e HTTPS (porta 443) para os hosts da SEFAZ.
* **Windows**: Para o teste `WINDOWS-MY`, a aplicação deve ser executada em sistema operacional Windows.

---

> **Nota de Manutenção**: Caso o endpoint mude para TLS 1.3 no futuro, basta alterar a constante dentro do método `finalizarSsl` e `capturarCadeia`.
