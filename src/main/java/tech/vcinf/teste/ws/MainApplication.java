package tech.vcinf.teste.ws;

import org.springframework.boot.ApplicationArguments;
import org.springframework.boot.ApplicationRunner;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;

import javax.net.ssl.*;
import java.io.*;
import java.net.URI;
import java.net.URL;
import java.net.http.*;
import java.nio.charset.StandardCharsets;
import java.nio.file.*;
import java.security.InvalidAlgorithmParameterException;
import java.security.KeyStore;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.cert.CRLException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.time.Duration;
import java.util.Enumeration;
import java.util.List;
import java.util.logging.Logger;

import javax.xml.crypto.MarshalException;
import javax.xml.crypto.dsig.*;
import javax.xml.crypto.dsig.dom.DOMSignContext;
import javax.xml.crypto.dsig.keyinfo.*;
import javax.xml.crypto.dsig.spec.*;
import javax.xml.parsers.DocumentBuilderFactory;
import javax.xml.parsers.ParserConfigurationException;
import javax.xml.transform.*;
import javax.xml.transform.dom.DOMSource;
import javax.xml.transform.stream.StreamResult;
import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.w3c.dom.NodeList;

import java.security.PrivateKey;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import org.xml.sax.InputSource;
import org.xml.sax.SAXException;

@SpringBootApplication
public class MainApplication implements ApplicationRunner {
    private static final Logger log = Logger.getLogger(MainApplication.class.getName());

    // --- CONFIGURAÇÕES ---
    private static final String PFX_PATH = "C:/certificado/407.pfx";
    private static final String PFX_PASS = "12345";
    private static final String WIN_THUMB = "C48514B5EDF842D34C322A1AAFAF8F6FDA3117A7";
    private static final String ENDPOINT = "https://nfe.sefaz.mt.gov.br/nfews/v2/services/NfeStatusServico4";
    private static final String CACERT_FILE = "cacerts_vcinf"; // Nome do arquivo local

    @Override
    public void run(ApplicationArguments args) throws Exception {
        log.info(">>> INICIANDO AMBIENTE SSL/TLS...");

        // 1. FASE DE GERAÇÃO: Cria o TrustStore com as cadeias da SEFAZ e ICP-Brasil
        gerarTrustStore();

        // 2. FASE DE TESTE: Executa as chamadas mTLS
        log.info(">>> INICIANDO TESTES DE REQUISIÇÃO...");
        executarTeste("WINDOWS-MY", criarSslContextWindows(WIN_THUMB));
        executarTeste("PFX-ARQUIVO", criarSslContextPfx(PFX_PATH, PFX_PASS));

        log.info(">>> INICIANDO ASSINATURA DE XML...");

        String xmlNFeBruto = getXmlNFe();
        String idDoc = extrairIdDocumento(xmlNFeBruto); // Extrai o ID para usar no nome do arquivo
        String xmlAssinado = assinarXml_pfx(xmlNFeBruto, PFX_PATH, PFX_PASS);
        log.info("XML NFe assinado com sucesso!");
        // SALVANDO NO DIRETÓRIO RAIZ
        String nomeArquivo = idDoc + ".xml";
        Path caminhoDestino = Paths.get(nomeArquivo);

        Files.writeString(caminhoDestino, xmlAssinado, StandardCharsets.UTF_8);
        log.info("Snippet do XML Assinado: " + xmlAssinado.substring(0, Math.min(xmlAssinado.length(), 200)));
        log.info("XML assinado e salvo em: " + caminhoDestino.toAbsolutePath());

        String xmlNFCeBruto = getXmlNFCe();
        idDoc = extrairIdDocumento(xmlNFCeBruto); // Extrai o ID para usar no nome do arquivo
        xmlAssinado = assinarXml_pfx(xmlNFCeBruto, PFX_PATH, PFX_PASS);
        nomeArquivo = idDoc + ".xml";
        caminhoDestino = Paths.get(nomeArquivo);

        Files.writeString(caminhoDestino, xmlAssinado, StandardCharsets.UTF_8);
        log.info("Snippet do XML Assinado: " + xmlAssinado.substring(0, Math.min(xmlAssinado.length(), 200)));
        log.info("XML assinado e salvo em: " + caminhoDestino.toAbsolutePath());

        String xmlReinfBruto = getXmlEfdReinf();
        idDoc = extrairIdDocumento(xmlReinfBruto); // Extrai o ID para usar no nome do arquivo
        xmlAssinado = assinarXml_pfx(xmlReinfBruto, PFX_PATH, PFX_PASS);
        nomeArquivo = idDoc + ".xml";
        caminhoDestino = Paths.get(nomeArquivo);

        Files.writeString(caminhoDestino, xmlAssinado, StandardCharsets.UTF_8);
        log.info("Snippet do XML Assinado: " + xmlAssinado.substring(0, Math.min(xmlAssinado.length(), 200)));
        log.info("XML assinado e salvo em: " + caminhoDestino.toAbsolutePath());

    }

    public String assinarXml_pfx(String xml, String caminhoPfx, String senha) throws Exception {
        KeyStore.PrivateKeyEntry pkEntry = getPrivateKeyEntry(caminhoPfx, senha);
        PrivateKey privateKey = pkEntry.getPrivateKey();
        X509Certificate cert = (X509Certificate) pkEntry.getCertificate();

        // Lógica de Detecção de Documento e Algoritmo
        if (xml.contains("<consStatServ") || xml.contains("<infNFe") || xml.contains("<infCte")) {
            // NFe, CTe, Status usam SHA1 e o ID geralmente começa com "ID", "NFe" ou "CTe"
            return assinarDocXmlSHA1(xml, privateKey, cert);
        } else if (xml.contains("<Reinf") || xml.contains("<infNFSe")) {
            // Reinf e NFSe Nacional usam SHA256
            return assinarDocXmlSHA256(xml, privateKey, cert);
        }

        throw new IllegalArgumentException("Tipo de XML desconhecido para assinatura automática.");
    }

    private String extrairIdDocumento(String xml) {
        // Busca simples via Regex para evitar o overhead de parsear o DOM duas vezes
        java.util.regex.Matcher m = java.util.regex.Pattern.compile("(?:Id|ID)=\"([^\"]+)\"").matcher(xml);
        return m.find() ? m.group(1) : "";
    }

    /**
     * Método Utilitário para extrair Chave e Certificado
     */
    private KeyStore.PrivateKeyEntry getPrivateKeyEntry(String caminho, String senha) throws Exception {
        KeyStore ks = KeyStore.getInstance("PKCS12");
        try (InputStream is = new FileInputStream(caminho)) {
            ks.load(is, senha.toCharArray());
        }

        Enumeration<String> aliases = ks.aliases();
        while (aliases.hasMoreElements()) {
            String alias = aliases.nextElement();
            if (ks.isKeyEntry(alias)) {
                return (KeyStore.PrivateKeyEntry) ks.getEntry(alias,
                        new KeyStore.PasswordProtection(senha.toCharArray()));
            }
        }
        throw new RuntimeException("Nenhuma chave privada encontrada no PFX.");
    }

    // ========== MÉTODOS DE GERAÇÃO (ANTIGO CACERTUTIL) ==========

    private void gerarTrustStore() {
        try {
            log.info("Gerando TrustStore local: " + CACERT_FILE);
            Path base = Paths.get(System.getProperty("java.home"), "lib", "security", "cacerts");
            KeyStore ks = KeyStore.getInstance(KeyStore.getDefaultType());

            try (InputStream is = Files.newInputStream(base)) {
                ks.load(is, "changeit".toCharArray());
            }

            // Importa Raízes ICP-Brasil
            CertificateFactory cf = CertificateFactory.getInstance("X.509");
            List.of("v10", "v5", "v2").forEach(v -> {
                try (InputStream in = new URL(
                        "http://acraiz.icpbrasil.gov.br/credenciadas/RAIZ/ICP-Brasil" + v + ".crt").openStream()) {
                    ks.setCertificateEntry("icp-" + v, (X509Certificate) cf.generateCertificate(in));
                } catch (Exception e) {
                    log.warning("Falha ao baixar ICP " + v);
                }
            });

            // Captura dinâmica dos hosts SEFAZ
            List.of("nfe.sefaz.mt.gov.br", "nfce.sefaz.mt.gov.br").forEach(host -> {
                try {
                    capturarCadeia(host, ks);
                } catch (Exception e) {
                    log.warning("Erro no host: " + host);
                }
            });

            try (OutputStream os = Files.newOutputStream(Paths.get(CACERT_FILE))) {
                ks.store(os, "changeit".toCharArray());
            }
            log.info("TrustStore gerado com sucesso!");
        } catch (Exception e) {
            log.severe("Erro ao gerar TrustStore: " + e.getMessage());
        }
    }

    private void capturarCadeia(String host, KeyStore ks) throws Exception {
        SSLContext ctx = SSLContext.getInstance("TLSv1.2");
        CapturingTrustManager ctm = new CapturingTrustManager();
        ctx.init(null, new TrustManager[] { ctm }, null);
        try (SSLSocket s = (SSLSocket) ctx.getSocketFactory().createSocket(host, 443)) {
            s.setSoTimeout(5000);
            SSLParameters p = s.getSSLParameters();
            p.setServerNames(List.of(new SNIHostName(host)));
            s.setSSLParameters(p);
            s.startHandshake();
        } catch (IOException ignored) {
        }
        if (ctm.chain != null) {
            for (int i = 0; i < ctm.chain.length; i++)
                ks.setCertificateEntry(host + "-" + i, ctm.chain[i]);
        }
    }

    // ========== MÉTODOS DE SSL (CONTEXTO) ==========

    private SSLContext criarSslContextWindows(String thumb) {
        try {
            KeyStore ks = KeyStore.getInstance("Windows-MY");
            ks.load(null, null);
            String alias = buscarAlias(ks, thumb);
            return (alias != null) ? finalizarSsl(ks, null) : null;
        } catch (Exception e) {
            return null;
        }
    }

    private SSLContext criarSslContextPfx(String p, String s) {
        try {
            KeyStore ks = KeyStore.getInstance("PKCS12");
            try (InputStream in = Files.newInputStream(Paths.get(p))) {
                ks.load(in, s.toCharArray());
            }
            return finalizarSsl(ks, s);
        } catch (Exception e) {
            return null;
        }
    }

    private SSLContext finalizarSsl(KeyStore identity, String pass) throws Exception {
        KeyStore trust = KeyStore.getInstance(KeyStore.getDefaultType());
        try (InputStream in = Files.newInputStream(Paths.get(CACERT_FILE))) {
            trust.load(in, "changeit".toCharArray());
        }

        KeyManagerFactory kmf = KeyManagerFactory.getInstance("SunX509");
        kmf.init(identity, pass != null ? pass.toCharArray() : null);
        TrustManagerFactory tmf = TrustManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm());
        tmf.init(trust);

        SSLContext ctx = SSLContext.getInstance("TLSv1.2");
        ctx.init(kmf.getKeyManagers(), tmf.getTrustManagers(), null);
        return ctx;
    }

    // ========== EXECUÇÃO E AUXILIARES ==========

    private void executarTeste(String label, SSLContext ctx) {
        if (ctx == null) {
            log.severe(label + " | Falha no contexto.");
            return;
        }
        try {
            HttpClient client = HttpClient.newBuilder().sslContext(ctx).connectTimeout(Duration.ofSeconds(15)).build();
            HttpRequest req = HttpRequest.newBuilder().uri(URI.create(ENDPOINT))
                    .header("Content-Type", "application/soap+xml; charset=utf-8")
                    .POST(HttpRequest.BodyPublishers.ofString(getXml_setConsultaStatus(), StandardCharsets.UTF_8))
                    .build();

            HttpResponse<String> res = client.send(req, HttpResponse.BodyHandlers.ofString());
            log.info(label + " | HTTP " + res.statusCode() + " | Sucesso!");
        } catch (Exception e) {
            log.warning(label + " | Erro: " + e.getMessage());
        }
    }

    private String buscarAlias(KeyStore ks, String thumb) throws Exception {
        String target = thumb.replaceAll("[^0-9A-Fa-f]", "").toUpperCase();
        MessageDigest sha1 = MessageDigest.getInstance("SHA-1");
        Enumeration<String> al = ks.aliases();
        while (al.hasMoreElements()) {
            String a = al.nextElement();
            X509Certificate c = (X509Certificate) ks.getCertificate(a);
            if (c != null && hex(sha1.digest(c.getEncoded())).equals(target))
                return a;
        }
        return null;
    }

    private String hex(byte[] bytes) {
        StringBuilder sb = new StringBuilder();
        for (byte b : bytes)
            sb.append(String.format("%02X", b));
        return sb.toString();
    }

    private String getXml_setConsultaStatus() {
        return "<?xml version=\"1.0\" encoding=\"utf-8\"?><soap12:Envelope xmlns:soap12=\"http://www.w3.org/2003/05/soap-envelope\"><soap12:Body><nfeDadosMsg xmlns=\"http://www.portalfiscal.inf.br/nfe/wsdl/NFeStatusServico4\"><consStatServ xmlns=\"http://www.portalfiscal.inf.br/nfe\" versao=\"4.00\"><tpAmb>1</tpAmb><cUF>51</cUF><xServ>STATUS</xServ></consStatServ></nfeDadosMsg></soap12:Body></soap12:Envelope>";
    }

    private String getXmlNFe() {
        return "<NFe xmlns=\"http://www.portalfiscal.inf.br/nfe\"><infNFe Id=\"NFe51260200053960793987559200000073941594056729\" versao=\"4.00\"><ide><cUF>51</cUF><cNF>59405672</cNF><natOp>VENDA DE PRODUCAO</natOp><mod>55</mod><serie>920</serie><nNF>7394</nNF><dhEmi>2026-02-16T11:31:28-04:00</dhEmi><dhSaiEnt>2026-02-16T11:31:28-04:00</dhSaiEnt><tpNF>1</tpNF><idDest>1</idDest><cMunFG>5106240</cMunFG><tpImp>1</tpImp><tpEmis>1</tpEmis><cDV>9</cDV><tpAmb>1</tpAmb><finNFe>1</finNFe><indFinal>0</indFinal><indPres>0</indPres><procEmi>0</procEmi><verProc>1.0</verProc></ide><emit><CPF>53960793987</CPF><xNome>JOSE CASTILHO RUIZ E OUTRO</xNome><enderEmit><xLgr>RODOVIA MT 242 KM 80</xLgr><nro>SN</nro><xCpl>FAZENDA RUIZ II</xCpl><xBairro>ZONA RURAL</xBairro><cMun>5106240</cMun><xMun>Nova Ubirata</xMun><UF>MT</UF><CEP>78888000</CEP><fone>66996860052</fone></enderEmit><IE>132630435</IE><CRT>3</CRT></emit><dest><CNPJ>84046101009816</CNPJ><xNome>BUNGE ALIMENTOS S/A</xNome><enderDest><xLgr>RODOVIA 242</xLgr><nro>s/n</nro><xCpl>KM    62</xCpl><xBairro>CARAVAGIO</xBairro><cMun>5107925</cMun><xMun>Sorriso</xMun><UF>MT</UF><CEP>78899000</CEP></enderDest><indIEDest>1</indIEDest><IE>130689645</IE><email>nfe.sap@bunge.com</email></dest><det nItem=\"1\"><prod><cProd>1</cProd><cEAN>SEM GTIN</cEAN><xProd>SOJA  EM GRAOS</xProd><NCM>12019000</NCM><CFOP>5101</CFOP><uCom>KG</uCom><qCom>49240.0000</qCom><vUnCom>1.8666666667</vUnCom><vProd>91914.67</vProd><cEANTrib>SEM GTIN</cEANTrib><uTrib>KG</uTrib><qTrib>49240.0000</qTrib><vUnTrib>1.8666666667</vUnTrib><indTot>1</indTot></prod><imposto><vTotTrib>367.66</vTotTrib><ICMS><ICMS51><orig>0</orig><CST>51</CST></ICMS51></ICMS><PIS><PISNT><CST>08</CST></PISNT></PIS><COFINS><COFINSNT><CST>08</CST></COFINSNT></COFINS><IBSCBS><CST>200</CST><cClassTrib>200036</cClassTrib><gIBSCBS><vBC>91914.67</vBC><gIBSUF><pIBSUF>0.1000</pIBSUF><gRed><pRedAliq>60.0000</pRedAliq><pAliqEfet>0.04</pAliqEfet></gRed><vIBSUF>36.77</vIBSUF></gIBSUF><gIBSMun><pIBSMun>0.0000</pIBSMun><gRed><pRedAliq>60.0000</pRedAliq><pAliqEfet>0.00</pAliqEfet></gRed><vIBSMun>0.00</vIBSMun></gIBSMun><vIBS>36.77</vIBS><gCBS><pCBS>0.9000</pCBS><gRed><pRedAliq>60.0000</pRedAliq><pAliqEfet>0.36</pAliqEfet></gRed><vCBS>330.89</vCBS></gCBS></gIBSCBS></IBSCBS></imposto><infAdProd>SENAR 0,2% R$ 183,83|FETHAB SOJA R$ 2.397,99|IAGRO R$ 137,87|</infAdProd><vItem>91914.67</vItem></det><total><ICMSTot><vBC>0.00</vBC><vICMS>0.00</vICMS><vICMSDeson>0.00</vICMSDeson><vFCP>0.00</vFCP><vBCST>0.00</vBCST><vST>0.00</vST><vFCPST>0.00</vFCPST><vFCPSTRet>0.00</vFCPSTRet><vProd>91914.67</vProd><vFrete>0.00</vFrete><vSeg>0.00</vSeg><vDesc>0.00</vDesc><vII>0.00</vII><vIPI>0.00</vIPI><vIPIDevol>0.00</vIPIDevol><vPIS>0.00</vPIS><vCOFINS>0.00</vCOFINS><vOutro>0.00</vOutro><vNF>91914.67</vNF><vTotTrib>367.66</vTotTrib></ICMSTot><IBSCBSTot><vBCIBSCBS>91914.67</vBCIBSCBS><gIBS><gIBSUF><vDif>0.00</vDif><vDevTrib>0.00</vDevTrib><vIBSUF>36.77</vIBSUF></gIBSUF><gIBSMun><vDif>0.00</vDif><vDevTrib>0.00</vDevTrib><vIBSMun>0.00</vIBSMun></gIBSMun><vIBS>36.77</vIBS><vCredPres>0.00</vCredPres><vCredPresCondSus>0.00</vCredPresCondSus></gIBS><gCBS><vDif>0.00</vDif><vDevTrib>0.00</vDevTrib><vCBS>330.89</vCBS><vCredPres>0.00</vCredPres><vCredPresCondSus>0.00</vCredPresCondSus></gCBS><gMono><vIBSMono>0.00</vIBSMono><vCBSMono>0.00</vCBSMono><vIBSMonoReten>0.00</vIBSMonoReten><vCBSMonoReten>0.00</vCBSMonoReten><vIBSMonoRet>0.00</vIBSMonoRet><vCBSMonoRet>0.00</vCBSMonoRet></gMono><gEstornoCred><vIBSEstCred>0.00</vIBSEstCred><vCBSEstCred>0.00</vCBSEstCred></gEstornoCred></IBSCBSTot><vNFTot>91914.67</vNFTot></total><transp><modFrete>1</modFrete><transporta><CNPJ>84046101001670</CNPJ><xNome>BUNGE ALIMENTOS S/A</xNome><IE>131189336</IE><xEnder>RODOVIA BR 163</xEnder><xMun>Rondonopolis</xMun><UF>MT</UF></transporta><veicTransp><placa>RRP9D15</placa><UF>MT</UF></veicTransp></transp><cobr><fat><nFat>001</nFat><vOrig>91914.67</vOrig><vDesc>0</vDesc><vLiq>91914.67</vLiq></fat><dup><nDup>001</nDup><dVenc>2026-04-30</dVenc><vDup>91914.67</vDup></dup></cobr><pag><detPag><indPag>1</indPag><tPag>18</tPag><vPag>91914.67</vPag></detPag><vTroco>0.00</vTroco></pag><infAdic><infCpl>ICMS DIFERIDO CONFORME ARTIGOS 573 A 586, C/C ART 6o ANEXO VIII DO RICMS-MT. FUNRURAL OPCAO PELA FOLHA DE SALARIO CONFORME PARAGRAFO 13 DO ART 25 LEI 8212/91 ALTERADO PELA LEI 13606/18. CND No 0061625073 NUMERO DE AUTENTICACAO: TLTAMLU2AB92U2UL VALIDADE 11/04/2026. CONTRATO: 1000482116. INTACTA: DECLARADA| |</infCpl></infAdic></infNFe></NFe>";
    }

    private String getXmlNFCe() {
        return "<nfeProc versao=\"4.00\" xmlns=\"http://www.portalfiscal.inf.br/nfe\"><NFe xmlns=\"http://www.portalfiscal.inf.br/nfe\"><infNFe Id=\"NFe51260134602686000102650020000085091230458530\" versao=\"4.00\"><ide><cUF>51</cUF><cNF>23045853</cNF><natOp>S VENDA MERCADORIAPRODUCAO DO ESTABEL</natOp><mod>65</mod><serie>2</serie><nNF>8509</nNF><dhEmi>2026-01-17T11:45:00-04:00</dhEmi><tpNF>1</tpNF><idDest>1</idDest><cMunFG>5107925</cMunFG><tpImp>4</tpImp><tpEmis>1</tpEmis><cDV>0</cDV><tpAmb>1</tpAmb><finNFe>1</finNFe><indFinal>1</indFinal><indPres>1</indPres><procEmi>0</procEmi><verProc>NFC-e R10</verProc></ide><emit><CNPJ>34602686000102</CNPJ><xNome>MJ COSMETICOS LTDA</xNome><enderEmit><xLgr>Avenida Natalino Joao Brescansin</xLgr><nro>1886</nro><xBairro>Centro-Norte</xBairro><cMun>5107925</cMun><xMun>Sorriso</xMun><UF>MT</UF><CEP>78890179</CEP><cPais>1058</cPais><xPais>BRASIL</xPais><fone>6635448815</fone></enderEmit><IE>140356347</IE><CRT>1</CRT></emit><dest><CPF>69540373972</CPF><xNome>HALLEYMAR</xNome><indIEDest>9</indIEDest></dest><det nItem=\"1\"><prod><cProd>11489</cProd><cEAN>7909883189730</cEAN><xProd>HOMEM ESP BARBA 200ML TERC UNICA UN</xProd><NCM>33071000</NCM><CEST>2002600</CEST><indEscala>S</indEscala><CFOP>5405</CFOP><uCom>PC</uCom><qCom>1.0000</qCom><vUnCom>70.9000000000</vUnCom><vProd>70.90</vProd><cEANTrib>7909883189730</cEANTrib><uTrib>PC</uTrib><qTrib>1.0000</qTrib><vUnTrib>70.9000</vUnTrib><indTot>1</indTot></prod><imposto><vTotTrib>32.56</vTotTrib><ICMS><ICMSSN500><orig>0</orig><CSOSN>500</CSOSN></ICMSSN500></ICMS><PIS><PISOutr><CST>49</CST><vBC>70.90</vBC><pPIS>0.0000</pPIS><vPIS>0.00</vPIS></PISOutr></PIS><COFINS><COFINSOutr><CST>49</CST><vBC>70.90</vBC><pCOFINS>0.0000</pCOFINS><vCOFINS>0.00</vCOFINS></COFINSOutr></COFINS><IS><CSTIS>000</CSTIS><cClassTribIS>000001</cClassTribIS><vBCIS>0.00</vBCIS><pIS>0.0000</pIS><vIS>0.00</vIS></IS><IBSCBS><CST>000</CST><cClassTrib>000001</cClassTrib><gIBSCBS><vBC>0.00</vBC><gIBSUF><pIBSUF>0.1000</pIBSUF><gDevTrib><vDevTrib>0.00</vDevTrib></gDevTrib><vIBSUF>0.00</vIBSUF></gIBSUF><gIBSMun><pIBSMun>0.0000</pIBSMun><gDevTrib><vDevTrib>0.00</vDevTrib></gDevTrib><vIBSMun>0.00</vIBSMun></gIBSMun><vIBS>0.00</vIBS><gCBS><pCBS>0.9000</pCBS><vCBS>0.00</vCBS></gCBS></gIBSCBS></IBSCBS></imposto><vItem>70.90</vItem></det><det nItem=\"2\"><prod><cProd>8424</cProd><cEAN>7909883144326</cEAN><xProd>EKOS COND PATAUA PRG 100ML UNICA UN</xProd><NCM>33059000</NCM><CEST>2002100</CEST><indEscala>S</indEscala><CFOP>5405</CFOP><uCom>PC</uCom><qCom>1.0000</qCom><vUnCom>39.5000000000</vUnCom><vProd>39.50</vProd><cEANTrib>7909883144326</cEANTrib><uTrib>PC</uTrib><qTrib>1.0000</qTrib><vUnTrib>39.5000</vUnTrib><indTot>1</indTot></prod><imposto><ICMS><ICMSSN500><orig>7</orig><CSOSN>500</CSOSN></ICMSSN500></ICMS><PIS><PISOutr><CST>49</CST><vBC>39.50</vBC><pPIS>0.0000</pPIS><vPIS>0.00</vPIS></PISOutr></PIS><COFINS><COFINSOutr><CST>49</CST><vBC>39.50</vBC><pCOFINS>0.0000</pCOFINS><vCOFINS>0.00</vCOFINS></COFINSOutr></COFINS><IS><CSTIS>000</CSTIS><cClassTribIS>000001</cClassTribIS><vBCIS>0.00</vBCIS><pIS>0.0000</pIS><vIS>0.00</vIS></IS><IBSCBS><CST>000</CST><cClassTrib>000001</cClassTrib><gIBSCBS><vBC>0.00</vBC><gIBSUF><pIBSUF>0.1000</pIBSUF><gDevTrib><vDevTrib>0.00</vDevTrib></gDevTrib><vIBSUF>0.00</vIBSUF></gIBSUF><gIBSMun><pIBSMun>0.0000</pIBSMun><gDevTrib><vDevTrib>0.00</vDevTrib></gDevTrib><vIBSMun>0.00</vIBSMun></gIBSMun><vIBS>0.00</vIBS><gCBS><pCBS>0.9000</pCBS><vCBS>0.00</vCBS></gCBS></gIBSCBS></IBSCBS></imposto><vItem>39.50</vItem></det><total><ICMSTot><vBC>0.00</vBC><vICMS>0.00</vICMS><vICMSDeson>0.00</vICMSDeson><vFCP>0.00</vFCP><vBCST>0.00</vBCST><vST>0.00</vST><vFCPST>0.00</vFCPST><vFCPSTRet>0.00</vFCPSTRet><vProd>110.40</vProd><vFrete>0.00</vFrete><vSeg>0.00</vSeg><vDesc>0.00</vDesc><vII>0.00</vII><vIPI>0.00</vIPI><vIPIDevol>0.00</vIPIDevol><vPIS>0.00</vPIS><vCOFINS>0.00</vCOFINS><vOutro>0.00</vOutro><vNF>110.40</vNF><vTotTrib>32.56</vTotTrib></ICMSTot><ISTot><vIS>0.00</vIS></ISTot><IBSCBSTot><vBCIBSCBS>0.00</vBCIBSCBS><gIBS><gIBSUF><vDif>0.00</vDif><vDevTrib>0.00</vDevTrib><vIBSUF>0.00</vIBSUF></gIBSUF><gIBSMun><vDif>0.00</vDif><vDevTrib>0.00</vDevTrib><vIBSMun>0.00</vIBSMun></gIBSMun><vIBS>0.00</vIBS><vCredPres>0.00</vCredPres><vCredPresCondSus>0.00</vCredPresCondSus></gIBS><gCBS><vDif>0.00</vDif><vDevTrib>0.00</vDevTrib><vCBS>0.00</vCBS><vCredPres>0.00</vCredPres><vCredPresCondSus>0.00</vCredPresCondSus></gCBS></IBSCBSTot><vNFTot>110.40</vNFTot></total><transp><modFrete>9</modFrete></transp><pag><detPag><indPag>0</indPag><tPag>03</tPag><vPag>110.40</vPag><dPag>2026-01-17</dPag><card><tpIntegra>1</tpIntegra><CNPJ>13207930000162</CNPJ><tBand>01</tBand><cAut>068355</cAut><CNPJReceb>34602686000102</CNPJReceb><idTermPag>1</idTermPag></card></detPag></pag><infAdic><infCpl>Token do Troca Facil: 207521d208509170126  Nome do Vendedor: EMANUELLY BATISTA DE ALMEIDA SANTOS</infCpl></infAdic><infRespTec><CNPJ>54517628000198</CNPJ><xContato>Rodrigo Kreiss</xContato><email>depto.homologacao@linx.com.br</email><fone>51992801474</fone></infRespTec></infNFe><infNFeSupl><qrCode><![CDATA[http://www.sefaz.mt.gov.br/nfce/consultanfce?p=51260134602686000102650020000085091230458530|2|1|1|2a0616f65ba7c7a3a5b5650d9263648da8533354]]></qrCode><urlChave>http://www.sefaz.mt.gov.br/nfce/consultanfce</urlChave></infNFeSupl></NFe><protNFe versao=\"4.00\" xmlns=\"http://www.portalfiscal.inf.br/nfe\"><infProt Id=\"ID151260033526968\"><tpAmb>1</tpAmb><verAplic>4.00</verAplic><chNFe>51260134602686000102650020000085091230458530</chNFe><dhRecbto>2026-01-17T11:45:27-04:00</dhRecbto><nProt>151260033526968</nProt><digVal>5ucNLrbnpr2afy5ipE0tpLC+W3Y=</digVal><cStat>100</cStat><xMotivo>Autorizado o uso da NF-e</xMotivo></infProt></protNFe></nfeProc>";
    }

    private String getXmlCTe() {
        return "<cteProc xmlns=\"http://www.portalfiscal.inf.br/cte\" versao=\"4.00\"><CTe xmlns=\"http://www.portalfiscal.inf.br/cte\"><infCte Id=\"CTe51260246756217000127570010000077491584547169\" versao=\"4.00\"><ide><cUF>51</cUF><cCT>58454716</cCT><CFOP>5356</CFOP><natOp>SERV. DE TRANSPORTE</natOp><mod>57</mod><serie>1</serie><nCT>7749</nCT><dhEmi>2026-02-11T10:40:00-04:00</dhEmi><tpImp>1</tpImp><tpEmis>1</tpEmis><cDV>9</cDV><tpAmb>1</tpAmb><tpCTe>0</tpCTe><procEmi>0</procEmi><verProc>MaisFrete_v4.00_RT</verProc><cMunEnv>5107925</cMunEnv><xMunEnv>SORRISO</xMunEnv><UFEnv>MT</UFEnv><modal>01</modal><tpServ>0</tpServ><cMunIni>5107925</cMunIni><xMunIni>SORRISO</xMunIni><UFIni>MT</UFIni><cMunFim>5106802</cMunFim><xMunFim>PORTO DOS GAUCHOS</xMunFim><UFFim>MT</UFFim><retira>1</retira><indIEToma>1</indIEToma><toma3><toma>3</toma></toma3></ide><compl><Entrega><noPeriodo><tpPer>4</tpPer><dIni>2026-02-11</dIni><dFim>2026-02-13</dFim></noPeriodo><semHora><tpHor>0</tpHor></semHora></Entrega><origCalc>SORRISO</origCalc><destCalc>PORTO DOS GAUCHOS</destCalc><xObs>TRANSPORTE SUBCONTRATADO COM GIOVANI SANTINI MARIANI (RNTRC 57456699), CPF/CNPJ 034.988.111/18, ENDERECO AVENIDA DAS NACOES, SN, BAIRRO JARDIM DOS IPES, SORRISO/MT, CEP 78890-421, PROPRIETARIO DO VEICULO MARCA VOLVO, PLACA OBE6J62 - RENAVAM 00998493279, UF MT, MOTORISTA ROMILDO EGEA MARTINS, CPF 010.940.641/90, CONJUNTO QCW0E27/QCW0I87/QCW0J57|INICIO VIAGEM: 11/02/2026 11:40|SEGURO CONTRATADO COM HDI SEGUROS S.A. (CNPJ 29.980.158/0082-12), APOLICE DE SEGURO: 549420250006492/559420250003407</xObs><ObsCont xCampo=\"PLACA\"><xTexto>OBE6J62</xTexto></ObsCont><ObsCont xCampo=\"\"><xTexto></xTexto></ObsCont><ObsCont xCampo=\"EM CASO DE ACIDENTE\"><xTexto>LIGUE PARA (11)5508-1300.</xTexto></ObsCont></compl><emit><CNPJ>46756217000127</CNPJ><IE>139446427</IE><xNome>TRANSPORTADORA AL LTDA</xNome><enderEmit><xLgr>AVENIDA PERIMETRAL SUDESTE</xLgr><nro>8245</nro><xCpl>SALA 12</xCpl><xBairro>SAO CRISTOVAO</xBairro><cMun>5107925</cMun><xMun>SORRISO</xMun><CEP>78894280</CEP><UF>MT</UF><fone>66981155960</fone></enderEmit><CRT>3</CRT></emit><rem><CNPJ>30463781000111</CNPJ><IE>137244436</IE><xNome>LAURENCE BORGES RAMALHO</xNome><fone>66999999995</fone><enderReme><xLgr>AV IDEMAR RIEDI</xLgr><nro>10024</nro><xBairro>INDUSTRIAL 1 ETAPA</xBairro><cMun>5107925</cMun><xMun>SORRISO</xMun><CEP>78890000</CEP><UF>MT</UF><cPais>1058</cPais><xPais>BRASIL</xPais></enderReme></rem><exped><CNPJ>30463781000111</CNPJ><IE>137244436</IE><xNome>LAURENCE BORGES RAMALHO</xNome><fone>66999999995</fone><enderExped><xLgr>AV IDEMAR RIEDI</xLgr><nro>10024</nro><xBairro>INDUSTRIAL 1 ETAPA</xBairro><cMun>5107925</cMun><xMun>SORRISO</xMun><CEP>78890000</CEP><UF>MT</UF><cPais>1058</cPais><xPais>BRASIL</xPais></enderExped></exped><receb><CPF>03498811118</CPF><IE>138295980</IE><xNome>GIOVANI SANTINI MARIANI</xNome><fone>66999796525</fone><enderReceb><xLgr>FAZENDA SANTA RITA TRAVESSA 13</xLgr><nro>SN</nro><xBairro>ZONA RURAL</xBairro><cMun>5106802</cMun><xMun>PORTO DOS GAUCHOS</xMun><CEP>78560000</CEP><UF>MT</UF><cPais>1058</cPais><xPais>BRASIL</xPais></enderReceb><email>alfaturamento@transportadoraal.com.br</email></receb><dest><CPF>03498811118</CPF><IE>138295980</IE><xNome>GIOVANI SANTINI MARIANI</xNome><fone>66999796525</fone><enderDest><xLgr>FAZENDA SANTA RITA TRAVESSA 13</xLgr><nro>SN</nro><xBairro>ZONA RURAL</xBairro><cMun>5106802</cMun><xMun>PORTO DOS GAUCHOS</xMun><CEP>78560000</CEP><UF>MT</UF><cPais>1058</cPais><xPais>BRASIL</xPais></enderDest><email>alfaturamento@transportadoraal.com.br</email></dest><vPrest><vTPrest>3650.00</vTPrest><vRec>3650.00</vRec><Comp><xNome>FRETE VALOR</xNome><vComp>3524.00</vComp></Comp><Comp><xNome>PEDAGIO</xNome><vComp>126.00</vComp></Comp></vPrest><imp><ICMS><ICMS45><CST>51</CST></ICMS45></ICMS><infAdFisco>CND N 0061450867 NUMERO DE AUTENTICACAO: TBTBLLA2MLUKB22T  CERTIDAO VALIDA ATE:  02/04/2026.</infAdFisco><IBSCBS><CST>000</CST><cClassTrib>000001</cClassTrib><gIBSCBS><vBC>3312.37</vBC><gIBSUF><pIBSUF>0.1000</pIBSUF><vIBSUF>3.31</vIBSUF></gIBSUF><gIBSMun><pIBSMun>0.0000</pIBSMun><vIBSMun>0.00</vIBSMun></gIBSMun><vIBS>3.31</vIBS><gCBS><pCBS>0.9000</pCBS><vCBS>29.81</vCBS></gCBS></gIBSCBS></IBSCBS><vTotDFe>3650.00</vTotDFe></imp><infCTeNorm><infCarga><vCarga>50000.00</vCarga><proPred>FEIJAO CAUPI</proPred><infQ><cUnid>01</cUnid><tpMed>PESO BRUTO</tpMed><qCarga>25000.0000</qCarga></infQ><infQ><cUnid>03</cUnid><tpMed>GRANEL</tpMed><qCarga>25.0000</qCarga></infQ><vCargaAverb>50000.00</vCargaAverb></infCarga><infDoc><infNFe><chave>51260230463781000111550010000014851010013675</chave></infNFe></infDoc><infModal versaoModal=\"4.00\"><rodo><RNTRC>55075133</RNTRC></rodo></infModal></infCTeNorm><autXML><CNPJ>04898488000177</CNPJ></autXML></infCte><infCTeSupl><qrCodCTe>https://www.sefaz.mt.gov.br/cte/qrcode?chCTe=51260246756217000127570010000077491584547169&amp;tpAmb=1</qrCodCTe></infCTeSupl></CTe><protCTe versao=\"4.00\"><infProt><tpAmb>1</tpAmb><verAplic>MT150423003</verAplic><chCTe>51260246756217000127570010000077491584547169</chCTe><dhRecbto>2026-02-11T10:45:37-04:00</dhRecbto><nProt>151260902233243</nProt><digVal>GWrkwrxGfgA8KUtmqv6h7W9cuGs=</digVal><cStat>100</cStat><xMotivo>Autorizado o Uso do CT-e</xMotivo></infProt></protCTe></cteProc>";
    }

    private String getXmlNFSe() {
        return "<?xml version=\"1.0\" encoding=\"utf-8\"?><NFSe versao=\"1.01\" xmlns=\"http://www.sped.fazenda.gov.br/nfse\"><infNFSe Id=\"NFS51079252224879861000150000000000003826017681697194\"><xLocEmi>Sorriso</xLocEmi><xLocPrestacao>Sorriso</xLocPrestacao><nNFSe>38</nNFSe><cLocIncid>5107925</cLocIncid><xLocIncid>Sorriso</xLocIncid><xTribNac>Suporte técnico em informática, inclusive instalação, configuração e manutenção de programas de computação e bancos de dados.</xTribNac><verAplic>SefinNacional_1.5.0</verAplic><ambGer>2</ambGer><tpEmis>1</tpEmis><procEmi>1</procEmi><cStat>107</cStat><dhProc>2026-01-13T18:21:13-03:00</dhProc><nDFSe>120248</nDFSe><emit><CNPJ>24879861000150</CNPJ><xNome>VICTOR BRUNO PEDROZO CAMPOS 04426108152</xNome><enderNac><xLgr>NATALINO JOAO BRESCANSIN</xLgr><nro>375</nro><xBairro>CENTRO-SUL</xBairro><cMun>5107925</cMun><UF>MT</UF><CEP>78896071</CEP></enderNac><fone>6696050228</fone><email>VICTOR-CAMPOS@OUTLOOK.COM</email></emit><valores><vLiq>510.00</vLiq></valores><DPS xmlns=\"http://www.sped.fazenda.gov.br/nfse\" versao=\"1.00\"><infDPS Id=\"DPS510792522487986100015000900000000000000037\"><tpAmb>1</tpAmb><dhEmi>2026-01-13T17:21:13-04:00</dhEmi><verAplic>SG.NFS-e.2023</verAplic><serie>00900</serie><nDPS>37</nDPS><dCompet>2026-01-13</dCompet><tpEmit>1</tpEmit><cLocEmi>5107925</cLocEmi><prest><CNPJ>24879861000150</CNPJ><fone>6635441504</fone><email>contato@vcinf.tech</email><regTrib><opSimpNac>2</opSimpNac><regEspTrib>0</regEspTrib></regTrib></prest><toma><CNPJ>07471960000189</CNPJ><xNome>SORRISO ALIMENTOS LTDA</xNome><end><endNac><cMun>5107925</cMun><CEP>78895390</CEP></endNac><xLgr>AYRTON SENNA</xLgr><nro>585</nro><xCpl>66996512039</xCpl><xBairro>NOVA PRATA</xBairro></end></toma><serv><locPrest><cLocPrestacao>5107925</cLocPrestacao></locPrest><cServ><cTribNac>010701</cTribNac><xDescServ>SISTEMA SGBR(SEMESTRAL)||Observacao: Dados para transferencias e depositos| Banco : 364 - Efi S.A.| Agencia : 0001| Conta : 172720-6| Chave PIX CNPJ : 24.879.861/0001-50</xDescServ></cServ></serv><valores><vServPrest><vServ>510.00</vServ></vServPrest><trib><tribMun><tribISSQN>1</tribISSQN><tpRetISSQN>1</tpRetISSQN></tribMun><totTrib><indTotTrib>0</indTotTrib></totTrib></trib></valores></infDPS></DPS></infNFSe>		</NFSe>";
    }

    private String getXmlEfdReinf() {
        return "<Reinf xmlns=\"http://www.reinf.esocial.gov.br/schemas/envioLoteEventosAssincrono/v1_00_00\"><envioLoteEventos><ideContribuinte><tpInsc>1</tpInsc><nrInsc>37042584</nrInsc></ideContribuinte><eventos><evento Id=\"ID1370425840000002026021217340600000\"><Reinf xmlns=\"http://www.reinf.esocial.gov.br/schemas/evtFechamento/v2_01_02\"><evtFechaEvPer id=\"ID1370425840000002026021217340600000\"><ideEvento><perApur>2026-01</perApur><tpAmb>1</tpAmb><procEmi>1</procEmi><verProc>2_01_02</verProc></ideEvento><ideContri><tpInsc>1</tpInsc><nrInsc>37042584</nrInsc></ideContri><ideRespInf><nmResp>JURACI JOREGE CAMICIA</nmResp><cpfResp>40770893953</cpfResp><telefone>6635441504</telefone><email/></ideRespInf><infoFech><evtServTm>N</evtServTm><evtServPr>N</evtServPr><evtAssDespRec>N</evtAssDespRec><evtAssDespRep>N</evtAssDespRep><evtComProd>N</evtComProd><evtCPRB>N</evtCPRB><evtAquis>N</evtAquis></infoFech></evtFechaEvPer></Reinf></evento></eventos></envioLoteEventos></Reinf>";
    }

    private static class CapturingTrustManager implements X509TrustManager {
        private X509Certificate[] chain;

        public void checkServerTrusted(X509Certificate[] c, String a) {
            this.chain = c;
        }

        public void checkClientTrusted(X509Certificate[] c, String a) {
        }

        public X509Certificate[] getAcceptedIssuers() {
            return new X509Certificate[0];
        }
    }

    public String assinarDocXmlSHA1(String xmlBruto, PrivateKey key, X509Certificate cert) {
        return executarAssinatura(xmlBruto, key, cert, DigestMethod.SHA1, SignatureMethod.RSA_SHA1);
    }

    public String assinarDocXmlSHA256(String xmlBruto, PrivateKey key, X509Certificate cert) {
        return executarAssinatura(xmlBruto, key, cert,
                "http://www.w3.org/2001/04/xmlenc#sha256",
                "http://www.w3.org/2001/04/xmldsig-more#rsa-sha256");
    }

    private String executarAssinatura(String xmlBruto, PrivateKey key, X509Certificate cert,
            String digestAlg, String sigAlg) {
        try {
            // 1. Carregar o documento XML DOMSignContext
            DocumentBuilderFactory dbf = DocumentBuilderFactory.newInstance();
            dbf.setNamespaceAware(true);
            Document doc = dbf.newDocumentBuilder().parse(new InputSource(new StringReader(xmlBruto)));

            // 2. Localizar o elemento pelo ID (infNFe, infCte, evtFechaEvPer, etc)
            Element toSign = descobrirElementoParaAssinar(doc);

            String nomeAtributoId = registrarAtributoId(toSign);

            String idValor = toSign.getAttribute(nomeAtributoId);

            // 3. Definição do Algoritmo
            String digestMethod;
            String signatureMethod;

            if (toSign.getNodeName().startsWith("evt") || toSign.getNodeName().startsWith("eSocial")) {
                digestMethod = DigestMethod.SHA256;
                signatureMethod = "http://www.w3.org/2001/04/xmldsig-more#rsa-sha256";
            } else {
                digestMethod = DigestMethod.SHA1;
                signatureMethod = SignatureMethod.RSA_SHA1;
            }

            // 4. Configuração da Assinatura
            XMLSignatureFactory factory = XMLSignatureFactory.getInstance("DOM");

            // Contexto no PAI do elemento (Irmão do elemento assinado)
            DOMSignContext dsc = new DOMSignContext(key, toSign.getParentNode());

            List<Transform> transforms = new ArrayList<>();
            transforms.add(factory.newTransform(Transform.ENVELOPED, (TransformParameterSpec) null));
            transforms.add(factory.newTransform("http://www.w3.org/TR/2001/REC-xml-c14n-20010315",
                    (TransformParameterSpec) null));

            Reference ref = factory.newReference("#" + idValor,
                    factory.newDigestMethod(digestMethod, null),
                    transforms, null, null);

            SignedInfo si = factory.newSignedInfo(
                    factory.newCanonicalizationMethod(CanonicalizationMethod.INCLUSIVE, (C14NMethodParameterSpec) null),
                    factory.newSignatureMethod(signatureMethod, null),
                    Collections.singletonList(ref));

            KeyInfoFactory kif = factory.getKeyInfoFactory();
            KeyInfo ki = kif.newKeyInfo(Collections.singletonList(kif.newX509Data(Collections.singletonList(cert))));

            // 5. Assinar
            XMLSignature signature = factory.newXMLSignature(si, ki);
            signature.sign(dsc);

            // 6. Serializar
            Transformer transformer = TransformerFactory.newInstance().newTransformer();
            transformer.setOutputProperty(OutputKeys.INDENT, "no");

            StringWriter writer = new StringWriter();
            transformer.transform(new DOMSource(doc), new StreamResult(writer));

            return writer.toString();
        } catch (Exception e) {
            // Multicatch limpo. Em produção, use logger.error aqui.
            throw new RuntimeException("Falha crítica na assinatura XML: " + e.getMessage(), e);
        }
    }

    /**
     * Registra o atributo ID e RETORNA o nome dele para uso posterior.
     */
    private String registrarAtributoId(Element elemento) {
        String[] atributosPossiveis = { "id", "Id", "ID" };

        for (String nomeAtributo : atributosPossiveis) {
            if (elemento.hasAttribute(nomeAtributo)) {
                elemento.setIdAttribute(nomeAtributo, true);
                return nomeAtributo; // Retorna o vencedor
            }
        }
        throw new IllegalArgumentException("Elemento " + elemento.getNodeName() + " não possui ID (id, Id, ID).");
    }

    /**
     * Localiza o elemento correto para assinar, ignorando wrappers de lote.
     * Prioriza tags de evento (evt*) ou informações fiscais (inf*).
     */
    private Element descobrirElementoParaAssinar(Document doc) {
        // Lista de tags que representam o "núcleo" do documento fiscal
        String[] tagsDeInteresse = { "infNFe", "infCte", "infNFSe", "evtFechaEvPer", "evtInfoEmpregador", "Reinf" };
        // Adicione outros "evt..." conforme necessário ou use lógica de prefixo

        NodeList allElements = doc.getElementsByTagName("*");
        for (int i = 0; i < allElements.getLength(); i++) {
            Element el = (Element) allElements.item(i);
            String tagName = el.getNodeName();

            // Lógica Reinf: Busca tags que começam com 'evt' (Eventos) e têm ID
            if (tagName.startsWith("evt")
                    && (el.hasAttribute("Id") || el.hasAttribute("ID") || el.hasAttribute("id"))) {
                return el;
            }

            // Lógica NFe/CTe: Busca infNFe/infCte
            if ((tagName.startsWith("infNFe") || tagName.startsWith("infCte"))
                    && (el.hasAttribute("Id") || el.hasAttribute("ID"))) {
                return el;
            }
        }
        throw new RuntimeException("Nenhum elemento assinável (evt*, inf*) encontrado no XML.");
    }

    public static void main(String[] args) {
        SpringApplication.run(MainApplication.class, args);
    }
}