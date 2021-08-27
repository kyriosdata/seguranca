/*
 * Copyright (c) 2019
 * Fábrica de Software - Instituto de Informática
 * Fábio Nogueira de Lucena
 */
package com.github.kyriosdata.assinar;

import org.junit.jupiter.api.Test;

import java.io.ByteArrayInputStream;
import java.io.InputStream;
import java.util.UUID;

import static org.junit.jupiter.api.Assertions.*;

class CertificadoTest {

    public static final String PASSWORD = "keystore";
    public static final String KEYSTORE = "assinar.keystore";
    public static final String ALIAS = "teste";

    @Test
    void construtorInvalido() {
        assertThrows(NullPointerException.class,
                () -> new Certificado(null, PASSWORD, ALIAS, "verificar"));

        assertThrows(NullPointerException.class,
                () -> new Certificado("k", (String)null, ALIAS, "verificar"));

        assertThrows(NullPointerException.class,
                () -> new Certificado("k", (char[])null, ALIAS, "verificar"));

        assertThrows(NullPointerException.class,
                () -> new Certificado("k", "s", null, "verificar"));

        assertThrows(NullPointerException.class,
                () -> new Certificado("k", "s", "a", null));
    }

    @Test
    void construtorKeystoreInvalido() {
        assertThrows(RuntimeException.class, () -> new Certificado("x", "s", "a", "i"));
    }

    @Test
    void verificaId() {
        Certificado certificado = new Certificado(KEYSTORE, PASSWORD, ALIAS, "criar");
        assertEquals("criar", certificado.getId());
    }

    @Test
    void base64Verificacao() {
        final String casa = "casa";
        final String base64 = "Y2FzYQ==";

        assertEquals(base64, Certificado.toBase64(casa));
    }

    @Test
    void toBase64AndFrom() {
        final String msg = UUID.randomUUID().toString();
        final String base64 = Certificado.toBase64(msg);
        final String retornado = Certificado.base64ToString(base64);
        assertEquals(msg, retornado);
    }

    @Test
    void tamanhoDaAssinatura() throws Exception {
        Certificado assinante = new Certificado(KEYSTORE, PASSWORD, ALIAS, "criar");
        byte[] conteudo = "casa".getBytes();
        byte[] assinatura = assinante.crie(conteudo);
        assertEquals(256, assinatura.length);
    }

    @Test
    void criaVerificaAssinaturaBytes() throws Exception {
        Certificado assinante = new Certificado(KEYSTORE, PASSWORD, ALIAS, "criar");
        byte[] conteudo = "casa".getBytes();
        byte[] assinatura = assinante.crie(conteudo);

        // Verifica assinatura
        Certificado verificador = new Certificado(KEYSTORE, PASSWORD, ALIAS, "verificar");
        assertTrue(verificador.verifique(conteudo, assinatura));
    }

    @Test
    void verificacaoFalhaSeNull() {
        Certificado assinante = new Certificado(KEYSTORE, PASSWORD, ALIAS, "criar");
        assertThrows(RuntimeException.class, () -> assinante.verifique(new byte[]{}, null));
    }

    @Test
    void verificacaoFalhaSeInputStreamNull() {
        Certificado assinante = new Certificado(KEYSTORE, PASSWORD, ALIAS, "criar");
        InputStream conteudo = null;
        assertThrows(RuntimeException.class, () -> assinante.verifique(conteudo, null));
    }

    @Test
    void criaVerificaAssinaturaInputStream() throws Exception {
        Certificado assinante = new Certificado(KEYSTORE, PASSWORD, ALIAS, "criar");
        byte[] conteudo = "casa".getBytes();
        ByteArrayInputStream bais = new ByteArrayInputStream(conteudo);
        byte[] assinatura = assinante.crie(bais);

        // Verifica assinatura
        Certificado verificador = new Certificado(KEYSTORE, PASSWORD, ALIAS, "verificar");
        ByteArrayInputStream entrada = new ByteArrayInputStream(conteudo);
        ByteArrayInputStream rubrica = new ByteArrayInputStream(assinatura);
        assertTrue(verificador.verifique(entrada, rubrica));
    }

    @Test
    void calcularHash() {
        final String msg = "A vida é bela!";
        final String hashHex = "cc3808ea2ab49713a67424a6b109db4f1d8c6b776f5429a8c8c61abc60f31c7c";

        byte[] sha256 = Certificado.hash(msg);
        assertEquals(hashHex, Certificado.toHex(sha256));
    }

    @Test
    void algoritmoInexistenteGeraFalha() {
        assertThrows(RuntimeException.class,
                () -> Certificado.hash("x", new byte[1]));
    }
}
