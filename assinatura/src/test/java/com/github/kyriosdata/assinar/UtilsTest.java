/*
 * Copyright (c) 2019
 * Fábrica de Software - Instituto de Informática
 * Fábio Nogueira de Lucena
 */
package com.github.kyriosdata.assinar;

import org.junit.jupiter.api.Test;

import java.io.ByteArrayInputStream;
import java.util.UUID;

import static org.junit.jupiter.api.Assertions.*;

class UtilsTest {

    public static final char[] PASSWORD = "keystore".toCharArray();
    public static final String KEYSTORE = "assinar.keystore";
    public static final String ALIAS = "teste";

    @Test
    void base64Verificacao() {
        final String casa = "casa";
        final String base64 = "Y2FzYQ==";

        assertEquals(base64, AssinaturaDigital.toBase64(casa));
    }

    @Test
    void toBase64AndFrom() {
        final String msg = UUID.randomUUID().toString();
        final String base64 = AssinaturaDigital.toBase64(msg);
        System.out.println(base64);
        final String retornado = AssinaturaDigital.base64ToString(base64);
        assertEquals(msg, retornado);
    }

    @Test
    void tamanhoDaAssinatura() throws Exception {
        AssinaturaDigital assinante = AssinaturaDigital.paraCriar(
                KEYSTORE, PASSWORD, ALIAS);
        byte[] conteudo = "casa".getBytes();
        byte[] assinatura = assinante.crie(conteudo);
        assertEquals(256, assinatura.length);
    }

    @Test
    void criaVerificaAssinaturaBytes() throws Exception {
        AssinaturaDigital assinante = AssinaturaDigital.paraCriar(
                KEYSTORE, PASSWORD, ALIAS);
        byte[] conteudo = "casa".getBytes();
        byte[] assinatura = assinante.crie(conteudo);

        // Verifica assinatura
        AssinaturaDigital verificador = AssinaturaDigital.paraVerificar(
                KEYSTORE, PASSWORD, ALIAS);
        assertTrue(verificador.verifique(conteudo, assinatura));
    }

    @Test
    void criaVerificaAssinaturaInputStream() throws Exception {
        AssinaturaDigital assinante = AssinaturaDigital.paraCriar(
                KEYSTORE, PASSWORD, ALIAS);
        byte[] conteudo = "casa".getBytes();
        ByteArrayInputStream bais = new ByteArrayInputStream(conteudo);
        byte[] assinatura = assinante.crie(bais);

        // Verifica assinatura
        AssinaturaDigital verificador = AssinaturaDigital.paraVerificar(
                KEYSTORE, PASSWORD, ALIAS);
        ByteArrayInputStream entrada = new ByteArrayInputStream(conteudo);
        ByteArrayInputStream rubrica = new ByteArrayInputStream(assinatura);
        assertTrue(verificador.verifique(entrada, rubrica));
    }

    @Test
    void calcularHash() {
        final String msg = "A vida é bela!";
        final String hashHex = "cc3808ea2ab49713a67424a6b109db4f1d8c6b776f5429a8c8c61abc60f31c7c";

        byte[] sha256 = AssinaturaDigital.hash(msg);
        assertEquals(hashHex, AssinaturaDigital.toHex(sha256));
    }

    @Test
    void algoritmoInexistenteGeraFalha() {
        assertThrows(RuntimeException.class,
                () -> AssinaturaDigital.hash("x", new byte[1]));
    }
}
