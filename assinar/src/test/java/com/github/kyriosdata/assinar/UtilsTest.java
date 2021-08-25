/**
 * Copyright (c) 2019
 * Fábrica de Software - Instituto de Informática
 * Fábio Nogueira de Lucena
 */

package com.github.kyriosdata.assinar;

import org.junit.jupiter.api.Test;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;

import static org.junit.jupiter.api.Assertions.*;

class UtilsTest {

    public static final char[] PASSWORD = "keystore".toCharArray();
    public static final String KEYSTORE = "assinar.keystore";
    public static final String ALIAS = "teste";

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
}
