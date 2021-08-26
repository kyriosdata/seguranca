/*
 * Copyright (c) 2021
 * Fábrica de Software - Instituto de Informática
 * Fábio Nogueira de Lucena
 */
package com.github.kyriosdata.assinar;

import java.io.*;
import java.nio.charset.StandardCharsets;
import java.security.*;
import java.security.cert.Certificate;

/**
 * Classe de conveniência para facilitar a criação de
 * assinaturas digitais e a verificação de assinaturas.
 * Uma instância deve ser criada para criar assinaturas,
 * via método {@link #paraCriar(String, char[], String)}
 * e outra específica para verificar, via método
 * {@link #paraVerificar(String, char[], String)}.
 */
@SuppressWarnings("PMD.DataflowAnomalyAnalysis")
public final class AssinaturaDigital {

    /**
     * Formato hexadecimal.
     */
    private static final String HEX = "%02x";

    /**
     * Algoritmo empregado para produção do valor de hash.
     */
    public static final String ALGORITHM = "SHA-256";

    private static final String STORE_TYPE = "PKCS12";

    public static final String SIGNING_ALGORITHM = "SHA256withRSA";

    private static PrivateKey getPrivateKey(
            String keystore,
            char[] password,
            String alias) throws Exception {
        KeyStore keyStore = KeyStore.getInstance(STORE_TYPE);
        keyStore.load(new FileInputStream(keystore), password);
        return (PrivateKey) keyStore.getKey(alias, password);
    }

    private static PublicKey getPublicKey(
            String keystore,
            char[] password,
            String alias) throws Exception {
        KeyStore keyStore = KeyStore.getInstance(STORE_TYPE);
        keyStore.load(new FileInputStream(keystore), password);
        Certificate certificate = keyStore.getCertificate(alias);
        return certificate.getPublicKey();
    }

    /**
     * A chave pública ou privada armazenada pela instância.
     * Será pública se criada pelo método
     * {@link #paraVerificar(String, char[], String)} e será
     * privada se criada pelo método
     * {@link #paraCriar(String, char[], String)}.
     */
    private Key chave;

    private AssinaturaDigital(Key chave) {
        this.chave = chave;
    }

    /**
     * Cria instância apta a criar assinaturas.
     *
     * @param keystore Repositório contendo chave privada.
     * @param password Senha de acesso ao repositório.
     * @param alias Nome (alias) do certificado.
     *
     * @return Instância apta a criar assinaturas digitais
     * para o certificado indicado.
     */
    public static AssinaturaDigital paraCriar(
            final String keystore,
            final char[] password,
            final String alias) {
        try {
            Key chavePublica = getPrivateKey(keystore, password, alias);
            return new AssinaturaDigital(chavePublica);
        } catch (Exception exp) {
            throw new RuntimeException("erro ao recuperar chave pública", exp);
        }
    }

    /**
     * Cria instância apta a verificar assinaturas.
     *
     * @param keystore Repositório contendo chave pública.
     * @param password Senha de acesso ao repositório.
     * @param alias Nome (alias) para certificado.
     *
     * @return Instância apta a verificar assinaturas
     * com base na chave pública indicada.
     */
    public static AssinaturaDigital paraVerificar(
            final String keystore,
            final char[] password,
            final String alias) {
        try {
            Key chavePrivada = getPublicKey(keystore, password, alias);
            return new AssinaturaDigital(chavePrivada);
        } catch (Exception exp) {
            throw new RuntimeException("erro ao recuperar chave privada", exp);
        }
    }

    /**
     * Obtém o valor de hash para a sequência de caracteres fornecida.
     * O algoritmo empregado é definido por {@link #ALGORITHM}.
     *
     * @param conteudo Conteúdo cujo valor de hash é desejado.
     *
     * @return A sequência de bytes correspondente ao valor de hash
     * para o argumento de entrada.
     */
    public static byte[] hash(final String conteudo) {
        return hash(conteudo.getBytes(StandardCharsets.UTF_8));
    }

    /**
     * Produz o valor de hash para a sequência de bytes fornecida. O
     * algoritmo de hash utilizado é definido pela constante
     * {@link #ALGORITHM}.
     *
     * @param conteudo Sequência de bytes para a qual o valor de hash
     *                 será calculado.
     * @return Valor do hash para o conteúdo fornecido. A sequência de bytes
     * retornada pode ser convertida para a representação hexadecimal
     * pelo método {@link #toHex(byte[])}.
     * @see #toHex(byte[])
     */
    public static byte[] hash(final byte[] conteudo) {
        return hash(ALGORITHM, conteudo);
    }

    /**
     * Produz o valor de hash usando um algoritmo.
     *
     * @param algorithm O algoritmo a ser utilizado para produzir o valor de
     *                  hash.
     * @param conteudo  Conteúdo cujo valor de hash será produzido.
     * @return Valor de hash empregando o algoritmo fornecido ou o valor
     * {@code null} caso o algoritmo seja inválido ou ocorra situação
     * excepcional durante a produção do valor de hash.
     */
    public static byte[] hash(final String algorithm, final byte[] conteudo) {
        try {
            final MessageDigest hash = MessageDigest.getInstance(algorithm);
            hash.update(conteudo);
            return hash.digest();
        } catch (NoSuchAlgorithmException se) {
            throw new RuntimeException("algoritmo não disponível", se);
        }
    }

    /**
     * Produz sequência de caracteres em hexadecimal para o vetor de bytes.
     *
     * @param sequencia Vetor de bytes cuja sequência em hexadecimal é desejada.
     * @return Sequência em hexadecimal correspondente aos bytes do vetor
     * fornecido.
     */
    public static String toHex(final byte[] sequencia) {
        final StringBuilder str = new StringBuilder(2 * sequencia.length);

        for (final byte valor : sequencia) {
            str.append(String.format(HEX, valor));
        }

        return str.toString();
    }

    /**
     * Cria assinatura para os dados obtidos pelo stream.
     *
     * @param paraAssinar Entrada contendo os dados a serem assinados.
     *
     * @return A assinatura correspondente aos dados de entrada e
     * a chave privada indicada no momento em que a instância foi
     * criada.
     *
     * @throws RuntimeException Indica motivo pelo qual não foi
     * possível criar a instância.
     */
    public byte[] crie(InputStream paraAssinar) throws Exception {
        return crie(paraAssinar.readAllBytes());
    }

    /**
     * Verifica a assinatura atribuída ao conteúdo fornecido.
     *
     * @param assinado Conteúdo para o qual a assinatura foi criada.
     * @param assinatura A assinatura criada para o conteúdo.
     * @return O valor {@code true} se e somente se a assinatura é
     * correspondente ao conteúdo fornecido. Adicionalmente, sabe-se
     * que a assinatura foi produzida pela chave pública definida na
     * criação da instância.
     */
    public boolean verifique(InputStream assinado, InputStream assinatura) {
        try {
            return verifique(assinado.readAllBytes(), assinatura.readAllBytes());
        } catch (Exception exp) {
            throw new RuntimeException("não foi possível verificar assinatura", exp);
        }
    }

    /**
     * Cria uma assinatura para o vetor de bytes.
     * @param data Dados a serem assinados.
     *
     * @return Assinatura para os bytes fornecidos empregando
     * a chave privada indicada no momento da criação da instância.
     * @throws RuntimeException Indica que não foi possível
     * criar a assinatura.
     */
    public byte[] crie(byte[] data) throws Exception {
        Signature assinante = Signature.getInstance(SIGNING_ALGORITHM);
        assinante.initSign((PrivateKey) chave);
        assinante.update(data);

        return assinante.sign();
    }

    /**
     * Verifica a assinatura de determinado conteúdo.
     *
     * @param assinado   Conteúdo assinado.
     * @param assinatura Assinatura estabelecida para o conteúdo assinado.
     * @return O valor {@code true} se e somente se a assinatura é válida.
     * @throws RuntimeException Indica motivo pelo qual a verificação
     * não pode ser realizada de forma satisfatória.
     */
    public boolean verifique(
            byte[] assinado,
            byte[] assinatura) {
        try {
            Signature signature = Signature.getInstance(SIGNING_ALGORITHM);
            signature.initVerify((PublicKey) chave);
            signature.update(assinado);

            return signature.verify(assinatura);
        } catch (Exception exp) {
            throw new RuntimeException("não foi possível verificar assinatura", exp);
        }
    }
}
