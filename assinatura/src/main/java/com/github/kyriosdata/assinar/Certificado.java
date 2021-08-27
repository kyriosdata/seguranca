/*
 * Copyright (c) 2021
 * Fábrica de Software - Instituto de Informática
 * Fábio Nogueira de Lucena
 */
package com.github.kyriosdata.assinar;

import java.io.FileInputStream;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.security.*;
import java.security.cert.Certificate;
import java.util.Base64;
import java.util.Objects;

/**
 * Classe que representa um certificado e permite operações
 * pertinentes como assinar um conteúdo e verificar se o
 * certificado foi empregado para assinar um documento
 * fornecido.
 */
@SuppressWarnings("PMD.DataflowAnomalyAnalysis")
public final class Certificado {

    /**
     * Formato hexadecimal.
     */
    private static final String HEX = "%02x";

    /**
     * Algoritmo empregado para produção do valor de hash.
     */
    public static final String ALGORITHM = "SHA-256";

    /**
     * Formato do repositório de certificados. O mesmo de arquivos
     * no formato .pfx.
     */
    private static final String STORE_TYPE = "PKCS12";

    /**
     * Estratégia empregada para assinar documentos.
     */
    public static final String SIGNING_ALGORITHM = "SHA256withRSA";

    /**
     * Chave pública associada ao certificado carregado.
     */
    private final PublicKey publicKey;

    /**
     * Chave privada associada ao certificado carregado.
     */
    private final PrivateKey privateKey;

    /**
     * Identificador do certificado.
     */
    private final String id;

    /**
     * Cria instância de certificado.
     *
     * @param keystore Arquivo contendo repositório de certificados (formato
     *                 {@link #STORE_TYPE}).
     * @param password Senha de acesso ao repositório.
     * @param alias Nome do certificado a ser recuperado
     *              do repositório.
     * @param id Nome associado ao certificado. Nenhum uso específico é
     *           previsto senão retornar este valor pelo método
     *           {@link #getId()}.
     */
    public Certificado(String keystore, String password, String alias, String id) {
        this(keystore,
                Objects.requireNonNull(password, "senha null").toCharArray(),
                alias, id);
    }

    /**
     * Cria instância de certificado.
     *
     * @param keystore Arquivo contendo repositório de certificados (formato
     *                 {@link #STORE_TYPE}).
     * @param senha Senha de acesso ao repositório.
     * @param alias Nome do certificado a ser recuperado
     *              do repositório.
     * @param id Nome associado ao certificado. Nenhum uso específico é
     *           previsto senão retornar este valor pelo método
     *           {@link #getId()}.
     */
    public Certificado(String keystore, char[] senha, String alias, String id) {
        Objects.requireNonNull(keystore);
        Objects.requireNonNull(senha);
        Objects.requireNonNull(alias);
        Objects.requireNonNull(id);

        try {
            KeyStore keyStore = KeyStore.getInstance(STORE_TYPE);
            keyStore.load(new FileInputStream(keystore), senha);

            privateKey = (PrivateKey) keyStore.getKey(alias, senha);
            Certificate certificate = keyStore.getCertificate(alias);
            publicKey = certificate.getPublicKey();

            this.id = id;
        } catch (Exception exp) {
            throw new RuntimeException("erro ao criar certificado", exp);
        }
    }

    /**
     * Retorna o identificador associado ao serviço de segurança (certificado).
     *
     * @return Identificador para a instância.
     */
    public String getId() {
        return id;
    }

    /**
     * Obtém o valor de hash para a sequência de caracteres fornecida.
     * O algoritmo empregado é definido por {@link #ALGORITHM}.
     *
     * @param conteudo Conteúdo cujo valor de hash é desejado.
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
     * Converte sequência de caracteres na versão usando Base64.
     *
     * @param dados Sequência a ser convertida para a Base64.
     * @return Codificação da sequência fornecida na base64.
     * @see #toBase64(byte[])
     * @see #base64ToString(String)
     * @see #decodeBase64(String)
     */
    public static String toBase64(final String dados) {
        return toBase64(dados.getBytes(StandardCharsets.UTF_8));
    }

    /**
     * Converte sequência de bytes na codificação base64 correspondente.
     *
     * @param dados Sequência de bytes a ser codificada na base64.
     * @return Codificação do vetor de entrada na base64.
     * @see #toBase64(String)
     * @see #base64ToString(String)
     * @see #decodeBase64(String)
     */
    public static String toBase64(final byte[] dados) {
        return Base64.getEncoder().encodeToString(dados);
    }

    /**
     * Decodifica a sequência fornecida na base64.
     *
     * @param base64 Sequência codificada na base64.
     * @return Sequência de bytes correspondente à entrada
     * fornecida na base64.
     */
    public static byte[] decodeBase64(final String base64) {
        return Base64.getDecoder().decode(base64);
    }

    /**
     * Converte a sequência codificada na base64 para a
     * sequência de caracteres correspondentes.
     *
     * @param base64 Entrada codificada na base64.
     * @return Sequência de caracteres correspondente à decodificação
     * da entrada na base64.
     */
    public static String base64ToString(final String base64) {
        byte[] bytes = decodeBase64(base64);
        return new String(bytes, StandardCharsets.UTF_8);
    }

    /**
     * Cria assinatura para os dados obtidos pelo stream.
     *
     * @param paraAssinar Entrada contendo os dados a serem assinados.
     * @return A assinatura correspondente aos dados de entrada e
     * a chave privada indicada no momento em que a instância foi
     * criada.
     * @throws RuntimeException Indica motivo pelo qual não foi
     *                          possível criar a instância.
     */
    public byte[] crie(InputStream paraAssinar) throws Exception {
        return crie(paraAssinar.readAllBytes());
    }

    /**
     * Verifica a assinatura atribuída ao conteúdo fornecido.
     *
     * @param assinado   Conteúdo para o qual a assinatura foi criada.
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
     *
     * @param data Dados a serem assinados.
     * @return Assinatura para os bytes fornecidos empregando
     * a chave privada indicada no momento da criação da instância.
     * @throws RuntimeException Indica que não foi possível
     *                          criar a assinatura.
     */
    public byte[] crie(byte[] data) throws Exception {
        Signature assinante = Signature.getInstance(SIGNING_ALGORITHM);
        assinante.initSign(privateKey);
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
     *                          não pode ser realizada de forma satisfatória.
     */
    public boolean verifique(
            byte[] assinado,
            byte[] assinatura) {
        try {
            Signature assinante = Signature.getInstance(SIGNING_ALGORITHM);
            assinante.initVerify(publicKey);
            assinante.update(assinado);

            return assinante.verify(assinatura);
        } catch (Exception exp) {
            throw new RuntimeException("não foi possível verificar assinatura", exp);
        }
    }
}
