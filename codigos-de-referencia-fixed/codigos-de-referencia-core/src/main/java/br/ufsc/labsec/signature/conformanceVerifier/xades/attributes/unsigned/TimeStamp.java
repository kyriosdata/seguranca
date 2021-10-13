/*

Desenvolvido pelo Laboratório de Segurança em Computação (LabSEC) do Departamento de Informática e Estatística (INE),
da Universidade Federal de Santa Catarina (UFSC).

Apoio: Colégio Notarial do Brasil (CNB) e Instituto Nacional de Tecnologia da Informação (ITI).

 */

package br.ufsc.labsec.signature.conformanceVerifier.xades.attributes.unsigned;

import java.io.IOException;
import java.sql.Time;
import java.util.Date;
import java.util.List;

import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.cms.ContentInfo;
import org.bouncycastle.tsp.TSPException;
import org.bouncycastle.tsp.TimeStampToken;

import br.ufsc.labsec.signature.AttributeParams;
import br.ufsc.labsec.signature.tsa.TimeStampVerifierInterface;
import br.ufsc.labsec.signature.conformanceVerifier.report.TimeStampReport;
import br.ufsc.labsec.signature.conformanceVerifier.xades.AbstractVerifier;
import br.ufsc.labsec.signature.conformanceVerifier.xades.attributes.SignatureAttribute;
import br.ufsc.labsec.signature.exceptions.EncodingException;
import br.ufsc.labsec.signature.exceptions.PbadException;
import br.ufsc.labsec.signature.exceptions.SignatureAttributeException;
import br.ufsc.labsec.signature.conformanceVerifier.xades.exceptions.TimeStampException;

/**
 * Representa um carimbo do tempo
 */
@SuppressWarnings("rawtypes")
public abstract class TimeStamp implements Comparable, SignatureAttribute {

    /**
     * Conteúdo do carimbo
     */
    protected ContentInfo contentInfo;
    /**
     * Objeto de verificador
     */
    protected AbstractVerifier signatureVerifier;

    /**
     * Construtor
     * @param verifier Usado para criar e verificar o atributo
     */
    public TimeStamp(AbstractVerifier verifier) {
        this.signatureVerifier = verifier;
    }

    /**
     * Construtor
     */
    public TimeStamp() {

    }

    /**
     * Obtém a data do carimbo do tempo
     * @return A data do carimbo do tempo
     * @throws TimeStampException Exceção em caso de erro durante a manipulação do carimbo
     */
    public Time getTimeReference() throws TimeStampException {
        TimeStampToken timeStamp = this.buildTimeStampToken();
        Date dateReference = timeStamp.getTimeStampInfo().getGenTime();
        return new Time(dateReference.getTime());
    }

    /**
     * Constrói um {@link TimeStampToken} a partir do contentInfo.
     * @return O {@link TimeStampToken} criado
     * @throws TimeStampException
     */
    protected TimeStampToken buildTimeStampToken() throws TimeStampException {
        TimeStampToken timeStampToken;
        if (this.contentInfo == null) {
            throw new TimeStampException(TimeStampException.MALFORMED_TIME_STAMP);
        }
        try {
            timeStampToken = new TimeStampToken(this.contentInfo);
        } catch (TSPException tspException) {
            TimeStampException exception = new TimeStampException(TimeStampException.INVALID_TIME_STAMP);
            exception.initCause(tspException);
            throw exception;
        } catch (IOException ioException) {
            TimeStampException exception = new TimeStampException(TimeStampException.MALFORMED_TIME_STAMP);
            exception.initCause(ioException);
            throw exception;
        }
        return timeStampToken;
    }

    /**
     * Verifica se dois arrays de bytes são iguais.
     * @param atual O array a ser comparado
     * @param expected O array esperado
     * @return Retorna 0 se são iguais ou 1 se são diferentes
     */
    protected int compareBytes(byte[] atual, byte[] expected) {
        int result = 0;
        int index = 0;
        while (index < atual.length && result == 0) {
            if (atual[index] > expected[index]) {
                result = 1;
            } else if (atual[index] < expected[index])
                result = -1;
            index++;
        }
        return result;
    }

    /**
     * Adiciona um atributo não-assinado
     * @param attributeId Identificador do atributo a ser adicionado
     * @param params Parâmetros do atributo
     * @param stamps Lista de carimbos
     * @throws PbadException
     * @throws SignatureAttributeException
     */
    public void addUnsignedAttribute(String attributeId, AttributeParams params, List<String> stamps) throws SignatureAttributeException, IOException {
        TimeStampVerifierInterface timeStampVerifier = this.signatureVerifier.getXadesSignatureComponent().timeStampVerifier;
        timeStampVerifier.setTimeStamp(this.contentInfo.toASN1Primitive().getEncoded(), this.getIdentifier(), this.signatureVerifier.getSignaturePolicy(),
                getTimeReference(), stamps, isLast());
        timeStampVerifier.addAttribute(attributeId, params);
    }

    /**
     * Remove um atributo não-assinado
     * @param attributeId Identificador do atributo a ser removido
     * @param index Índice do atributo
     * @param stamps Lista de carimbos
     * @throws SignatureAttributeException
     * @throws EncodingException
     * @throws IOException
     */
    public void removeUnsignedAttribute(String attributeId, int index, List<String> stamps) throws SignatureAttributeException, EncodingException, IOException {
        TimeStampVerifierInterface timeStampVerifier = this.signatureVerifier.getXadesSignatureComponent().timeStampVerifier;
        timeStampVerifier.setTimeStamp(this.contentInfo.toASN1Primitive().getEncoded(), this.getIdentifier(), this.signatureVerifier.getSignaturePolicy(),
                getTimeReference(), stamps, isLast());
        timeStampVerifier.removeAttribute(attributeId, index);
    }

    /**
     * Obtém o <code>ContentInfo<code>, que pertence ao BouncyCastle
     * e permite um acesso mais detalhado à
     * estrutura do carimbo do tempo
     * @return O {@link ContentInfo} do carimbo
     */
    public ContentInfo getContentInfo() {
        ContentInfo contentInfo = ContentInfo.getInstance((ASN1Sequence) this.contentInfo.toASN1Primitive());
        return contentInfo;
    }

    /**
     * Compara dois objetos desta classe
     * @param object O objeto a ser comparado
     * @return Indica se os dois objetos são iguais
     */
    @Override
    public int compareTo(Object object) {
        TimeStamp otherTimeStamp = (TimeStamp) object;
        int compare = 0;
        try {
            compare = this.getTimeReference().compareTo(otherTimeStamp.getTimeReference());
        } catch (TimeStampException timeStampException) {
            timeStampException.printStackTrace();
        }
        return -compare;
    }

    /**
     * Calcula o hash do atributo
     * @param hashAlgorithmId O algoritmo utilizado
     * @return O valor de hash do atributo
     * @throws PbadException Exceção em caso de erro durante o cálculo
     */
    protected abstract byte[] getHashFromSignature(String hashAlgorithmId) throws PbadException;

    /**
     * Obtém o identificador do atributo
     */
    public abstract String getIdentifier();

    /**
     * Faz a validação do atributo
     * @param timeStampReport O relatório de verificação do carimbo
     * @param stamps Lista de carimbos de tempo
     * @throws PbadException
     */
    public abstract void validate(TimeStampReport timeStampReport, List<TimeStamp> stamps) throws PbadException;

    /**
     * Gera o relatório de verificação do carimbo de tempo
     * @return O relatório criado
     */
    public abstract TimeStampReport getReport();

    /**
     * Retorna se o carimbo de tempo é o último da assinatura
     * @return Indica se o carimbo é o último na assinatura
     * @throws TimeStampException
     */
    protected abstract boolean isLast() throws TimeStampException;
}
