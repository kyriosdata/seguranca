/*

Desenvolvido pelo Laboratório de Segurança em Computação (LabSEC) do Departamento de Informática e Estatística (INE),
da Universidade Federal de Santa Catarina (UFSC).

Apoio: Colégio Notarial do Brasil (CNB) e Instituto Nacional de Tecnologia da Informação (ITI).

 */

package br.ufsc.labsec.signature.conformanceVerifier.cades.attributes;

import java.io.IOException;
import java.sql.Time;
import java.util.Date;
import java.util.List;

import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.cms.Attribute;
import org.bouncycastle.asn1.cms.ContentInfo;
import org.bouncycastle.cms.CMSException;
import org.bouncycastle.cms.CMSSignedData;
import org.bouncycastle.tsp.TSPException;
import org.bouncycastle.tsp.TimeStampToken;

import br.ufsc.labsec.signature.conformanceVerifier.cades.CadesSignature;
import br.ufsc.labsec.signature.conformanceVerifier.cades.CadesSignatureContainer;
import br.ufsc.labsec.signature.conformanceVerifier.cades.exceptions.SigningCertificateException;
import br.ufsc.labsec.signature.conformanceVerifier.cades.exceptions.TimeStampException;
import br.ufsc.labsec.signature.conformanceVerifier.report.TimeStampReport;
import br.ufsc.labsec.signature.exceptions.EncodingException;
import br.ufsc.labsec.signature.exceptions.PbadException;
import br.ufsc.labsec.signature.exceptions.SignatureAttributeException;

/**
 * Representa um carimbo do tempo
 */
public abstract class TimeStamp implements Comparable<TimeStamp>, SignatureAttribute {

    /**
     * Conteúdo do carimbo
     */
    protected ContentInfo contentInfo;

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
        TimeStampToken timeStampToken = null;
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
        if (atual != null && expected != null) {
            while (index < atual.length && result == 0) {
                if (atual[index] > expected[index]) {
                    result = 1;
                } else if (atual[index] < expected[index])
                    result = -1;
                index++;
            }
        } else {
            result = -2;
        }
        return result;
    }

    /**
     * Retorna um objeto do atributo desejado
     * @param identifier O identificador do atributo
     * @param index Índice do atributo
     * @return Um objeto do atributo desejado
     */
    public Attribute getEncodedAttribute(String identifier, Integer index) throws SignatureAttributeException {
       
        CadesSignature signature = null;
        try {
        	 CMSSignedData cmsSignedData = new CMSSignedData(this.contentInfo);
             CadesSignatureContainer container = new CadesSignatureContainer(cmsSignedData);
            signature = container.getSignatureAt(0);
        } catch (EncodingException encodingException) {
            throw new SignatureAttributeException(encodingException.getMessage());
        } catch (CMSException cmsException) {
        	throw new SignatureAttributeException(cmsException.getMessage());
		}
        Attribute genericEncoding = null;
        genericEncoding = signature.getEncodedAttribute(identifier, index);
        return genericEncoding;
    }

    public Attribute getEncodedAttribute(String attributeId) throws SignatureAttributeException {
        return this.getEncodedAttribute(attributeId, 0);
    }

    /**
     * Adiciona um atributo não-assinado
     * @param attribute Identificador do atributo a ser adicionado
     * @throws SignatureAttributeException
     */
    public void addUnsignedAttribute(SignatureAttribute attribute) throws SignatureAttributeException {
        List<String> attributeIdentifiers = this.getAttributeList();
        int ocurrences = 0;
        if (attribute.isUnique()) {
            for (String identifier : attributeIdentifiers) {
                if (identifier.equals(attribute.getIdentifier()))
                    ocurrences++;
            }
        }
        if (ocurrences == 0) {
            CadesSignatureContainer signatureContainer = this.contentInfoToSignatureContainer();
            CadesSignature signature = null;
            try {
                signature = signatureContainer.getSignatureAt(0);
            } catch (EncodingException encodingException) {
                throw new SignatureAttributeException(encodingException);
            }
            try {
                signature.addUnsignedAttribute(attribute);
            } catch (PbadException signatureException) {
                throw new SignatureAttributeException(signatureException.getMessage());
            }
            this.contentInfo = signatureContainer.getSignedData().toASN1Structure();
        }
    }

    /**
     * Remove um atributo não-assinado
     * @param attributeId Identificador do atributo a ser removido
     * @param index Índice do atributo
     * @throws SignatureAttributeException
     */
    public void removeUnsignedAttribute(String attributeId, int index) throws SignatureAttributeException, EncodingException {
        CadesSignatureContainer signatureContainer = this.contentInfoToSignatureContainer();
        CadesSignature signature = null;
        try {
            signature = signatureContainer.getSignatureAt(0);
        } catch (EncodingException encodingException) {
            throw new SignatureAttributeException(encodingException);
        }
        try {
            signature.removeUnsignedAttribute(attributeId, index);
        } catch (SignatureAttributeException signatureAttributeException) {
            throw new SignatureAttributeException(signatureAttributeException);
        }
        this.contentInfo = signatureContainer.getSignedData().toASN1Structure();
    }

    /**
     * Substitui um atributo não assinado qualquer, útil quando é necessário adicionar mais
     * atributos em um carimbo de tempo por exemplo
     * @param attribute O atributo que foi atualizado
     * @param index O indice do atributo em relação aos seus similares, ou seja, se há três carimbos do tempo da
     *            assinatura e o segundo vai ser atualizado o indice é 1
     * @throws PbadException
     * @throws SignatureAttributeException
     */
    public void replaceUnsignedAttribute(SignatureAttribute attribute, Integer index) throws PbadException, SignatureAttributeException {
        CadesSignatureContainer signatureContainer = this.contentInfoToSignatureContainer();
        CadesSignature signature = null;
        try {
            signature = signatureContainer.getSignatureAt(0);
        } catch (EncodingException encodingException) {
            throw new SignatureAttributeException(encodingException);
        }
        try {
            signature.replaceUnsignedAttribute(attribute, index);
        } catch (SignatureAttributeException signatureAttributeException) {
            throw new SignatureAttributeException(signatureAttributeException);
        }
        this.contentInfo = signatureContainer.getSignedData().toASN1Structure();
    }

    /**
     * Transforma um ContentInfo (carimbo do tempo) em uma assinatura
     * @return O carimbo como uma assinatura CAdES
     */
    protected CadesSignatureContainer contentInfoToSignatureContainer() {
        CMSSignedData cmsSignedData = null;
		try {
			cmsSignedData = new CMSSignedData(this.contentInfo);
		} catch (CMSException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
        CadesSignatureContainer container = new CadesSignatureContainer(cmsSignedData);
        return container;
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
     * @param otherTimeStamp O objeto a ser comparado
     * @return Indica se os dois objetos são iguais
     */
    @Override
    public int compareTo(TimeStamp otherTimeStamp) {
        int compare = 0;
        try {
            compare = this.getTimeReference().compareTo(otherTimeStamp.getTimeReference());
        } catch (TimeStampException timeStampException) {
            timeStampException.printStackTrace();
        }
        return -compare;
    }

    /**
     * Retorna a lista de atributos do carimbo
     * @return A lista de atributos do carimbo
     */
    public List<String> getAttributeList() {
        CadesSignatureContainer signatureContainer = this.contentInfoToSignatureContainer();
        CadesSignature signature = null;
        try {
            signature = signatureContainer.getSignatureAt(0);
        } catch (EncodingException encodingException) {
            encodingException.printStackTrace();
        }
        return signature.getAttributeList();
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
     * @param report O relatório de verificação do carimbo
     * @param stamps Lista de carimbos de tempo
     * @throws SignatureAttributeException
     */
    public abstract void validate(TimeStampReport report, List<TimeStamp> stamps) throws SignatureAttributeException;
}
