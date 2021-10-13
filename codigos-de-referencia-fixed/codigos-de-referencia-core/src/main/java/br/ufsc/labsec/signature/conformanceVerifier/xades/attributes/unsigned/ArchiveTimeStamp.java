/*

Desenvolvido pelo Laboratório de Segurança em Computação (LabSEC) do Departamento de Informática e Estatística (INE),
da Universidade Federal de Santa Catarina (UFSC).

Apoio: Colégio Notarial do Brasil (CNB) e Instituto Nacional de Tecnologia da Informação (ITI).

 */

package br.ufsc.labsec.signature.conformanceVerifier.xades.attributes.unsigned;

import java.sql.Time;

import org.bouncycastle.asn1.cms.ContentInfo;
import org.w3c.dom.Element;

import br.ufsc.labsec.signature.conformanceVerifier.xades.AbstractVerifier;
import br.ufsc.labsec.signature.AlgorithmIdentifierMapper;
import br.ufsc.labsec.signature.conformanceVerifier.xades.SignatureVerifier;
import br.ufsc.labsec.signature.conformanceVerifier.xades.attributes.SignatureAttribute;
import br.ufsc.labsec.signature.exceptions.EncodingException;
import br.ufsc.labsec.signature.exceptions.PbadException;
import br.ufsc.labsec.signature.exceptions.SignatureAttributeException;
import br.ufsc.labsec.signature.conformanceVerifier.xades.exceptions.TimeStampException;
import br.ufsc.labsec.signature.conformanceVerifier.xades.exceptions.UnknowAttributeException;

/**
 * Representa o carimbo do tempo de arquivamento no formato XAdES.
 * Esquema do atributo ArchiveTimeStamp retirado do ETSI TS 101 903:
 * 
 * {@code 
 * <xsd:element name="TimeStampValidationData" type="ValidationDataType"/>
 * 
 * <xsd:complexType name="ValidationDataType">
 * <xsd:sequence>
 * 	<xsd:element ref="xades:CertificateValues" minOccurs="0" />
 * 	<xsd:element ref="xades:RevocationValues" minOccurs="0" />
 * </xsd:sequence>
 * <xsd:attribute name="Id" type="xsd:ID" use="optional"/>
 * <xsd:attribute name="UR" type="xsd:anyURI" use="optional"/>
 * </xsd:complexType>
 * }
 */
public class ArchiveTimeStamp extends SignatureTimeStamp implements SignatureAttribute {
    public static final String IDENTIFIER = "ArchiveTimeStamp";

    /**
     * Construtor usado para instanciar um ou mais carimbos do tempo de
     * arquivamento
     * @param abstractVerifier Usado para criar e verificar o atributo
     * @param index Índice usado para selecionar o atributo
     * @throws SignatureAttributeException
     */
    public ArchiveTimeStamp(AbstractVerifier abstractVerifier, Integer index) throws SignatureAttributeException, EncodingException {
        super(abstractVerifier, index);
    }

    /**
     * Construtor usado para criar um novo carimbo do tempo de arquivamento
     * através de um {@link ContentInfo}
     * @param contentInfo O conteúdo do carimbo do tempo
     */
    public ArchiveTimeStamp(ContentInfo contentInfo) {
        super(contentInfo);
    }

    /**
     * Decodifica o atributo para adição de atributos ou obtenção de dados do
     * carimbo do tempo
     * @param genericEncoding O atributo codificado
     * @throws EncodingException
     * @throws SignatureAttributeException
     */
    public ArchiveTimeStamp(Element genericEncoding) throws EncodingException, SignatureAttributeException {
        super(genericEncoding);
    }

    /**
     * Retorna o identificador do atributo
     * @return O identificador do atributo
     */
    @Override
    public String getIdentifier() {
        return ArchiveTimeStamp.IDENTIFIER;
    }

    /**
     * Calcula o valor de hash do carimbo de tempo de arquivamento
     * @param hashAlgorithmId O algoritmo a ser utilizado no cálculo
     * @return O valor de hash do carimbo
     * @throws PbadException Exceção em caso de erro na canonização
     */
    @Override
    protected byte[] getHashFromSignature(String hashAlgorithmId) throws PbadException {
        byte[] valueHash = this.signatureVerifier.getSignature().getArchiveTimeStampHashValue(
                AlgorithmIdentifierMapper.getAlgorithmNameFromIdentifier(hashAlgorithmId), this.getTimeReference());
        return valueHash;
    }

    /**
     * Retorna o nome do atributo
     * @return O nome "XAdES:ArchiveTimeStamp"
     */
    @Override
    protected String getElementName() {
        return "XAdES:ArchiveTimeStamp";
    }

    /**
     * Verifica se o atributo é o último carimbo na assinatura
     * @return Indica se o carimbo é o último na assinatura
     * @throws TimeStampException Exceção em caso de erro na verificação da lista de carimbos
     */
    @Override
    protected boolean isLast() throws TimeStampException {
        boolean result = false;
        SignatureVerifier verifier = (SignatureVerifier) this.signatureVerifier;
        Time timeReference;
        try {
            timeReference = verifier.getOrderedTimeStamps().get(0).getTimeReference();
        } catch (TimeStampException timeStampException) {
            throw new TimeStampException(timeStampException);
        } catch (EncodingException encodingException) {
            throw new TimeStampException(encodingException);
        } catch (SignatureAttributeException signatureAttributeException) {
            throw new TimeStampException(signatureAttributeException);
        } catch (UnknowAttributeException unknowAttributeException) {
            throw new TimeStampException(unknowAttributeException);
        }
        if (timeReference.compareTo(this.getTimeReference()) == 0)
            result = true;
        return result;
    }

}
