/*

Desenvolvido pelo Laboratório de Segurança em Computação (LabSEC) do Departamento de Informática e Estatística (INE),
da Universidade Federal de Santa Catarina (UFSC).

Apoio: Colégio Notarial do Brasil (CNB) e Instituto Nacional de Tecnologia da Informação (ITI).

 */

package br.ufsc.labsec.signature.conformanceVerifier.xades.attributes.unsigned;

import org.bouncycastle.asn1.cms.ContentInfo;
import org.w3c.dom.Element;

import br.ufsc.labsec.signature.conformanceVerifier.xades.AbstractVerifier;
import br.ufsc.labsec.signature.AlgorithmIdentifierMapper;
import br.ufsc.labsec.signature.conformanceVerifier.xades.attributes.SignatureAttribute;
import br.ufsc.labsec.signature.exceptions.EncodingException;
import br.ufsc.labsec.signature.exceptions.PbadException;
import br.ufsc.labsec.signature.exceptions.SignatureAttributeException;

/**
 * Representa o carimbo do tempo sobre as referências.
 * 
 * Esquema do atributo SigAndRefsTimeStamp retirado do ETSI TS 101 903:
 * 
 * {@code
 * <xsd:element name="SigAndRefsTimeStamp" type="XAdESTimeStampType"/>
 * }
 */
public class SigAndRefsTimeStamp extends SignatureTimeStamp implements SignatureAttribute {

    public static final String IDENTIFIER = "SigAndRefsTimeStamp";

    /**
     * Construtor usado para verificação do atributo
     * @param signatureVerifier Usado para criar e verificar o atributo
     * @param index Índice usado para selecionar o atributo
     * @throws SignatureAttributeException
     * @throws EncodingException
     */
    public SigAndRefsTimeStamp(AbstractVerifier signatureVerifier, Integer index) throws SignatureAttributeException, EncodingException {
        super(signatureVerifier, index);
    }

    /**
     * Retorna a tag XML do atributo
     * @return Retorna "XAdES:SigAndRefsTimeStamp"
     */
    protected String getElementName() {
        return "XAdES:SigAndRefsTimeStamp";
    }

    /**
     * Construtor usado para criar um novo carimbo do tempo.
     * @param contentInfo O conteúdo do carimbo do tempo
     */
    public SigAndRefsTimeStamp(ContentInfo contentInfo) {
        super(contentInfo);
    }

    /**
     * Construtor usado para decodificar carimbos do tempo e obter dados dos
     * mesmos ou alterar os seus atributos não assinados.
     * @param genericEncoding O atributo codificado
     * @throws EncodingException
     * @throws SignatureAttributeException
     */
    public SigAndRefsTimeStamp(Element genericEncoding) throws EncodingException, SignatureAttributeException {
        super(genericEncoding);
    }

    /**
     * Retorna o identificador do atributo
     * @return O identificador do atributo
     */
    @Override
    public String getIdentifier() {
        return SigAndRefsTimeStamp.IDENTIFIER;
    }

    /**
     * Calcula o hash do atributo
     * @param hashAlgorithmId O algoritmo utilizado
     * @return O valor de hash do atributo
     * @throws PbadException Exceção em caso de erro durante o cálculo
     */
    @Override
    protected byte[] getHashFromSignature(String hashAlgorithmId) throws PbadException {
        return this.signatureVerifier.getSignature().getSigAndRefsHashValue(
                AlgorithmIdentifierMapper.getAlgorithmNameFromIdentifier(hashAlgorithmId));
    }
}
