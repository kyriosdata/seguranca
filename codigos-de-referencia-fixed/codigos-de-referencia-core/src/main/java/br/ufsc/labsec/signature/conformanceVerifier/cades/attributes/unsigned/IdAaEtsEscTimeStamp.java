/*

Desenvolvido pelo Laboratório de Segurança em Computação (LabSEC) do Departamento de Informática e Estatística (INE),
da Universidade Federal de Santa Catarina (UFSC).

Apoio: Colégio Notarial do Brasil (CNB) e Instituto Nacional de Tecnologia da Informação (ITI).

 */

package br.ufsc.labsec.signature.conformanceVerifier.cades.attributes.unsigned;

import org.bouncycastle.asn1.cms.Attribute;
import org.bouncycastle.asn1.cms.ContentInfo;
import org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers;

import br.ufsc.labsec.signature.conformanceVerifier.cades.AbstractVerifier;
import br.ufsc.labsec.signature.exceptions.EncodingException;
import br.ufsc.labsec.signature.exceptions.PbadException;
import br.ufsc.labsec.signature.exceptions.SignatureAttributeException;

/**
 * Repesenta o carimbo de tempo sobre as referências no formato CAdES.
 * <p>
 * 
 * Oid e esquema do atributo id-aa-ets-escTimeStamp retirado do documento ETSI
 * TS 101 733 V1.8.1:
 * <p>
 * 
 * <pre>
 * id-aa-ets-escTimeStamp OBJECT IDENTIFIER ::= { iso(1) member-body(2)
 * us(840) rsadsi(113549) pkcs(1) pkcs-9(9) smime(16) id-aa(2) 25}
 * 
 * ESCTimeStampToken ::= TimeStampToken
 * </pre>
 */
public class IdAaEtsEscTimeStamp extends IdAaSignatureTimeStampToken {

    public static final String IDENTIFIER = PKCSObjectIdentifiers.id_aa_ets_escTimeStamp.getId();

    /**
     * Constrói um objeto {@link IdAaEtsEscTimeStamp} a partir de um
     * {@link ContentInfo}.
     * @param contentInfo O conteúdo do carimbo do tempo
     * @throws SignatureAttributeException
     */
    public IdAaEtsEscTimeStamp(ContentInfo contentInfo) throws SignatureAttributeException {
        super(contentInfo);
    }

    /**
     * Deve-se utilizar este construtor no momento de validação do atributo. O
     * parâmetro <code> index </code> deve ser usado no caso em que há mais de
     * um atributo do mesmo tipo. Caso contrário, ele deve ser zero.
     * @param verifier Usado para criar e verificar o atributo
     * @param index Índice usado para selecionar o atributo
     * @throws SignatureAttributeException
     */
    public IdAaEtsEscTimeStamp(AbstractVerifier verifier, Integer index) throws SignatureAttributeException, EncodingException {
        super(verifier, index);
    }

    /**
     * Constrói um objeto {@link IdAaEtsEscTimeStamp}
     * @param genericEncoding O atributo codificado
     * @throws SignatureAttributeException
     */
    public IdAaEtsEscTimeStamp(Attribute genericEncoding) throws SignatureAttributeException {
        super(genericEncoding);
    }

    /**
     * Retorna o identificador do atributo
     * @return O identificador do atributo
     */
    @Override
    public String getIdentifier() {
        return IdAaEtsEscTimeStamp.IDENTIFIER;
    }

    /**
     * Calcula o hash do atributo
     * @param algorithm O algoritmo utilizado
     * @return O valor de hash do atributo
     * @throws PbadException Exceção em caso de erro durante o cálculo
     */
    @Override
    public byte[] getHashFromSignature(String algorithm) throws PbadException {
        return this.signatureVerifier.getSignature().getSigAndRefsHashValue(algorithm);
    }
}
