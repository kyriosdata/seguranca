/*

Desenvolvido pelo Laboratório de Segurança em Computação (LabSEC) do Departamento de Informática e Estatística (INE),
da Universidade Federal de Santa Catarina (UFSC).

Apoio: Colégio Notarial do Brasil (CNB) e Instituto Nacional de Tecnologia da Informação (ITI).

 */

package br.ufsc.labsec.signature.conformanceVerifier.cades.attributes.unsigned;

import java.sql.Time;

import org.bouncycastle.asn1.cms.Attribute;
import org.bouncycastle.asn1.cms.ContentInfo;

import br.ufsc.labsec.signature.conformanceVerifier.cades.AbstractVerifier;
import br.ufsc.labsec.signature.AlgorithmIdentifierMapper;
import br.ufsc.labsec.signature.conformanceVerifier.cades.SignatureVerifier;
import br.ufsc.labsec.signature.conformanceVerifier.cades.exceptions.TimeStampException;
import br.ufsc.labsec.signature.conformanceVerifier.cades.exceptions.UnknowAttributeException;
import br.ufsc.labsec.signature.exceptions.EncodingException;
import br.ufsc.labsec.signature.exceptions.PbadException;
import br.ufsc.labsec.signature.exceptions.SignatureAttributeException;

/**
 * O atributo IdAaEtsArchiveTimeStampV2 representa o carimbo do tempo de
 * arquivamento.
 * <p>
 * 
 * Oid e esquema do atributo id-aa-ets-archiveTimestampV2 retirado do documento
 * ETSI TS 101 733 V1.8.1:
 * <p>
 * 
 * <pre>
 * id-aa-ets-archiveTimestampV2 OBJECT IDENTIFIER ::= { iso(1) member-body(2)
 * us(840) rsadsi(113549) pkcs(1) pkcs-9(9) smime(16) id-aa(2) 48}
 * 
 * ArchiveTimeStampToken ::= TimeStampToken
 * </pre>
 */
public class IdAaEtsArchiveTimeStampV2 extends IdAaSignatureTimeStampToken {
    public static final String IDENTIFIER = "1.2.840.113549.1.9.16.2.48";

    /**
     * Deve-se utilizar este construtor no momento de validação do atributo. O
     * parâmetro <code> index </code> deve ser usado no caso em que há mais de
     * um atributo do mesmo tipo. Caso contrário, ele deve ser zero.
     * @param signatureVerifier Usado para criar e verificar o atributo
     * @param index Índice usado para selecionar o atributo
     */
    public IdAaEtsArchiveTimeStampV2(AbstractVerifier signatureVerifier, Integer index) throws SignatureAttributeException {
        super(signatureVerifier, index);
    }

    /**
     * Constrói um objeto {@link IdAaEtsArchiveTimeStampV2}
     * @param genericEncoding O atributo codificado.
     */
    public IdAaEtsArchiveTimeStampV2(Attribute genericEncoding) throws SignatureAttributeException {
        super(genericEncoding);
    }

    /**
     * Constrói um objeto {@link IdAaEtsArchiveTimeStampV2} a partir de um
     * {@link ContentInfo}.
     * @param contentInfo O conteúdo do carimbo do tempo
     */
    public IdAaEtsArchiveTimeStampV2(ContentInfo contentInfo) throws SignatureAttributeException, EncodingException {
        super(contentInfo);
    }

    /**
     * Retorna o identificador do atributo
     * @return O identificador do atributo
     */
    @Override
    public String getIdentifier() {
        return IdAaEtsArchiveTimeStampV2.IDENTIFIER;
    }

    /**
     * Calcula o hash do atributo
     * @param hashAlgorithmId O algoritmo utilizado
     * @return O valor de hash do atributo
     * @throws PbadException Exceção em caso de erro durante o cálculo
     */
    @Override
    protected byte[] getHashFromSignature(String hashAlgorithmId) throws PbadException {
    	return getHashFromSignature(hashAlgorithmId, true);
    }

    /**
     * Calcula o hash do atributo
     * @param hashAlgorithmId O algoritmo utilizado
     * @param hashWithoutTag Indica a forma de cálculo da hash, de acordo com as notas 2 e 3 da pagina 109 do ETSI TS 101 733 V2.2.1.
     *                      Se verdadeiro indica que o calculo é feito sem incluir tag e length.
     * @return O valor de hash do atributo
     * @throws PbadException Exceção em caso de erro durante o cálculo
     */
    protected byte[] getHashFromSignature(String hashAlgorithmId, boolean hashWithoutTag) throws PbadException {
        return this.signatureVerifier.getSignature().getArchiveTimeStampHashValue(
                AlgorithmIdentifierMapper.getAlgorithmNameFromIdentifier(hashAlgorithmId), this.getTimeReference(), hashWithoutTag);
    }

    /**
     * Verifica se o atributo é o último carimbo na assinatura
     * @return Indica se o carimbo é o último na assinatura
     */
    @Override
    protected boolean isLast() {
        boolean result = false;
        SignatureVerifier verifier = (SignatureVerifier) this.signatureVerifier;
        Time timeReference;
        try {
            timeReference = verifier.getOrderedTimeStamps().get(0).getTimeReference();
        } catch (TimeStampException timeStampException) {
            return false;
        } catch (SignatureAttributeException signatureAttributeException) {
            return false;
        } catch (EncodingException e) {
            return false;
        } catch (UnknowAttributeException e) {
            return false;
        }
        try {
            if (timeReference.compareTo(this.getTimeReference()) == 0)
                result = true;
        } catch (TimeStampException e) {
            return false;
        }
        return result;
    }
}
