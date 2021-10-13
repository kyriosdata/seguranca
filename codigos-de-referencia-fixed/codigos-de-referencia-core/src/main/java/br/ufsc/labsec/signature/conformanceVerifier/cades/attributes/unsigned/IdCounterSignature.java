/*

Desenvolvido pelo Laboratório de Segurança em Computação (LabSEC) do Departamento de Informática e Estatística (INE),
da Universidade Federal de Santa Catarina (UFSC).

Apoio: Colégio Notarial do Brasil (CNB) e Instituto Nacional de Tecnologia da Informação (ITI).

 */

package br.ufsc.labsec.signature.conformanceVerifier.cades.attributes.unsigned;

import org.bouncycastle.asn1.cms.Attribute;
import org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers;
import org.bouncycastle.cms.SignerInformation;

import br.ufsc.labsec.signature.conformanceVerifier.cades.AbstractVerifier;
import br.ufsc.labsec.signature.conformanceVerifier.cades.CadesSignatureInformation;
import br.ufsc.labsec.signature.conformanceVerifier.cades.CmsParent;
import br.ufsc.labsec.signature.conformanceVerifier.cades.SignatureVerifier;
import br.ufsc.labsec.signature.conformanceVerifier.cades.attributes.CounterSignatureInterface;
import br.ufsc.labsec.signature.exceptions.SignatureAttributeException;

/**
 * Representa uma contra assinatura no formato CAdES.
 * <p>
 * 
 * Oid e esquema do atributo id-countersignature retirado da RFC 3852:
 * <p>
 * 
 * <pre>
 *  id-countersignature OBJECT IDENTIFIER ::= { iso(1) member-body(2)
 *  us(840) rsadsi(113549) pkcs(1) pkcs9(9) 6 }
 *         
 *  Countersignature ::= SignerInfo
 * </pre>
 * 
 * @see <a href="http://www.ietf.org/rfc/rfc3852.txt">RFC 3852</a>
 */
public class IdCounterSignature extends CadesSignatureInformation implements CounterSignatureInterface {

    public static final String IDENTIFIER = PKCSObjectIdentifiers.pkcs_9_at_counterSignature.getId();

    /**
     * É passado uma referência nula para a super classe, pois uma instância
     * derivada deste construtor nunca será utilizada, tendo em vista que a
     * verificação de contra assinaturas é realizada de forma diferente dos
     * demais atributos não assinados
     * @param signatureVerifier Usado para criar e verificar o atributo
     * @param index Índice usado para selecionar o atributo
     */
    public IdCounterSignature(AbstractVerifier signatureVerifier, Integer index) {
        super(null, true, null);
    }

    /**
     * Chama o construtor da super classe passando o contra assinante, e passa
     * true como argumento pois toda contra assinatura deve ser detached
     * @param counterSigner SignerInformation do contra-assinante
     * @param parent A assinatura que será contra assinada
     */
    public IdCounterSignature(SignerInformation counterSigner, CmsParent parent) {
        super(counterSigner, true, parent);
    }

    /**
     * Método não utilizado por esta classe, o atributo contra assinatura tem um
     * tratamento diferente dos demais
     */
    @Override
    public Attribute getEncoded() throws SignatureAttributeException {
        return null;
    }

    /**
     * Retorna o identificador do atributo
     * @return O identificador do atributo
     */
    @Override
    public String getIdentifier() {
        return IdCounterSignature.IDENTIFIER;
    }

    /**
     * Informa se o atributo é assinado
     * @return Indica se o atributo é assinado
     */
    @Override
    public boolean isSigned() {
        return false;
    }

    /**
     * Método não utilizado por esta classe, pois a validade da contra
     * assinatura é realizada através da classe {@link SignatureVerifier}
     */
    @Override
    public void validate() throws SignatureAttributeException {
    }

    /**
     * Verifica se o atributo deve ter apenas uma instância na assinatura
     * @return Indica se o atributo deve ter apenas uma instância na assinatura
     */
    @Override
    public boolean isUnique() {
        return false;
    }
}
