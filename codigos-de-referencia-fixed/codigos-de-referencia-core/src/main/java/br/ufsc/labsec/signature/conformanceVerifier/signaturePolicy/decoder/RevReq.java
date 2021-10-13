/*

Desenvolvido pelo Laboratório de Segurança em Computação (LabSEC) do Departamento de Informática e Estatística (INE),
da Universidade Federal de Santa Catarina (UFSC).

Apoio: Colégio Notarial do Brasil (CNB) e Instituto Nacional de Tecnologia da Informação (ITI).

 */

package br.ufsc.labsec.signature.conformanceVerifier.signaturePolicy.decoder;

import br.ufsc.labsec.signature.conformanceVerifier.signaturePolicy.SignaturePolicyExtension;
import org.bouncycastle.asn1.ASN1Enumerated;
import org.bouncycastle.asn1.ASN1Sequence;
import org.w3c.dom.Element;

///**
// * RevReq ::= SEQUENCE {
// enuRevReq EnuRevReq,
// exRevReq    SignPolExtensions OPTIONAL}
//
// * EnuRevReq ::= ENUMERATED {
// clrCheck    (0), --Checks shall be made against current CRLs
// -- (or authority revocation lists)
// ocspCheck   (1), -- The revocation status shall be checked
// -- using the Online Certificate Status Protocol (RFC 2450)
// bothCheck   (2),    -- Both CRL and OCSP checks shall be carried out
// eitherCheck (3),    -- At least one of CRL or OCSP checks shall be carried out
// noCheck     (4),    -- no check is mandated
// other       (5) -- Other mechanism as defined by signature policy extension
// }
// */
//
///**
// * <xsd:complexType name="RevocationReqType">
// <xsd:sequence>
// <xsd:element name="EnuRevReq"
// type="EnuRevReqType"/>
// <xsd:element name="exRevReq" type="SignPolExtensionsListType"
// minOccurs="0"/>
// </xsd:sequence>
// </xsd:complexType>
//
// <xsd:simpleType name="EnuRevReqType">
// <xsd:restriction base="xsd:string">
// <xsd:enumeration value="clrcheck"/>
// <xsd:enumeration value="ocspcheck"/>
// <xsd:enumeration value="bothcheck"/>
// <xsd:enumeration value="eithercheck"/>
// <xsd:enumeration value="nocheck"/>
// <xsd:enumeration value="other"/>
// </xsd:restriction>
// </xsd:simpleType>
// */

/**
 * Este atributo indica as verificações mínimas que devem ser realizadas, de
 * acordo com a Política de Assinatura.
 */
public class RevReq {

    /**
     * Enumeração de verificações mínimas a serem realizadas
     */
    public enum EnuRevReq {
        // deve ser crl
        CLR_CHECK,
        OCSP_CHECK,
        BOTH_CHECK,
        EITHER_CHECK,
        NO_CHECK,
        OTHER
    }

    /**
     * Verificação mínima a ser feita
     */
    private EnuRevReq enuRevReq;
    /**
     * Regra adicional
     */
    private SignaturePolicyExtension exRevReq;

    /**
     * Construtor usado para decodificar um atributo de uma política ASN1.
     * @param revReq codificação ASN1 do atributo {@link RevReq}.
     */
    public RevReq(ASN1Sequence revReq) {

        String[] names = { EnuRevReq.CLR_CHECK.toString(), EnuRevReq.OCSP_CHECK.toString(), EnuRevReq.BOTH_CHECK.toString(),
            EnuRevReq.EITHER_CHECK.toString(), EnuRevReq.NO_CHECK.toString(), EnuRevReq.OTHER.toString() };

        this.enuRevReq = EnuRevReq.valueOf(names[((ASN1Enumerated) revReq.getObjectAt(0)).getValue().intValue()]);

        if (revReq.size() == 2) {
            this.exRevReq = new SignaturePolicyExtension((ASN1Sequence) revReq.getObjectAt(1));
        }
    }

    /**
     * Construtor usado para decodificar um atributo de uma política XML.
     * @param element elemento XML que representa o atributo {@link RevReq}.
     * @param index seleciona dentro do <code>element</code> qual atributo deve
     *            ser usado.
     */
    public RevReq(Element element, int index) {
        String enuRevReqType = element.getChildNodes().item(index).getTextContent();
        if (enuRevReqType.equalsIgnoreCase("clrcheck")) {
            this.enuRevReq = EnuRevReq.CLR_CHECK;
        } else if (enuRevReqType.equalsIgnoreCase("ocspcheck")) {
            this.enuRevReq = EnuRevReq.OCSP_CHECK;
        } else if (enuRevReqType.equalsIgnoreCase("bothcheck")) {
            this.enuRevReq = EnuRevReq.BOTH_CHECK;
        } else if (enuRevReqType.equalsIgnoreCase("eithercheck")) {
            this.enuRevReq = EnuRevReq.EITHER_CHECK;
        } else if (enuRevReqType.equalsIgnoreCase("nocheck")) {
            this.enuRevReq = EnuRevReq.NO_CHECK;
        } else if (enuRevReqType.equalsIgnoreCase("other")) {
            this.enuRevReq = EnuRevReq.OTHER;
        }
    }

	/**
	 * Construtor usado para parametrizar a validação de certificados.
	 * @param enuRevReq Os requistos de revogação que essa instância representa.
	 */
	public RevReq(EnuRevReq enuRevReq) {

		this.enuRevReq = enuRevReq;

	}

    /**
     * Retorna o atributo <code>EnuRevReq</code>.
     * @return O valor do atributo
     */
    public EnuRevReq getEnuRevReq() {
        return this.enuRevReq;
    }

    /**
     * Retorna o atributo <code>ExRevReq</code>.
     * @return O valor do atributo
     */
    public SignaturePolicyExtension getExRevReq() {
        return this.exRevReq;
    }

    /**
     * Verifica se o atributo opcional <code>ExRevReq</code> está presente.
     * @return Indica se o atributo não é nulo.
     */
    public boolean hasExRevReq() {
        return this.exRevReq != null;
    }

}
