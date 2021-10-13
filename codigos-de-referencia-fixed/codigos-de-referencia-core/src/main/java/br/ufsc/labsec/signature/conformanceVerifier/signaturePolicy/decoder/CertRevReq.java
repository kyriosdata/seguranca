/*

Desenvolvido pelo Laboratório de Segurança em Computação (LabSEC) do Departamento de Informática e Estatística (INE),
da Universidade Federal de Santa Catarina (UFSC).

Apoio: Colégio Notarial do Brasil (CNB) e Instituto Nacional de Tecnologia da Informação (ITI).

 */

package br.ufsc.labsec.signature.conformanceVerifier.signaturePolicy.decoder;

import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.ASN1TaggedObject;
import org.w3c.dom.Element;

import br.ufsc.labsec.signature.conformanceVerifier.signaturePolicy.decoder.RevReq.EnuRevReq;

///**
// * CertRevReq ::= SEQUENCE {
// endCertRevReq   RevReq,
// caCerts         [0] RevReq
// }
// */
//
///**
// * <xsd:complexType name="CertificateRevReqType">
// <xsd:sequence>
// <xsd:element name="EndRevReq" type="RevocationReqType"/>
// <xsd:element name="CACerts" type="RevocationReqType"/>
// </xsd:sequence>
// */

/**
 * Esta classe representa um atributo que especifica o mínimo de requerimentos para informações de
 * revocação, obtida através e/ou OCSPs, para ser usada na verificação da
 * revogação de certificados.
 */
public class CertRevReq {

    /**
     * Certificados finais da cadeia
     */
    private RevReq endCertRevReq;
    /**
     * Certificados de Autoridade Certificadoras
     */
    private RevReq caCerts;

    /**
     * Construtor usado para decodificar um atributo de uma política ASN1.
     * @param certRevReq codificação ASN1 do atributo {@link CertRevReq}.
     */
    public CertRevReq(ASN1Sequence certRevReq) {

        this.endCertRevReq = new RevReq((ASN1Sequence) certRevReq.getObjectAt(0));
        this.caCerts = null;

        ASN1TaggedObject taggetObj = (ASN1TaggedObject) certRevReq.getObjectAt(1);
        if (taggetObj.getTagNo() == 0) {
            this.caCerts = new RevReq((ASN1Sequence) taggetObj.getObject());
        }
    }

    /**
     * Construtor usado para parametrizar a validação de certificados.
     * @param endCertRevReq requisitos de revogação do certificado final.
     * @param caCerts requisitos de revogação dos certificados intermediários.
     */
	public CertRevReq(EnuRevReq endCertRevReq, EnuRevReq caCerts) {

		this.endCertRevReq = new RevReq(endCertRevReq);
		this.caCerts = new RevReq(caCerts);

	}

    /**
     * Construtor usado para decodificar um atributo de uma política XML.
     * @param element elemento XML que representa o atributo {@link CertRevReq}.
     */
    public CertRevReq(Element element) {
        // pega o atributo endCertRevReq
        this.endCertRevReq = new RevReq(element, 0);
        // pega o atributo caCerts
        this.caCerts = new RevReq(element, 1);
    }

    /**
     * Retorna o atributo <code>EndCertRevReq</code>, que representa os
     * certificados finais. Este atributo pode ser o certificado do assinante, o
     * certificado de atributo, ou o certificado de autoridade de carimbo do
     * tempo.
     * @return O atributo
     */
    public RevReq getEndCertRevReq() {
        return endCertRevReq;
    }

    /**
     * Retorna o atributo <code>CaCerts</code>, que representa os certificados
     * das Autoridades Certificadoras.
     * @return O atributo
     */
    public RevReq getCaCerts() {
        return caCerts;
    }
}
