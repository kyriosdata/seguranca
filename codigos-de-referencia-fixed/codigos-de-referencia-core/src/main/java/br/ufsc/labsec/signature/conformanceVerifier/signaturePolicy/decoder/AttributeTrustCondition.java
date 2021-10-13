/*

Desenvolvido pelo Laboratório de Segurança em Computação (LabSEC) do Departamento de Informática e Estatística (INE),
da Universidade Federal de Santa Catarina (UFSC).

Apoio: Colégio Notarial do Brasil (CNB) e Instituto Nacional de Tecnologia da Informação (ITI).

 */

package br.ufsc.labsec.signature.conformanceVerifier.signaturePolicy.decoder;

import java.io.IOException;
import java.security.NoSuchAlgorithmException;
import java.security.cert.CertificateException;

import org.bouncycastle.asn1.ASN1Boolean;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.ASN1TaggedObject;
import org.w3c.dom.Element;

///**
// * HowCertAttribute ::= ENUMERATED {
// claimedAttribute    (0),
// certifiedAttribtes (1),
// either              (2) }
// */
//
///**
// * AttributeTrustCondition ::= SEQUENCE {
// attributeMandated            BOOLEAN,              -- Attribute shall be present
// howCertAttribute             HowCertAttribute,
// attrCertificateTrustTrees   [0] CertificateTrustTrees   OPTIONAL,
// attrRevReq                  [1] CertRevReq             OPTIONAL,
// attributeConstraints        [2] AttributeConstraints   OPTIONAL }
// */

/**
 * Este atributo especifica as condições de confiança do atributo.
 */
public class AttributeTrustCondition {

    /**
     * Enumeração de condições de confiança do atributo
     */
    public enum HowCertAttribute {
        CLAIMED_ATTRIBUTE, CERTIFIED_ATTRIBUTES, EITHER
    }

    /**
     * Indica se o atributo é obrigatório
     */
    private ASN1Boolean attributeMandated;
    /**
     * Condição do atributo
     */
    private HowCertAttribute howCertAttribute;
    /**
     * Array de pontos de segurança
     */
    private CertificateTrustPoint[] attrCertificateTrustTrees;
    /**
     * Informações de revogação
     */
    private CertRevReq attrRevReq;
    /**
     * Restrições do atributo
     */
    private AttributeConstraints attributeConstraints;

    /**
     * Construtor usado para decodificar um atributo de uma política ASN1.
     * @param attributeTrustCondition codificação ASN1 do atributo
     *            {@link AttributeTrustCondition}.
	 * @throws CertificateException Exceção em caso de erro na codificação do certificado
	 * @throws IOException Exceção em caso de erro nos bytes do atributo
	 * @throws NoSuchAlgorithmException Exceção em caso de algoritmo de hash inválido
     */
    public AttributeTrustCondition(ASN1Sequence attributeTrustCondition) throws CertificateException, IOException, NoSuchAlgorithmException {

        this.attributeMandated = (ASN1Boolean) attributeTrustCondition.getObjectAt(0);
        this.attrCertificateTrustTrees = null;
        this.attrRevReq = null;
        this.attributeConstraints = null;

        for (HowCertAttribute certAttr : HowCertAttribute.values()) {

            if (certAttr.toString().equals(attributeTrustCondition.getObjectAt(1).toString())) {
                this.howCertAttribute = certAttr;
            }
        }

        for (int i = 2; i < attributeTrustCondition.size(); i++) {
            ASN1TaggedObject taggetObj = (ASN1TaggedObject) attributeTrustCondition.getObjectAt(i);
            switch (taggetObj.getTagNo()) {
                case 0:
                    this.attrCertificateTrustTrees = this.readTrustTrees((ASN1Sequence) taggetObj.getObject());
                    break;

                case 1:
                    this.attrRevReq = new CertRevReq((ASN1Sequence) taggetObj.getObject());
                    break;

                case 2:
                    this.attributeConstraints = new AttributeConstraints((ASN1Sequence) taggetObj.getObject());
                    break;
            }
        }
    }

    /**
     * Construtor usado para decodificar um atributo de uma política XML.
     * @param element elemento XML que representa o atributo
     *            {@link AttributeTrustCondition}.
     */
    public AttributeTrustCondition(Element element) {
        // TODO Auto-generated constructor stub
    }

    /**
     * Cria o array de pontos de segurança através da sequência ASN.1 dada
     * @param trustTrees A sequência ASN.1
     * @return O array gerado
	 * @throws CertificateException Exceção em caso de erro na codificação do certificado
	 * @throws IOException Exceção em caso de erro nos bytes do atributo
	 * @throws NoSuchAlgorithmException Exceção em caso de algoritmo de hash inválido
     */
    private CertificateTrustPoint[] readTrustTrees(ASN1Sequence trustTrees) throws CertificateException, IOException,
        NoSuchAlgorithmException {

        CertificateTrustPoint[] certificateTrustTrees = null;

        if (trustTrees.size() > 0) {
            certificateTrustTrees = new CertificateTrustPoint[trustTrees.size()];
            for (int i = 0; i < certificateTrustTrees.length; i++) {

                certificateTrustTrees[i] = new CertificateTrustPoint((ASN1Sequence) trustTrees.getObjectAt(i));
            }
        }
        return certificateTrustTrees;
    }

    /**
     * Retorna se o atributo é obrigatório
     * @return Indica se o atributo é obrigatório
     */
    public ASN1Boolean isAttributeMandated() {
        return attributeMandated;
    }

    /**
     * Retorna o atributo <code>HowCertAttribute</code>.
     * @return O valor do atributo
     */
    public HowCertAttribute getHowCertAttribute() {
        return howCertAttribute;
    }

    /**
     * Retorna o atributo <code>AttrCertificateTrustTrees</code>.
     * @return Um array de {@link CertificateTrustPoint}.
     */
    public CertificateTrustPoint[] getAttrCertificateTrustTrees() {
        return attrCertificateTrustTrees;
    }

    /**
     * Retorna o atributo <code>AttrRevReq</code>.
     * @return O valor do atributo
     */
    public CertRevReq getAttrRevReq() {
        return attrRevReq;
    }

    /**
     * Retorna o atributo <code>AttributeConstraints</code>.
     * @return O valor do atributo
     */
    public AttributeConstraints getAttributeConstraints() {
        return attributeConstraints;
    }

    /**
     * Verifica de existe o atributo <code>CertificateTrustTrees</code>.
     * @return Indica se o atributo não é nulo.
     */
    public boolean hasCertificateTrustTrees() {
        return this.attrCertificateTrustTrees != null;
    }

    /**
     * Verifica se existe o atributo AttrRevReq.
     * @return Indica se o atributo não é nulo.
     */
    public boolean hasAttrRevReq() {
        return this.attrRevReq != null;
    }

    /**
     * Verifica se existe o atributo AttributeConstraints.
     * @return Indica se o atributo não é nulo.
     */
    public boolean hasAttributeConstraints() {
        return this.attributeConstraints != null;
    }
}
