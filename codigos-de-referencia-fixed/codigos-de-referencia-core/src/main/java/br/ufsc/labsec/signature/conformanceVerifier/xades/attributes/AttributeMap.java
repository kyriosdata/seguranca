/*

Desenvolvido pelo Laboratório de Segurança em Computação (LabSEC) do Departamento de Informática e Estatística (INE),
da Universidade Federal de Santa Catarina (UFSC).

Apoio: Colégio Notarial do Brasil (CNB) e Instituto Nacional de Tecnologia da Informação (ITI).

 */

package br.ufsc.labsec.signature.conformanceVerifier.xades.attributes;

import java.util.HashMap;
import java.util.Map;

import br.ufsc.labsec.signature.conformanceVerifier.xades.attributes.signed.AllDataObjectTimeStamp;
import br.ufsc.labsec.signature.conformanceVerifier.xades.attributes.signed.CommitmentTypeIndication;
import br.ufsc.labsec.signature.conformanceVerifier.xades.attributes.signed.DataObjectFormat;
import br.ufsc.labsec.signature.conformanceVerifier.xades.attributes.signed.IndividualDataObjectsTimeStamp;
import br.ufsc.labsec.signature.conformanceVerifier.xades.attributes.signed.SignaturePolicyIdentifier;
import br.ufsc.labsec.signature.conformanceVerifier.xades.attributes.signed.SignatureProductionPlace;
import br.ufsc.labsec.signature.conformanceVerifier.xades.attributes.signed.SignerRole;
import br.ufsc.labsec.signature.conformanceVerifier.xades.attributes.signed.SigningCertificate;
import br.ufsc.labsec.signature.conformanceVerifier.xades.attributes.signed.SigningTime;
import br.ufsc.labsec.signature.conformanceVerifier.xades.attributes.unsigned.ArchiveTimeStamp;
import br.ufsc.labsec.signature.conformanceVerifier.xades.attributes.unsigned.AttrAuthoritiesCertValues;
import br.ufsc.labsec.signature.conformanceVerifier.xades.attributes.unsigned.AttributeCertificateRefs;
import br.ufsc.labsec.signature.conformanceVerifier.xades.attributes.unsigned.AttributeRevocationRefs;
import br.ufsc.labsec.signature.conformanceVerifier.xades.attributes.unsigned.AttributeRevocationValues;
import br.ufsc.labsec.signature.conformanceVerifier.xades.attributes.unsigned.CertificateValues;
import br.ufsc.labsec.signature.conformanceVerifier.xades.attributes.unsigned.CompleteCertificateRefs;
import br.ufsc.labsec.signature.conformanceVerifier.xades.attributes.unsigned.CompleteRevocationRefs;
import br.ufsc.labsec.signature.conformanceVerifier.xades.attributes.unsigned.CounterSignature;
import br.ufsc.labsec.signature.conformanceVerifier.xades.attributes.unsigned.RefsOnlyTimeStamp;
import br.ufsc.labsec.signature.conformanceVerifier.xades.attributes.unsigned.RevocationValues;
import br.ufsc.labsec.signature.conformanceVerifier.xades.attributes.unsigned.SigAndRefsTimeStamp;
import br.ufsc.labsec.signature.conformanceVerifier.xades.attributes.unsigned.SignatureTimeStamp;
import br.ufsc.labsec.signature.conformanceVerifier.xades.attributes.unsigned.UnsignedDataObjectProperty;

/**
 * Esta classe é usada para fazer o mapeamento de atributos entre seus
 * identificadores e suas respectivas classes.
 */
public class AttributeMap {

    static {
        AttributeMap.initialize();
    }
    /**
     * Mapeamento de atributos entre seus identificadores e suas respectivas
     * classes.
     */
    static private Map<String, Class<?>> attributeMap;

    /**
     * Pelo fato de essa classe só possuir métodos estáticos ela não deve ser
     * construída. <br>
     * Assim o construtor é privado para não dar a possibilidade de
     * instanciação.
     */
    private AttributeMap() {
    }

    /**
     * Faz o mapeamento dos identificadores de cada atributo com a sua
     * respectiva classe.
     */
    static public void initialize() {
        AttributeMap.addAttributeMapping("SigningCertificate", SigningCertificate.class);
        AttributeMap.addAttributeMapping("SignaturePolicyIdentifier", SignaturePolicyIdentifier.class);
        AttributeMap.addAttributeMapping("DataObjectFormat", DataObjectFormat.class);
        AttributeMap.addAttributeMapping("SigningTime", SigningTime.class);
        AttributeMap.addAttributeMapping("SignerRole", SignerRole.class);
        AttributeMap.addAttributeMapping("SignatureProductionPlace", SignatureProductionPlace.class);
        AttributeMap.addAttributeMapping("CommitmentTypeIndication", CommitmentTypeIndication.class);
        AttributeMap.addAttributeMapping("AllDataObjectTimeStamp", AllDataObjectTimeStamp.class);
        AttributeMap.addAttributeMapping("IndividualDataObjectsTimeStamp", IndividualDataObjectsTimeStamp.class);
        AttributeMap.addAttributeMapping("SignatureTimeStamp", SignatureTimeStamp.class);
        AttributeMap.addAttributeMapping("CounterSignature", CounterSignature.class);
        AttributeMap.addAttributeMapping("CompleteCertificateRefs", CompleteCertificateRefs.class);
        AttributeMap.addAttributeMapping("CompleteRevocationRefs", CompleteRevocationRefs.class);
        AttributeMap.addAttributeMapping("AttributeCertificateRefs", AttributeCertificateRefs.class);
        AttributeMap.addAttributeMapping("AttributeRevocationRefs", AttributeRevocationRefs.class);
        AttributeMap.addAttributeMapping("SigAndRefsTimeStamp", SigAndRefsTimeStamp.class);
        AttributeMap.addAttributeMapping("RefsOnlyTimeStamp", RefsOnlyTimeStamp.class);
        AttributeMap.addAttributeMapping("CertificateValues", CertificateValues.class);
        AttributeMap.addAttributeMapping("RevocationValues", RevocationValues.class);
        AttributeMap.addAttributeMapping("AttrAuthoritiesCertValues", AttrAuthoritiesCertValues.class);
        AttributeMap.addAttributeMapping("AttributeRevocationValues", AttributeRevocationValues.class);
        AttributeMap.addAttributeMapping("ArchiveTimeStamp", ArchiveTimeStamp.class);
        AttributeMap.addAttributeMapping("UnsignedDataObjectProperty", UnsignedDataObjectProperty.class);
    }

    /**
     * Informa a classe do atributo pelo seu identificador único.
     * @param attributeIdentifier Identificador único do atributo. Ex.:
     *            "1.2.840.113549.1.1.5".
     * @return A classe do atributo
     */
    static public Class<?> getAttributeClass(String attributeIdentifier) {
        Class<?> retorno = null;
        if (AttributeMap.attributeMap != null) {
            retorno = AttributeMap.attributeMap.get(attributeIdentifier);
        }
        return retorno;
    }

    /**
     * Permite adicionar um novo atributo no mapeamento de atributos.
     * @param attributeIdentifier Identificador único do attributo. Ex.:
     *            "1.2.840.113549.1.1.5".
     * @param attributeClass Classe do atributo correspondente ao
     *            identificador único informado.
     */
    static public void addAttributeMapping(String attributeIdentifier, Class<?> attributeClass) {
        if (AttributeMap.attributeMap == null)
            AttributeMap.attributeMap = new HashMap<String, Class<?>>();
        AttributeMap.attributeMap.put(attributeIdentifier, attributeClass);
    }
}
