/*

Desenvolvido pelo Laboratório de Segurança em Computação (LabSEC) do Departamento de Informática e Estatística (INE),
da Universidade Federal de Santa Catarina (UFSC).

Apoio: Colégio Notarial do Brasil (CNB) e Instituto Nacional de Tecnologia da Informação (ITI).

 */

package br.ufsc.labsec.signature.conformanceVerifier.cades.attributes;

import java.util.HashMap;
import java.util.Map;

import br.ufsc.labsec.signature.conformanceVerifier.cades.attributes.signed.IdAaEtsSigPolicyId;
import br.ufsc.labsec.signature.conformanceVerifier.cades.attributes.signed.IdAaEtsSignerLocation;
import br.ufsc.labsec.signature.conformanceVerifier.cades.attributes.signed.IdAaSigningCertificate;
import br.ufsc.labsec.signature.conformanceVerifier.cades.attributes.signed.IdAaSigningCertificateV2;
import br.ufsc.labsec.signature.conformanceVerifier.cades.attributes.signed.IdSigningTime;
import br.ufsc.labsec.signature.conformanceVerifier.cades.attributes.unsigned.IdAaEtsArchiveTimeStampV2;
import br.ufsc.labsec.signature.conformanceVerifier.cades.attributes.unsigned.IdAaEtsAttrRevocationRefs;
import br.ufsc.labsec.signature.conformanceVerifier.cades.attributes.unsigned.IdAaEtsCertValues;
import br.ufsc.labsec.signature.conformanceVerifier.cades.attributes.unsigned.IdAaEtsCertificateRefs;
import br.ufsc.labsec.signature.conformanceVerifier.cades.attributes.unsigned.IdAaEtsEscTimeStamp;
import br.ufsc.labsec.signature.conformanceVerifier.cades.attributes.unsigned.IdAaEtsRevocationRefs;
import br.ufsc.labsec.signature.conformanceVerifier.cades.attributes.unsigned.IdAaEtsRevocationValues;
import br.ufsc.labsec.signature.conformanceVerifier.cades.attributes.unsigned.IdAaSignatureTimeStampToken;
import br.ufsc.labsec.signature.conformanceVerifier.cades.attributes.unsigned.IdCounterSignature;
import br.ufsc.labsec.signature.conformanceVerifier.xades.attributes.signed.SignaturePolicyIdentifier;
import br.ufsc.labsec.signature.conformanceVerifier.xades.attributes.signed.SignatureProductionPlace;
import br.ufsc.labsec.signature.conformanceVerifier.xades.attributes.signed.SigningCertificate;
import br.ufsc.labsec.signature.conformanceVerifier.xades.attributes.signed.SigningTime;
import br.ufsc.labsec.signature.conformanceVerifier.xades.attributes.unsigned.ArchiveTimeStamp;
import br.ufsc.labsec.signature.conformanceVerifier.xades.attributes.unsigned.AttributeRevocationRefs;
import br.ufsc.labsec.signature.conformanceVerifier.xades.attributes.unsigned.CertificateValues;
import br.ufsc.labsec.signature.conformanceVerifier.xades.attributes.unsigned.CompleteCertificateRefs;
import br.ufsc.labsec.signature.conformanceVerifier.xades.attributes.unsigned.CompleteRevocationRefs;
import br.ufsc.labsec.signature.conformanceVerifier.xades.attributes.unsigned.CounterSignature;
import br.ufsc.labsec.signature.conformanceVerifier.xades.attributes.unsigned.RevocationValues;
import br.ufsc.labsec.signature.conformanceVerifier.xades.attributes.unsigned.SigAndRefsTimeStamp;
import br.ufsc.labsec.signature.conformanceVerifier.xades.attributes.unsigned.SignatureTimeStamp;

/**
 * Esta classe é usada para fazer o mapeamento de atributos entre seus
 * identificadores em assinaturas CAdES e XAdES.
 */
public class AttributeMapCadesXades {
    static {
        AttributeMapCadesXades.initialize();
    }
    /**
     * Mapeamento de atributos entre seus identificadores em assinaturas CAdES e XAdES
     */
    private static Map<String, String> attributeMap;

    /**
     * Pelo fato de essa classe só possuir métodos estáticos ela não deve ser
     * construída. <br>
     * Assim o construtor é privado para não dar a possibilidade de
     * instanciação.
     */
    private AttributeMapCadesXades() {
    }

    /**
     * Faz o mapeamento dos identificadores de cada atributo XAdES e CAdES.
     */
    public static void initialize() {
        AttributeMapCadesXades.addAttributeMapping(SigningCertificate.IDENTIFIER, IdAaSigningCertificate.IDENTIFIER);
        AttributeMapCadesXades.addAttributeMapping(SignaturePolicyIdentifier.IDENTIFIER, IdAaEtsSigPolicyId.IDENTIFIER);
        AttributeMapCadesXades.addAttributeMapping(SignatureProductionPlace.IDENTIFIER, IdAaEtsSignerLocation.IDENTIFIER);
        AttributeMapCadesXades.addAttributeMapping(CounterSignature.IDENTIFIER, IdCounterSignature.IDENTIFIER);
        AttributeMapCadesXades.addAttributeMapping(SignatureTimeStamp.IDENTIFIER, IdAaSignatureTimeStampToken.IDENTIFIER);
        AttributeMapCadesXades.addAttributeMapping(CompleteCertificateRefs.IDENTIFIER, IdAaEtsCertificateRefs.IDENTIFIER);
        AttributeMapCadesXades.addAttributeMapping(CompleteRevocationRefs.IDENTIFIER, IdAaEtsRevocationRefs.IDENTIFIER);
        AttributeMapCadesXades.addAttributeMapping(CertificateValues.IDENTIFIER, IdAaEtsCertValues.IDENTIFIER);
        AttributeMapCadesXades.addAttributeMapping(RevocationValues.IDENTIFIER, IdAaEtsRevocationValues.IDENTIFIER);
        AttributeMapCadesXades.addAttributeMapping(SigAndRefsTimeStamp.IDENTIFIER, IdAaEtsEscTimeStamp.IDENTIFIER);
        AttributeMapCadesXades.addAttributeMapping(ArchiveTimeStamp.IDENTIFIER, IdAaEtsArchiveTimeStampV2.IDENTIFIER);
        AttributeMapCadesXades.addAttributeMapping(SigningCertificate.IDENTIFIER, IdAaSigningCertificateV2.IDENTIFIER);
        AttributeMapCadesXades.addAttributeMapping(AttributeRevocationRefs.IDENTIFIER, IdAaEtsAttrRevocationRefs.IDENTIFIER);
        AttributeMapCadesXades.addAttributeMapping(SigningTime.IDENTIFIER, IdSigningTime.IDENTIFIER);
    }

    /**
     * Informa o atributo XAdES correspondente ao atributo CAdES
     * @param attributeClassXades O Identificador único do atributo XAdES. Ex.: "1.2.840.113549.1.1.5".
     * @return O identificador do atributo CAdES
     */
    static public String getAttributeClass(String attributeClassXades) {
        String retorno = null;
        if (AttributeMapCadesXades.attributeMap != null) {
            retorno = AttributeMapCadesXades.attributeMap.get(attributeClassXades);
        }
        return retorno;
    }

    /**
     * Permite adicionar um novo atributo no mapeamento de atributos.
     * @param attributeClassCades O Identificador único do atributo CAdES.
     * @param attributeClassXades O Identificador único do atributo XAdES.
     */
    static public void addAttributeMapping(String attributeClassCades, String attributeClassXades) {
        if (AttributeMapCadesXades.attributeMap == null)
            AttributeMapCadesXades.attributeMap = new HashMap<String, String>();
        AttributeMapCadesXades.attributeMap.put(attributeClassCades, attributeClassXades);
    }
}
