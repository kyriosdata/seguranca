package br.ufsc.labsec.signature;

import br.ufsc.labsec.signature.conformanceVerifier.report.PaReport;
import br.ufsc.labsec.signature.conformanceVerifier.report.Report;
import br.ufsc.labsec.signature.conformanceVerifier.signaturePolicy.decoder.CertRevReq;
import br.ufsc.labsec.signature.conformanceVerifier.signaturePolicy.decoder.CertificateTrustPoint;
import br.ufsc.labsec.signature.conformanceVerifier.signaturePolicy.decoder.SignerRules.CertInfoReq;
import br.ufsc.labsec.signature.conformanceVerifier.signaturePolicy.decoder.SignerRules.CertRefReq;
import br.ufsc.labsec.signature.conformanceVerifier.signaturePolicy.decoder.SignerRules.ExternalSignedData;
import br.ufsc.labsec.signature.conformanceVerifier.signaturePolicy.decoder.SigningPeriod;

import javax.security.auth.x500.X500Principal;
import java.security.cert.TrustAnchor;
import java.util.List;
import java.util.Set;

public interface SignaturePolicyInterface {

    enum AdESType {
        XAdES, CAdES, PAdES
    }

    // FIXME - Esses métodos criam dependencias com classes internas ao
    // componente de assinatura
    // isso pode ser um problema futuro, mas a principio são apenas estruturas
    // simples
    String getPolicyId();

    Set<TrustAnchor> getSigningTrustAnchors();

    Set<CertificateTrustPoint> getTrustPoints();

    List<String> getMandatedSignedAttributeList();

	List<String> getMandatedUnsignedSignerAttributeList();

    List<String> getMandatedUnsignedVerifierAttributeList();

    CertRevReq getSignerRevocationReqs();

    String getSignatureAlgorithmIdentifier();

    String[] getSignatureAlgorithmIdentifierSet();

    CertificateTrustPoint getTrustPoint(X500Principal issuerX500Principal);

    int getMinKeyLength();

    int[] getMinKeyLengthSet();

    SigningPeriod getSigningPeriod();

    ExternalSignedData getExternalSignedData();

    CertRefReq getSigningCertRefReq();

    byte[] getSignPolicyHash();

    void setActualPolicy(String oid, String signaturePolicyUri, AdESType policyType);

    PaReport getReport();

    void getLpaReport(Report report, AdESType policyType);

    Set<TrustAnchor> getTimeStampTrustAnchors();
    
    Set<CertificateTrustPoint> getTimeStampTrustPoints();
    
    CertRevReq getTimeStampRevocationReqs();

    String getURL(AdESType policyType);

    String getSigURL(AdESType policyType);

    public boolean isXml();

	String getHashAlgorithmId();

	String[] getHashAlgorithmIdSet();

	List<String> getPoliciesAvaiable(AdESType type);
	
	CertInfoReq getMandatedCertificateInfo();

    default void setDefaultPolicy() { }
	
	
}
