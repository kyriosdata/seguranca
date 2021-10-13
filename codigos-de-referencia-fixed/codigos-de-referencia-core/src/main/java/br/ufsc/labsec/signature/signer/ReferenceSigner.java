package br.ufsc.labsec.signature.signer;

import br.ufsc.labsec.component.AbstractComponentConfiguration;
import br.ufsc.labsec.signature.CertificateCollection;
import br.ufsc.labsec.signature.CertificateValidation;
import br.ufsc.labsec.signature.PrivateInformation;
import br.ufsc.labsec.signature.RevocationInformation;
import br.ufsc.labsec.signature.SignaturePolicyInterface;
import br.ufsc.labsec.signature.tsa.TimeStamp;
import br.ufsc.labsec.signature.tsa.TimeStampAttributeIncluder;
import br.ufsc.labsec.signature.tsa.TimeStampVerifierInterface;
import br.ufsc.labsec.signature.*;
import br.ufsc.labsec.signature.conformanceVerifier.cades.CadesSignatureComponent;
import br.ufsc.labsec.signature.conformanceVerifier.cms.CmsSignatureComponent;
import br.ufsc.labsec.signature.conformanceVerifier.pades.PadesSignatureComponent;
import br.ufsc.labsec.signature.conformanceVerifier.pdf.PdfSignatureComponent;
import br.ufsc.labsec.signature.conformanceVerifier.signaturePolicy.SignaturePolicyComponent;
import br.ufsc.labsec.signature.conformanceVerifier.validationService.TrustAnchorComponent;
import br.ufsc.labsec.signature.conformanceVerifier.validationService.TrustAnchorInterface;
import br.ufsc.labsec.signature.conformanceVerifier.validationService.ValidationServiceRepository;
import br.ufsc.labsec.signature.conformanceVerifier.xades.XadesSignatureComponent;
import br.ufsc.labsec.signature.conformanceVerifier.xml.XmlSignatureComponent;
import br.ufsc.labsec.signature.repository.PKCS12IdentityService.PKCS12Repository;
import br.ufsc.labsec.signature.signer.PolicyStorage.StamperComponent;
import br.ufsc.labsec.signature.signer.suite.SingletonSuiteMapper;
import br.ufsc.labsec.signature.tsa.TimeStampComponent;
import org.bouncycastle.cms.CMSSignedDataGenerator;
import org.bouncycastle.cms.CMSSignedGenerator;

import java.security.Security;

/**
 * Esta classe engloba métodos do assinador de referência
 */
public class ReferenceSigner extends AbstractComponentConfiguration {

	public ReferenceSigner() {

		super();
//		Propriedade para habilitar o uso da curva brainpoolP512r1, desabilitada pelo JDK por default
// 		Mais informações https://bugs.openjdk.java.net/browse/JDK-8238911

		System.setProperty("jdk.sunec.disableNative", "false");
		Security.setProperty("jdk.disabled.namedCurves", "secp112r1, secp112r2, secp128r1, secp128r2, secp160k1, secp160r1, secp160r2, secp192k1, secp192r1, secp224k1, secp224r1, secp256k1, sect113r1, sect113r2, sect131r1, sect131r2, sect163k1, sect163r1, sect163r2, sect193r1, sect193r2, sect233k1, sect233r1, sect239k1, sect283k1, sect283r1, sect409k1, sect409r1, sect571k1, sect571r1, X9.62 c2tnb191v1, X9.62 c2tnb191v2, X9.62 c2tnb191v3, X9.62 c2tnb239v1, X9.62 c2tnb239v2, X9.62 c2tnb239v3, X9.62 c2tnb359v1, X9.62 c2tnb431r1, X9.62 prime192v2, X9.62 prime192v3, X9.62 prime239v1, X9.62 prime239v2, X9.62 prime239v3, brainpoolP256r1, brainpoolP320r1, brainpoolP384r1");

		// -------- CADES --------

		component(CadesSignatureComponent.class)
				.connect(PKCS12Repository.class)
				.on(CertificateCollection.class)
				.on(RevocationInformation.class)
				.on(PrivateInformation.class);

		component(CadesSignatureComponent.class)
			.param("reportStylePathHTML", "resources/report.xsl")
			.param("reportStylePathPDF", "resources/reportPdf.xsl")
			.param("city", "")
			.param("stateOrProvince", "")
			.param("postalCode", "")
			.param("countryName", "")
			.param("algorithmOid", CMSSignedGenerator.DIGEST_SHA256);

		component(CadesSignatureComponent.class).connect(
				SignaturePolicyComponent.class).on(
				SignaturePolicyInterface.class);

		component(CadesSignatureComponent.class).connect(
				ValidationServiceRepository.class).on(
				CertificateValidation.class);

		component(CadesSignatureComponent.class)
				.connect(TimeStampComponent.class).on(TimeStamp.class);

		// -------- XADES --------

		component(XadesSignatureComponent.class)
				.connect(PKCS12Repository.class)
				.on(CertificateCollection.class)
				.on(RevocationInformation.class)
				.on(PrivateInformation.class);

		component(XadesSignatureComponent.class)
			.param("xadesSchema","resources/XAdESv141.xsd")
			.param("xmlDsigSchema", "resources/xmldsig.xsd")
			.param("reportStylePathHTML", "resources/report.xsl")
			.param("reportStylePathPDF", "resources/reportPdf.xsl")
			.param("city", "")
			.param("stateOrProvince", "")
			.param("postalCode", "")
			.param("countryName", "")
			.param("algorithmOid",
					SingletonSuiteMapper.getInstance().signatureAlgorithms.get(SingletonSuiteMapper.SHA256));

		component(XadesSignatureComponent.class).connect(
				SignaturePolicyComponent.class).on(
				SignaturePolicyInterface.class);

		component(XadesSignatureComponent.class)
				.connect(CadesSignatureComponent.class)
				.on(TimeStampVerifierInterface.class)
				.on(TimeStampAttributeIncluder.class);

		component(XadesSignatureComponent.class).connect(
				ValidationServiceRepository.class).on(
				CertificateValidation.class);

		// -------- PADES --------

		component(PadesSignatureComponent.class).connect(SignaturePolicyComponent.class)
				.on(SignaturePolicyInterface.class);

		component(PadesSignatureComponent.class).connect(ValidationServiceRepository.class)
				.on(CertificateValidation.class);

		component(PadesSignatureComponent.class).connect(CadesSignatureComponent.class)
				.on(Verifier.class)
				.on(Signer.class);

		// -------- CMS --------

		component(CmsSignatureComponent.class).connect(ValidationServiceRepository.class)
				.on(CertificateValidation.class);

		component(CmsSignatureComponent.class).connect(PKCS12Repository.class)
				.on(CertificateCollection.class)
				.on(RevocationInformation.class)
				.on(PrivateInformation.class);

		component(CmsSignatureComponent.class).connect(CmsSignatureComponent.class)
				.on(CertificateCollection.class)
				.on(RevocationInformation.class);

		component(CmsSignatureComponent.class).connect(TrustAnchorComponent.class)
				.on(TrustAnchorInterface.class);

		// -------- XML --------

		component(XmlSignatureComponent.class).connect(ValidationServiceRepository.class)
				.on(CertificateValidation.class);

		component(XmlSignatureComponent.class).connect(PKCS12Repository.class)
				.on(CertificateCollection.class)
				.on(RevocationInformation.class);

		component(XmlSignatureComponent.class).connect(XmlSignatureComponent.class)
				.on(CertificateCollection.class)
				.on(RevocationInformation.class);

		component(XmlSignatureComponent.class).connect(TrustAnchorComponent.class)
				.on(TrustAnchorInterface.class);

		// -- PKCS12Repository
		component(PKCS12Repository.class).param("cachePath", "/tmp/verificador-de-conformidade/Cache")
				.param("repositoryPath", "/tmp/verificador-de-conformidade/Repository")
				.connect(CadesSignatureComponent.class)
				.on(CertificateCollection.class)
				.on(RevocationInformation.class);

		//--Validation Service Repository

		component(ValidationServiceRepository.class)
				.connect(PKCS12Repository.class)
				.on(CertificateCollection.class)
				.on(RevocationInformation.class);

		component(ValidationServiceRepository.class)
			.connect(PKCS12Repository.class)
				.on(CertificateCollection.class)
				.on(RevocationInformation.class);

		component(ValidationServiceRepository.class)
			.connect(CadesSignatureComponent.class)
				.on(CertificateCollection.class)
				.on(RevocationInformation.class);

		component(ValidationServiceRepository.class)
			.connect(XadesSignatureComponent.class)
				.on(CertificateCollection.class)
				.on(RevocationInformation.class);


		// -- TimeStampComponent

		component(TimeStampComponent.class)
				.param("algorithmOid", CMSSignedDataGenerator.DIGEST_SHA256);

		component(XadesSignatureComponent.class)
			.connect(TimeStampComponent.class)
				.on(TimeStamp.class);

		component(CadesSignatureComponent.class)
			.connect(TimeStampComponent.class)
				.on(TimeStamp.class);

		component(SignaturePolicyComponent.class).connect(TrustAnchorComponent.class)
				.on(TrustAnchorInterface.class);

		component(SignaturePolicyComponent.class)
			.param("lpaUrlAsn1CAdES", "http://politicas.icpbrasil.gov.br/LPA_CAdES.der")
			.param("lpaUrlAsn1SignatureCAdES", "http://politicas.icpbrasil.gov.br/LPA_CAdES.p7s")
			.param("lpaUrlAsn1PAdES", "http://politicas.icpbrasil.gov.br/LPA_PAdES.der")
			.param("lpaUrlAsn1SignaturePAdES", "http://politicas.icpbrasil.gov.br/LPA_PAdES.p7s")
			.param("lpaUrlXml", "http://politicas.icpbrasil.gov.br/LPA_XAdES.xml")
			.param("lpaUrlXmlSignature", "http://politicas.icpbrasil.gov.br/LPA_XAdES.xml");

		//StamperComponent
		component(StamperComponent.class).connect(CadesSignatureComponent.class)
				.on(Signer.class);

		component(StamperComponent.class).connect(XadesSignatureComponent.class)
				.on(Signer.class);

		component(StamperComponent.class).connect(CmsSignatureComponent.class)
				.on(Signer.class);

		component(StamperComponent.class).connect(XmlSignatureComponent.class)
				.on(Signer.class);

		component(StamperComponent.class).connect(PdfSignatureComponent.class)
				.on(Signer.class);

		component(StamperComponent.class).connect(PadesSignatureComponent.class)
				.on(Signer.class);
	}

	public static void main(String[] args) {
		new ReferenceSigner().run(args);
	}

}
