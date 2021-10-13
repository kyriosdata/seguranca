package br.ufsc.labsec.signature.conformanceVerifier;

import br.ufsc.labsec.component.AbstractComponentConfiguration;
import br.ufsc.labsec.signature.*;
import br.ufsc.labsec.signature.conformanceVerifier.cades.CadesSignatureComponent;
import br.ufsc.labsec.signature.conformanceVerifier.cms.CmsSignatureComponent;
import br.ufsc.labsec.signature.conformanceVerifier.gui.ReportGuiComponent;
import br.ufsc.labsec.signature.conformanceVerifier.pades.PadesSignatureComponent;
import br.ufsc.labsec.signature.conformanceVerifier.signaturePolicy.SignaturePolicyComponent;
import br.ufsc.labsec.signature.conformanceVerifier.validationService.TrustAnchorInterface;
import br.ufsc.labsec.signature.conformanceVerifier.validationService.TrustAnchorComponent;
import br.ufsc.labsec.signature.conformanceVerifier.validationService.ValidationServiceRepository;
import br.ufsc.labsec.signature.conformanceVerifier.xades.XadesSignatureComponent;
import br.ufsc.labsec.signature.conformanceVerifier.xml.XmlSignatureComponent;
import br.ufsc.labsec.signature.repository.PKCS12IdentityService.PKCS12Repository;
import br.ufsc.labsec.signature.tsa.TimeStampVerifierInterface;

import java.security.Security;

/**
 * Classe de inicialização do Verificador de Conformidade
 */
public class ConformanceVerifier extends AbstractComponentConfiguration {

	/**
	 * Construtor, onde os componentes são conectados
	 */
	public ConformanceVerifier() {
		super();
//		Propriedade para habilitar o uso da curva brainpoolP512r1, desabilitada pelo JDK por default
// 		Mais informações https://bugs.openjdk.java.net/browse/JDK-8238911

		System.setProperty("jdk.sunec.disableNative", "false");
		Security.setProperty("jdk.disabled.namedCurves", "secp112r1, secp112r2, secp128r1, secp128r2, secp160k1, secp160r1, secp160r2, secp192k1, secp192r1, secp224k1, secp224r1, secp256k1, sect113r1, sect113r2, sect131r1, sect131r2, sect163k1, sect163r1, sect163r2, sect193r1, sect193r2, sect233k1, sect233r1, sect239k1, sect283k1, sect283r1, sect409k1, sect409r1, sect571k1, sect571r1, X9.62 c2tnb191v1, X9.62 c2tnb191v2, X9.62 c2tnb191v3, X9.62 c2tnb239v1, X9.62 c2tnb239v2, X9.62 c2tnb239v3, X9.62 c2tnb359v1, X9.62 c2tnb431r1, X9.62 prime192v2, X9.62 prime192v3, X9.62 prime239v1, X9.62 prime239v2, X9.62 prime239v3, brainpoolP256r1, brainpoolP320r1, brainpoolP384r1");

		//--Cades Signature Component
		component(CadesSignatureComponent.class).connect(PKCS12Repository.class)
				.on(CertificateCollection.class)
				.on(RevocationInformation.class);

		component(CadesSignatureComponent.class).connect(SignaturePolicyComponent.class)
				.on(SignaturePolicyInterface.class);

		component(CadesSignatureComponent.class).connect(ValidationServiceRepository.class)
				.on(CertificateValidation.class);

		component(CadesSignatureComponent.class).connect(CadesSignatureComponent.class)
				.on(CertificateCollection.class)
				.on(RevocationInformation.class);

		component(CadesSignatureComponent.class)
				.param("reportStylePathHTML", "resources/report.xsl")
				.param("reportStylePathPDF", "resources/reportPdf.xsl");

		//--Xades Signature Component
		component(XadesSignatureComponent.class).connect(PKCS12Repository.class)
				.on(CertificateCollection.class)
				.on(RevocationInformation.class);

		component(XadesSignatureComponent.class).connect(SignaturePolicyComponent.class)
				.on(SignaturePolicyInterface.class);

		component(XadesSignatureComponent.class).connect(CadesSignatureComponent.class)
				.on(TimeStampVerifierInterface.class)
				.on(CertificateCollection.class)
				.on(RevocationInformation.class);

		component(XadesSignatureComponent.class).connect(ValidationServiceRepository.class)
				.on(CertificateValidation.class);

		component(XadesSignatureComponent.class).connect(XadesSignatureComponent.class)
				.on(CertificateCollection.class)
				.on(RevocationInformation.class);

		component(XadesSignatureComponent.class)
				.param("xadesSchema", "resources/XAdESv141.xsd")
				.param("reportStylePathHTML", "resources/report.xsl")
				.param("reportStylePathPDF", "resources/reportPdf.xsl")
				.param("xmlDsigSchema", "resources/xmldsig.xsd");

		//--Validation Service Repository
		component(ValidationServiceRepository.class).connect(PKCS12Repository.class)
				.on(CertificateCollection.class)
				.on(RevocationInformation.class);

		component(ValidationServiceRepository.class).connect(CadesSignatureComponent.class)
				.on(CertificateCollection.class)
				.on(RevocationInformation.class);

		component(ValidationServiceRepository.class).connect(XadesSignatureComponent.class)
				.on(CertificateCollection.class)
				.on(RevocationInformation.class);

		component(ValidationServiceRepository.class).connect(CmsSignatureComponent.class)
				.on(CertificateCollection.class)
				.on(RevocationInformation.class);

		component(ValidationServiceRepository.class).connect(XmlSignatureComponent.class)
				.on(CertificateCollection.class)
				.on(RevocationInformation.class);

		//--PKCS12 Repository
		component(PKCS12Repository.class).connect(CadesSignatureComponent.class)
				.on(CertificateCollection.class)
				.on(RevocationInformation.class);

		component(PKCS12Repository.class).connect(XadesSignatureComponent.class)
				.on(CertificateCollection.class)
				.on(RevocationInformation.class);

		component(PKCS12Repository.class)
				.param("cachePath", "/tmp/verificador-de-conformidade/Cache")
				.param("repositoryPath", "/tmp/verificador-de-conformidade/Repository");

		//--Report Gui Component
		component(ReportGuiComponent.class).connect(CadesSignatureComponent.class)
				.on(Verifier.class);

		component(ReportGuiComponent.class).connect(XadesSignatureComponent.class)
				.on(Verifier.class);

		component(ReportGuiComponent.class).connect(PKCS12Repository.class)
				.on(IdentitySelector.class);

		component(ReportGuiComponent.class).connect(CmsSignatureComponent.class)
				.on(Verifier.class);

		component(ReportGuiComponent.class).connect(XmlSignatureComponent.class)
				.on(Verifier.class);

		component(ReportGuiComponent.class).connect(PadesSignatureComponent.class)
				.on(Verifier.class);

		//--CMS Signature Component
		component(CmsSignatureComponent.class).connect(ValidationServiceRepository.class)
				.on(CertificateValidation.class);

		component(CmsSignatureComponent.class).connect(PKCS12Repository.class)
				.on(CertificateCollection.class)
				.on(RevocationInformation.class);

		component(CmsSignatureComponent.class).connect(CmsSignatureComponent.class)
				.on(CertificateCollection.class)
				.on(RevocationInformation.class);

		component(CmsSignatureComponent.class)
				.param("reportStylePathHTML", "resources/report.xsl")
				.param("reportStylePathPDF", "resources/reportPdf.xsl");

		component(CmsSignatureComponent.class).connect(TrustAnchorComponent.class)
				.on(TrustAnchorInterface.class);

		//--XML Signature Component
		component(XmlSignatureComponent.class).connect(ValidationServiceRepository.class)
				.on(CertificateValidation.class);

		component(XmlSignatureComponent.class).connect(PKCS12Repository.class)
				.on(CertificateCollection.class)
				.on(RevocationInformation.class);

		component(XmlSignatureComponent.class).connect(XmlSignatureComponent.class)
				.on(CertificateCollection.class)
				.on(RevocationInformation.class);

		component(XmlSignatureComponent.class)
				.param("reportStylePathHTML", "resources/report.xsl")
				.param("reportStylePathPDF", "resources/reportPdf.xsl");

		component(XmlSignatureComponent.class).connect(TrustAnchorComponent.class)
				.on(TrustAnchorInterface.class);

		//--PAdES Signature Component
		component(PadesSignatureComponent.class).connect(SignaturePolicyComponent.class)
				.on(SignaturePolicyInterface.class);

		component(PadesSignatureComponent.class).connect(ValidationServiceRepository.class)
				.on(CertificateValidation.class);


		component(PadesSignatureComponent.class).connect(CadesSignatureComponent.class)
				.on(Verifier.class)
				.on(Signer.class);

		component(PadesSignatureComponent.class)
				.param("reportStylePathHTML", "resources/report.xsl")
				.param("reportStylePathPDF", "resources/reportPdf.xsl");


		// Signature Policies
		component(SignaturePolicyComponent.class)
				.param("lpaUrlAsn1CAdES", "http://politicas.icpbrasil.gov.br/LPA_CAdES.der")
				.param("lpaUrlAsn1SignatureCAdES", "http://politicas.icpbrasil.gov.br/LPA_CAdES.p7s")
				.param("lpaUrlAsn1PAdES", "http://politicas.icpbrasil.gov.br/LPA_PAdES.der")
				.param("lpaUrlAsn1SignaturePAdES", "http://politicas.icpbrasil.gov.br/LPA_PAdES.p7s")
				.param("lpaUrlXml", "http://politicas.icpbrasil.gov.br/LPA_XAdES.xml")
				.param("lpaUrlXmlSignature", "http://politicas.icpbrasil.gov.br/LPA_XAdES.xml");

		component(SignaturePolicyComponent.class).connect(TrustAnchorComponent.class)
				.on(TrustAnchorInterface.class);
	}

	/**
	 * Método de inicialização do Verificador
	 * @param args Parâmetros para a inicialização
	 */
	public static void main(String[] args) {
		new ConformanceVerifier().run(args);
	}

}
