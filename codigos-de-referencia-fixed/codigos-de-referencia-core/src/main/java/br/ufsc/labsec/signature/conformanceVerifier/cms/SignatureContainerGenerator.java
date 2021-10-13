package br.ufsc.labsec.signature.conformanceVerifier.cms;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.security.PrivateKey;
import java.security.Security;
import java.security.cert.Certificate;
import java.security.cert.CertificateEncodingException;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.logging.Level;
import br.ufsc.labsec.component.Application;
import br.ufsc.labsec.signature.AlgorithmIdentifierMapper;
import br.ufsc.labsec.signature.signer.FileFormat;
import br.ufsc.labsec.signature.signer.suite.SingletonSuiteMapper;
import org.apache.commons.io.IOUtils;
import org.bouncycastle.cert.jcajce.JcaCertStore;
import org.bouncycastle.cms.*;
import org.bouncycastle.cms.jcajce.JcaSimpleSignerInfoGeneratorBuilder;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.util.Store;

/**
 * Esta classe gera contêineres de assinaturas no formato CMS.
 */
public class SignatureContainerGenerator {

	/**
	 * Documento assinado
	 */
	private final InputStream target;
	/**
	 * Indica se a assinatura é anexada
	 */
	private boolean isAttached;
	/**
	 * Componente de assinatura CMS
	 */
	private final CmsSignatureComponent cmsSignatureComponent;
	/**
	 * Algoritmo da assinatura
	 */
	private String signatureSuite = SingletonSuiteMapper.getDefaultSignatureSuite();

	/**
	 * Construtor
	 * @param cmsSignatureComponent Componente de assinatura CMS
	 * @param target Arquivo assinado
	 */
	public SignatureContainerGenerator(CmsSignatureComponent cmsSignatureComponent, InputStream target) {
		this.cmsSignatureComponent = cmsSignatureComponent;
		this.target = target;
	}

	/**
	 * Constrói um objeto {@link SignerInfoGenerator} com as informações do assinante
	 * @param pvKey Chave privada
	 * @param cert Certificado do assinante
	 * @return Um objeto {@link SignerInfoGenerator} com as informações do assinante
	 */
	private SignerInfoGenerator buildSignInfo(PrivateKey pvKey, X509Certificate cert) {
		assert pvKey != null || cert != null: "NULL PARAMETERS FOUND AT " + getClass();
		SignerInfoGenerator returnable = null;
		try {
			returnable = buildSignerInfoGenerator(pvKey, cert);
		} catch (OperatorCreationException e) {
			Application.logger.log(Level.WARNING, e.getMessage(), e);
		}
		return returnable;
	}

	/**
	 * Transforma um {@link InputStream} em array de bytes
	 * @param in Um {@link InputStream}
	 * @return O array de bytes
	 * @throws IOException Exceção em caso de erro na transformação
	 */
	public byte[] processFile(InputStream in) throws IOException {
		return IOUtils.toByteArray(in);
	}

	/**
	 * Constrói um objeto {@link Store} com o certificado dado
	 * @param cert O certificado
	 * @return Um objeto {@link Store}
	 * @throws CertificateEncodingException Exceção no caso de erro na criação do {@link Store}
	 */
	// Permite ser sobre-escrito para a criação de contra-assinaturas
	public Store getCertificateStore(X509Certificate cert) throws CertificateEncodingException {
		List<Certificate> certs = new ArrayList<>();
		certs.add(cert);
		return buildCertStore(certs);
	}

	/**
	 * Gera o contêiner de assinatura CMS
	 * @param in O documento assinado
	 * @param pvKey Chave privada
	 * @param cert Certificado do assinante
	 * @return O contêiner de assinatura CMS
	 * @throws CertificateEncodingException Exceção em caso de problema com o certificado
	 * @throws CMSException Exceção em caso de erro de processamento da assinatura CMS
	 * @throws IOException Exceção em caso de problema com o {@link InputStream}
	 */
	public CmsSignatureContainer generate(InputStream in, PrivateKey pvKey, X509Certificate cert)
			throws CertificateEncodingException, CMSException, IOException {

		Security.addProvider(new BouncyCastleProvider());
		CMSSignedDataGenerator gen = new CMSSignedDataGenerator();

		SignerInfoGenerator info = buildSignInfo(pvKey, cert);
		gen.addSignerInfoGenerator(info);

		Store store = getCertificateStore(cert);
		gen.addCertificates(store);

		CMSSignedData cms = cmsSignedDataFromGenerator(gen, in);
		return new CmsSignatureContainer(cms, cmsSignatureComponent);
	}

	/**
	 * Cria um objeto {@link CMSSignedData} a partir do conteúdo do stream dado
	 * @param generator Gerador de {@link CMSSignedData}
	 * @param in Stream com o conteúdo
	 * @return O objeto {@link CMSSignedData} gerado
	 * @throws CMSException Exceção em caso de erro na geração do conteúdo
	 * @throws IOException Exceção em caso de erro no conteúdo do stream
	 */
	// Permite ser sobre-escrito para a criação de contra-assinaturas
	protected CMSSignedData cmsSignedDataFromGenerator(CMSSignedDataGenerator generator, InputStream in) throws CMSException, IOException {
		CMSTypedData digest = new CMSProcessableByteArray(processFile(in));
		return generator.generate(digest, isAttached);
	}

	/**
	 * Gera o contêiner de assinatura CMS
	 * @return O contêiner de assinatura CMS
	 * @throws CertificateEncodingException Exceção em caso de problema com o certificado
	 * @throws OperatorCreationException Exceção em caso de problema na geração da informação do assinante
	 * @throws CMSException Exceção em caso de erro de processamento da assinatura CMS
	 * @throws IOException Exceção em caso de problema com o {@link InputStream}
	 */
	public CmsSignatureContainer generate()
			throws CertificateEncodingException, OperatorCreationException, CMSException, IOException {
		
		Security.addProvider(new BouncyCastleProvider());
		CMSSignedDataStreamGenerator generator = new CMSSignedDataStreamGenerator();
		PrivateKey privateKey = this.cmsSignatureComponent.privateInformation.getPrivateKey();
		
		if (privateKey == null) {
			return null;
		}
		
		Certificate signerCert = this.cmsSignatureComponent.privateInformation.getCertificate();
		
		SignerInfoGenerator jcaSignerInfoGenerator = buildSignerInfoGenerator(privateKey, signerCert);
		generator.addSignerInfoGenerator(jcaSignerInfoGenerator);
		
		List<Certificate> certs = new ArrayList<>();
		certs.add(signerCert);
		Store store = buildCertStore(certs);
		generator.addCertificates(store);
				
		ByteArrayOutputStream outputStream = new ByteArrayOutputStream();
		OutputStream contentProcessor = generator.open(outputStream, this.isAttached);

		byte[] buffer = new byte[1024];
		int len;
		while ((len = this.target.read(buffer)) != -1) {
			contentProcessor.write(buffer, 0, len);
		}

		contentProcessor.close();
		CMSSignedData cmsSignedData = new CMSSignedData(new ByteArrayInputStream(outputStream.toByteArray()));

		return new CmsSignatureContainer(cmsSignedData, this.cmsSignatureComponent);
	}

	public void setSignatureSuite(String signatureSuite) {
		this.signatureSuite = signatureSuite;
	}

	/**
	 * Atribue o valor do atributo isAttached de acordo com o parâmetro do tipo de assinatura,
	 * anexada ou destacada
	 * @param mode O tipo da assinatura
	 */
	public void setMode(String mode) {
		this.isAttached = mode.equalsIgnoreCase(FileFormat.ATTACHED.toString());
	}

	/**
	 * Retorna a lista dos tipos de assinatura disponíveis
	 * @return Lista dos tipos de assinatura disponíveis
	 */
	public List<String> getModes() {
		String[] modes = { FileFormat.ATTACHED.toString(), FileFormat.DETACHED.toString() };
		return Arrays.asList(modes);
	}
	
	/**
	 * Cria um objeto {@link SignerInfoGenerator} para posterior geração de
	 * assinatura
	 * @param privateKey chave privada do assinante
	 * @param certificate certificado do assinante
	 * @return Um objeto {@link SignerInfoGenerator}
	 */
	private SignerInfoGenerator buildSignerInfoGenerator(PrivateKey privateKey, Certificate certificate)
			throws OperatorCreationException {
		SignerInfoGenerator built = null;
		try {
			String algorithm = AlgorithmIdentifierMapper.getAlgorithmNameFromIdentifier(signatureSuite);
			built = new JcaSimpleSignerInfoGeneratorBuilder().build(
					algorithm, privateKey, (X509Certificate) certificate
			);
		} catch (CertificateEncodingException e) {
			Application.logger.log(Level.WARNING, e.getMessage(), e);
		}
		return built;
	}

	/**
	 * Constrói um objeto {@link Store} com a lista de certificados
	 * @param certs A lista de certificados
	 * @return Um objeto {@link Store}
	 * @throws CertificateEncodingException Exceção no caso de erro na criação do {@link Store}
	 */
	protected Store buildCertStore(List<Certificate> certs) throws CertificateEncodingException {
		return new JcaCertStore(certs);
	}

}
