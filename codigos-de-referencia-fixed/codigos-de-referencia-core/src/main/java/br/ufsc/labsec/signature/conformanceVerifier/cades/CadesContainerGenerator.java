/*

Desenvolvido pelo Laboratório de Segurança em Computação (LabSEC) do Departamento de Informática e Estatística (INE),
da Universidade Federal de Santa Catarina (UFSC).

Apoio: Colégio Notarial do Brasil (CNB) e Instituto Nacional de Tecnologia da Informação (ITI).

 */

package br.ufsc.labsec.signature.conformanceVerifier.cades;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.Security;
import java.security.cert.CertPath;
import java.security.cert.Certificate;
import java.security.cert.CertificateEncodingException;
import java.security.cert.X509Certificate;
import java.sql.Time;
import java.util.ArrayList;
import java.util.Collections;
import java.util.Date;
import java.util.Hashtable;
import java.util.List;

import br.ufsc.labsec.signature.SystemTime;
import org.bouncycastle.asn1.ASN1EncodableVector;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.cms.Attribute;
import org.bouncycastle.asn1.cms.AttributeTable;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cms.CMSException;
import org.bouncycastle.cms.CMSSignedData;
import org.bouncycastle.cms.CMSSignedDataStreamGenerator;
import org.bouncycastle.cms.SignerInfoGenerator;
import org.bouncycastle.cms.SimpleAttributeTableGenerator;
import org.bouncycastle.cms.jcajce.JcaSignerInfoGeneratorBuilder;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.DigestCalculatorProvider;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.bouncycastle.operator.jcajce.JcaDigestCalculatorProviderBuilder;
import org.bouncycastle.util.CollectionStore;
import org.bouncycastle.util.Store;

import br.ufsc.labsec.component.Application;
import br.ufsc.labsec.signature.AlgorithmIdentifierMapper;
import br.ufsc.labsec.signature.ContentToBeSigned;
import br.ufsc.labsec.signature.SignaturePolicyInterface;
import br.ufsc.labsec.signature.conformanceVerifier.cades.attributes.SignatureAttribute;
import br.ufsc.labsec.signature.conformanceVerifier.cades.exceptions.CadesSignatureException;
import br.ufsc.labsec.signature.conformanceVerifier.cades.exceptions.SignatureModeException;
import br.ufsc.labsec.signature.conformanceVerifier.signaturePolicy.decoder.SignaturePolicy;
import br.ufsc.labsec.signature.conformanceVerifier.signaturePolicy.decoder.SignerRules.CertInfoReq;
import br.ufsc.labsec.signature.conformanceVerifier.xades.exceptions.AlgorithmException;
import br.ufsc.labsec.signature.conformanceVerifier.xades.exceptions.ToBeSignedException;
import br.ufsc.labsec.signature.exceptions.EncodingException;
import br.ufsc.labsec.signature.exceptions.PbadException;
import br.ufsc.labsec.signature.exceptions.SignatureAttributeException;

/**
 * Esta classe é utilizada apenas pela classe
 * {@link SignatureContainerGenerator}.
 * Não deve ser utilizada pelo usuário.
 * Implementa {@link ContainerGenerator}.
 */
public class CadesContainerGenerator implements ContainerGenerator {

	/**
	 * Conteúdo a ser assinado
	 */
	protected CadesContentToBeSigned contentToBeSigned;
	/**
	 * Informações do assinante
	 */
	protected SignerData signer;
	/**
	 * Gerador de {@link CMSSignedData}
	 */
	protected CMSSignedDataStreamGenerator cmsSignedDataGenerator;
	/**
	 * Lista de atributos da assinatura
	 */
	protected List<SignatureAttribute> signatureAttributes;
	/**
	 * Política de assinatura
	 */
	protected SignaturePolicyInterface signaturePolicy;
	/**
	 * Componente de assinatura CAdES
	 */
	protected CadesSignatureComponent component;

	/**
	 * Constrói um {@link CadesContainerGenerator} a partir da Política de
	 * Assinatura usada na assinatura.
	 * @param cadesComponent Componente de assinatura CAdES
	 */
	public CadesContainerGenerator(CadesSignatureComponent cadesComponent) {
		this.component = cadesComponent;
		this.signaturePolicy = cadesComponent.signaturePolicyInterface;
		this.signatureAttributes = new ArrayList<SignatureAttribute>();
		this.cmsSignedDataGenerator = new CMSSignedDataStreamGenerator();
		Security.addProvider(new BouncyCastleProvider());
	}

	/**
	 * Gera o contêiner da assinatura CAdES
	 * @return O contêiner gerado
	 * @throws PbadException Exceção em caso de erro na criação do contêiner
	 * @throws AlgorithmException
	 */
	public SignatureContainer generate() {
		CMSSignedData cmsSignedData = null;
		try {
			cmsSignedData = this.generateSignature();
			return new CadesSignatureContainer(cmsSignedData.getEncoded(),
					this.contentToBeSigned.getContentToBeSigned());
		} catch (CadesSignatureException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (IOException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (CertificateEncodingException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (OperatorCreationException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (SignatureModeException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (SignatureAttributeException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (EncodingException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (CMSException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
		return null;
	}

	/**
	 * Gera uma assinatura no formato CAdES.
	 * @return O conteúdo assinado
	 * @throws IOException Exceção em caso de erro na leitura do conteúdo a ser assinado
	 * @throws SignatureModeException Exceção em caso de erro no modo de assinatura
	 * @throws OperatorCreationException 
	 * @throws CertificateEncodingException Exceção em caso de erro no certificado do assinante
	 * @throws EncodingException 
	 * @throws SignatureAttributeException  Exceção em caso de erro nos atributos da assinatura
	 * @throws CMSException Exceção em caso de erro na manipulação do conteúdo a ser assinado
	 * @throws CadesSignatureException  Exceção em caso de erro na geração da assinatura CAdES
	 */
	protected CMSSignedData generateSignature() throws SignatureModeException,
			IOException, CertificateEncodingException, OperatorCreationException, SignatureAttributeException, EncodingException, CMSException, CadesSignatureException {
		ByteArrayOutputStream outputStream = new ByteArrayOutputStream();
		OutputStream contentProcessor = this.cmsSignedDataGenerator.open(
				outputStream, this.isAttached());

		SignerInfoGenerator signerInfoGenerator = this.buildSignerInfoGenerator(this.signer.getKey(),
						this.signer.getCertificate());

		if (!this.contentToBeSigned.isStreamed()) {
			//Não deve entrar aqui, código legado.
			byte[] toBeSigned = this.contentToBeSigned.getContentToBeSigned();
			contentProcessor.write(toBeSigned);
		} else {
			InputStream contentStream = this.contentToBeSigned.getContentToBeSignedAsStream();
			String policyHashAlgorithm = signaturePolicy.getHashAlgorithmId();
			MessageDigest md;
			try {
				md = MessageDigest.getInstance(AlgorithmIdentifierMapper
							.getAlgorithmNameFromIdentifier(policyHashAlgorithm));
			} catch (NoSuchAlgorithmException e) {
				Application.logger.info("Not possible to instantiate the MessageDigest.");
				throw new CadesSignatureException("Not possible to instantiate the MessageDigest.", e);
			}
			
			byte[] buffer = new byte[1024];
			int len;
			while ((len = contentStream.read(buffer)) != -1) {
				contentProcessor.write(buffer, 0, len);
				md.update(buffer, 0, len);
			}
			
			this.contentToBeSigned.setHash(md.digest());

		}
		
		
		this.addCertificateInfo(this.cmsSignedDataGenerator);
		this.addSigner(signerInfoGenerator);
		
		contentProcessor.close();

		return new CMSSignedData(new ByteArrayInputStream(outputStream.toByteArray()));
	}

	/**
	 * Adiciona informações de certificado no gerador de {@link CMSSignedData} dado
	 * @param cmsSignedDataGenerator O gerador de {@link CMSSignedData}
	 * @throws CadesSignatureException Exceção em caso de erro na obtenção dos certificados ou na sua adição
	 */
	private void addCertificateInfo(CMSSignedDataStreamGenerator cmsSignedDataGenerator)
			throws CadesSignatureException {

		CertInfoReq certInfoReq = this.signaturePolicy.getMandatedCertificateInfo();

		Store store = null;
		
		
		switch (certInfoReq) {
			case NONE:
				break;
	
			case SIGNER_ONLY:
					
				try {
					X509CertificateHolder cert = new X509CertificateHolder(this.signer.getCertificate().getEncoded());
					List<X509CertificateHolder> certs = Collections.singletonList(cert);
					store = new CollectionStore(certs);
					
					cmsSignedDataGenerator.addCertificates(store);
					
				} catch (CMSException | CertificateEncodingException | IOException e) {
					throw new CadesSignatureException(e);
				}
				break;
	
			case FULL_PATH:
	
				
				try {
				
					CertPath certPath = this.component.certificateValidation
							.generateCertPath(this.signer.getCertificate(), this.signaturePolicy.getSigningTrustAnchors(), new Time(SystemTime.getSystemTime()));
					
					List<X509CertificateHolder> certs = new ArrayList<X509CertificateHolder>();
					for (Certificate cert : certPath.getCertificates()) {
						certs.add(new X509CertificateHolder(cert.getEncoded()));
					}
					
					store = new CollectionStore(certs);
					
					cmsSignedDataGenerator.addCertificates(store);
					
				} catch (CMSException | CertificateEncodingException | IOException e) {
					throw new CadesSignatureException(e);
				}
				break;
		}

	}

	/**
	 * Determina o conteúdo que será assinado
	 * @param contentsToBeSigned O conteúdo para assinatura
	 */
	public void setContentsToBeSigned(List<ContentToBeSigned> contentsToBeSigned) {
		if (contentsToBeSigned.size() > 1)
			try {
				throw new CadesSignatureException(
						"Assinaturas CAdES só permitem um único conteúdo");
			} catch (CadesSignatureException e) {
				// TODO Auto-generated catch block
				e.printStackTrace();
			}
		this.contentToBeSigned = (CadesContentToBeSigned) contentsToBeSigned
				.get(0);
	}

	/**
	 * Determina quais atributos serão usados no processo de assinatura
	 * @param attributeList	Lista de atributos a serem inseridos na assinatura
	 * @throws SignatureAttributeException Exceção em caso de erro em algum atributo
	 */
	public void setAttributes(List<SignatureAttribute> attributeList)
			throws SignatureAttributeException {
		SignatureAttribute signatureAttribute;
		for (SignatureAttribute attribute : attributeList) {
			signatureAttribute = attribute;
			boolean isSignedAttribute = signatureAttribute.isSigned();
			if (!isSignedAttribute) {
				throw new SignatureAttributeException(
						"Neste momento devem ser adicionados apenas "
								+ "atributos assinados. Os atributos não assinados devem ser adicionados após"
								+ "a assinatura já ter sido criada");
			}
		}
		this.signatureAttributes = attributeList;
	}

	/**
	 * Atribue os dados do assinante
	 * @param signer Os dados do assinante
	 */
	public void setSigner(SignerData signer) {
		this.signer = signer;
	}

	/**
	 * Verifica se o modo de assinatura é anexado
	 * @return Indica que o modo de assinatura é anexado
	 * @throws SignatureModeException Exceção em caso de modo inválido
	 */
	protected boolean isAttached() throws SignatureModeException {
		boolean isAttached;
		if (this.contentToBeSigned.getSignatureMode().equals(
				SignatureModeCAdES.DETACHED)) {
			isAttached = false;
		} else if (this.contentToBeSigned.getSignatureMode().equals(
				SignatureModeCAdES.ATTACHED)) {
			isAttached = true;
		} else {
			throw new SignatureModeException(
					"Modo de assinatura incompatível com o padrão CAdES");
		}
		return isAttached;
	}

	/**
	 * Adiciona as informações do assinante no contêiner
	 * @param signerInfoGenerator As informações do assinante
	 * @throws SignatureAttributeException Exceção em caso de erro na adição
	 */
	protected void addSigner(SignerInfoGenerator signerInfoGenerator)
			throws CertificateEncodingException, OperatorCreationException,
			SignatureAttributeException, EncodingException {
		ASN1EncodableVector asn1EncodableVector = new ASN1EncodableVector();
		for (SignatureAttribute signatureAttribute : this.signatureAttributes) {
			Attribute attribute = signatureAttribute.getEncoded();
			asn1EncodableVector.add(attribute);
		}
		SimpleAttributeTableGenerator signedAttributeTableGenerator = new SimpleAttributeTableGenerator(
				new AttributeTable(asn1EncodableVector));
		signerInfoGenerator = new SignerInfoGenerator(signerInfoGenerator,
				signedAttributeTableGenerator, null);
		this.cmsSignedDataGenerator.addSignerInfoGenerator(signerInfoGenerator);
	}

	/**
	 * Informa a tabela de atributos de uma assinatura
	 * @return O mapa entre atributo e identificador de atributo
	 * @throws SignatureAttributeException Exceção em caso de erro nos atributos
	 */
	protected Hashtable<ASN1ObjectIdentifier, Attribute> getSignatureAttributesTable()
			throws SignatureAttributeException {
		Hashtable<ASN1ObjectIdentifier, Attribute> signedAttributes = new Hashtable<ASN1ObjectIdentifier, Attribute>();
		for (SignatureAttribute signatureAttribute : this.signatureAttributes) {
			signedAttributes
					.put(new ASN1ObjectIdentifier(signatureAttribute
							.getIdentifier()), signatureAttribute.getEncoded());
		}
		return signedAttributes;
	}

	/**
	 * Cria um objeto {@link SignerInfoGenerator} para posterior geração de
	 * assinatura
	 * @param privateKey A chave privada do assinante
	 * @param certificate O certificado do assinante
	 * @return O objeto {@link SignerInfoGenerator} gerado
	 * @throws OperatorCreationException
	 * @throws CertificateEncodingException
	 */
	protected SignerInfoGenerator buildSignerInfoGenerator(
			PrivateKey privateKey, Certificate certificate)
			throws OperatorCreationException, CertificateEncodingException {
		String signatureAlgorithm = this.signaturePolicy
				.getSignatureAlgorithmIdentifier();
		JcaContentSignerBuilder contentSignerBuilder = new JcaContentSignerBuilder(
				AlgorithmIdentifierMapper
						.getAlgorithmNameFromIdentifier(signatureAlgorithm));
		ContentSigner contentSigner = contentSignerBuilder.build(privateKey);
		DigestCalculatorProvider digestCalculatorProvider = new JcaDigestCalculatorProviderBuilder()
				.setProvider("BC").build();
		JcaSignerInfoGeneratorBuilder signerInfoGeneratorBuilder = new JcaSignerInfoGeneratorBuilder(
				digestCalculatorProvider);
		X509Certificate signerCertificate = (X509Certificate) certificate;
		return signerInfoGeneratorBuilder.build(contentSigner,
				signerCertificate);
	}

}
