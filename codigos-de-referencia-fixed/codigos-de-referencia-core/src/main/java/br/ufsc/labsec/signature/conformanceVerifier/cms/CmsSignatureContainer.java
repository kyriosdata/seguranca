package br.ufsc.labsec.signature.conformanceVerifier.cms;

import java.io.ByteArrayInputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Collection;
import java.util.List;
import java.util.logging.Level;

import br.ufsc.labsec.signature.exceptions.VerificationException;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.ASN1TaggedObject;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.cms.CMSException;
import org.bouncycastle.cms.CMSProcessableByteArray;
import org.bouncycastle.cms.CMSSignedData;
import org.bouncycastle.cms.SignerInformation;
import org.bouncycastle.cms.SignerInformationStore;
import org.bouncycastle.util.Store;
import org.bouncycastle.util.io.Streams;

import br.ufsc.labsec.component.Application;
import br.ufsc.labsec.signature.conformanceVerifier.cms.exceptions.CmsSignatureException;
import br.ufsc.labsec.signature.exceptions.EncodingException;
import br.ufsc.labsec.signature.exceptions.PbadException;

/**
 * Esta classe representa o contêiner de assinaturas que estão dentro do {@link CMSSignedData}.
 */
@SuppressWarnings("rawtypes")
public class CmsSignatureContainer {

	/**
	 * O arquivo assinado
	 */
	private CMSSignedData cmsSignedData;
	/**
	 * Componente de assinatura CMS
	 */
	private CmsSignatureComponent cmsSignatureComponent;

	/**
	 * Construtor
	 * @param cmsSignedData Arquivo assinado
	 * @param cmsSignatureComponent Componente de assinatura CMS
	 */
	public CmsSignatureContainer(CMSSignedData cmsSignedData, CmsSignatureComponent cmsSignatureComponent) {
		this.cmsSignedData = cmsSignedData;
		this.cmsSignatureComponent = cmsSignatureComponent;
	}

	/**
	 * Construtor
	 * @param signatureBytes Bytes do documento de assinatura
	 * @param cmsSignatureComponent Componente de assinatura CMS
	 * @throws VerificationException
	 */
	public CmsSignatureContainer(byte[] signatureBytes, CmsSignatureComponent cmsSignatureComponent) throws VerificationException {

		this.cmsSignatureComponent = cmsSignatureComponent;
		try {
			this.cmsSignedData = new CMSSignedData(signatureBytes);
		} catch (CMSException | NullPointerException e) {
			Application.loggerInfo.log(Level.WARNING, "Não foi possível abrir a assinatura como um objeto CMSSignedData.");
			throw new VerificationException(e);
		}

	}

	/**
	 * Construtor
	 * @param target Caminho do documento de assinatura
	 * @param signedContent Caminho do conteúdo que foi assinado
	 * @param cmsSignatureComponent Componente de assinatura CMS
	 */
	public CmsSignatureContainer(String target, String signedContent, CmsSignatureComponent cmsSignatureComponent) {

		this.cmsSignatureComponent = cmsSignatureComponent;
		byte[] targetBytes = null;

		try {
			targetBytes = Streams.readAll(new FileInputStream(new File(target)));
			this.cmsSignedData = new CMSSignedData(targetBytes);
		} catch (FileNotFoundException e) {
			Application.logger.log(Level.SEVERE, "Não foi possível abrir a assinatura.", e);
		} catch (CMSException | IOException e) {
			Application.logger.log(Level.SEVERE, "Ocorreu um erro ao processar a assinatura.", e);
		}

		try {
			if (this.hasDetachedContent()) {
				byte[] signedContentBytes = Streams.readAll(new FileInputStream(new File(signedContent)));
				this.cmsSignedData = new CMSSignedData(new CMSProcessableByteArray(signedContentBytes), targetBytes);
			}
		} catch (FileNotFoundException e) {
			Application.logger.log(Level.SEVERE, "Não foi possível encontrar o conteúdo detached da assinatura.", e);
		} catch (CMSException | IOException | NullPointerException e) {
			Application.logger.log(Level.SEVERE, "Ocorreu um erro ao processar a assinatura.", e);
		} catch (EncodingException e) {
			Application.logger.log(Level.SEVERE, e.getMessage(), e);
		}

	}

	/**
	 * Retorna o arquivo em formato InputStream
	 * @return O arquivo em formato InputStream
	 */
	public InputStream getStream() {

		try {
			return new ByteArrayInputStream(this.cmsSignedData.getEncoded());
		} catch (IOException e) {
			Application.logger.log(Level.SEVERE, "Ocorreu um erro ao processar a assinatura.", e);
		}

		return null;

	}

	/**
	 * Retorna as assinaturas no arquivo
	 * @return As assinaturas no arquivo
	 */
	public List<CmsSignature> getSignatures() {

		SignerInformationStore signerInfosStore = this.cmsSignedData.getSignerInfos();
		Collection<SignerInformation> signerInfos = signerInfosStore.getSigners();
		List<CmsSignature> signatures = new ArrayList<CmsSignature>();

		for (SignerInformation signerInfo : signerInfos) {
			signatures.add(new CmsSignature(this, signerInfo, this.cmsSignatureComponent));
		}

		return signatures;

	}

	/**
	 * Retorna os certificados utilizados para assinatura no arquivo
	 * @return Um objeto {@link Store} com os certificados
	 */
	Store getCertificateStore() {
		return this.cmsSignedData.getCertificates();
	}

	/**
	 * Retorna a lista de certificados utilizados para assinatura no arquivo
	 * @return A lista de certificados
	 * @throws CMSException Exceção em caso de erro na criação da lista
	 * @throws CertificateException Exceção em caso de erro na manipulação dos certificados
	 */
    List<X509Certificate> getCertificates()
            throws CMSException, CertificateException {
        List<X509Certificate> certs = new ArrayList<>();
        try {
            for (Object o : this.getCertificateStore().getMatches(null)) {
                X509CertificateHolder c = (X509CertificateHolder) o;
                certs.add(new JcaX509CertificateConverter().getCertificate(c));
            }
            return certs;
        } catch (ClassCastException e) {
            throw new CMSException("Erro ao processar certificado.", e);
        }
    }

	/**
	 * Retorna a lista de certificados revogados
	 * @return A lista de certificados revogados
	 */
	public Store getCrls() {
		return this.cmsSignedData.getCRLs();
	}

	/**
	 * Verifica se o arquivo possui alguma assinatura com conteúdo destacado
	 * @return Indica se o arquivo possui conteúdo destacado
	 */
	public boolean hasDetachedContent() throws EncodingException {

		try {
			ASN1Sequence contentInfoSeq = (ASN1Sequence) ASN1Sequence.fromByteArray(this.cmsSignedData.getEncoded());
			ASN1TaggedObject berTaggedObj = (ASN1TaggedObject) contentInfoSeq.getObjectAt(1);
			ASN1Sequence signedDataSeq = (ASN1Sequence) berTaggedObj.getObject();
			ASN1Sequence encapContent = (ASN1Sequence) signedDataSeq.getObjectAt(2);
			return encapContent.size() == 1;
		} catch (IOException ioException) {
			throw new EncodingException("Falha na codificação do CMSSignedData passado por parâmetro.", ioException);
		}

	}

	/**
	 * Atribue o conteúdo assinado
	 * @param signedContentBytes Os bytes do conteúdo assinado
	 * @throws PbadException Exceção caso ocorra erro na transformação dos bytes
	 */
	public void setSignedContent(byte[] signedContentBytes) throws PbadException {

		try {
			this.cmsSignedData = new CMSSignedData(new CMSProcessableByteArray(signedContentBytes),
					this.cmsSignedData.getEncoded());
		} catch (IOException ioException) {
			Application.logger.log(Level.SEVERE, "Ocorreu um erro ao processar a assinatura.", ioException);
		} catch (CMSException cmsException) {
			throw new CmsSignatureException("Erro ao decodificar assinatura.", cmsException);
		}

	}

	/**
	 * Retorna o arquivo em formato OutputStream
	 * @param outputStream Stream no qual será colocado o valor do arquivo de assinatura
	 * @throws EncodingException Exceção caso haja algum problema na conversão dos dados
	 *         do arquivo para o stream
	 */
    public void encode(OutputStream outputStream) throws EncodingException {
        try {
            byte[] cms = this.cmsSignedData.getEncoded();
            outputStream.write(cms);
            outputStream.close();
        } catch (IOException ioException) {
            throw new EncodingException(ioException);
        }
    }

	/**
	 * Retorna os bytes do arquivo assinado
	 * @return O arquivo assinado em um array de bytes
	 * @throws EncodingException Exceção em caso de erro na obtenção dos bytes
	 */
	public byte[] toBytes() throws EncodingException {
		try {
			return this.cmsSignedData.getEncoded();
		} catch (IOException ioException) {
			throw new EncodingException(ioException);
		}
	}

	//	Contra-assinaturas não podem ser reconstruidas a partir dos bytes (getEncoded)
	//	e precisam de acesso ao próprio cmsSignedData
	public CMSSignedData getCmsSignedData() {
		return cmsSignedData;
	}

}
