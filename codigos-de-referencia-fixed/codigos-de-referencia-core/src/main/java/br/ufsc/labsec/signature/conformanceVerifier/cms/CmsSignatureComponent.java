package br.ufsc.labsec.signature.conformanceVerifier.cms;

import java.util.List;

import br.ufsc.labsec.component.Application;
import br.ufsc.labsec.component.Component;
import br.ufsc.labsec.component.Requirement;
import br.ufsc.labsec.signature.CertificateCollection;
import br.ufsc.labsec.signature.CertificateValidation;
import br.ufsc.labsec.signature.IOService;
import br.ufsc.labsec.signature.PrivateInformation;
import br.ufsc.labsec.signature.RevocationInformation;
import br.ufsc.labsec.signature.Signer;
import br.ufsc.labsec.signature.Verifier;
import br.ufsc.labsec.signature.conformanceVerifier.validationService.TrustAnchorInterface;
import br.ufsc.labsec.signature.signer.signatureSwitch.CmsSigner;


/**
 * Representa um componente de assinatura CMS.
 * Estende {@link Component}.
 */
public class CmsSignatureComponent extends Component {

	@Requirement
	public List<CertificateCollection> certificateCollection;
	@Requirement
	public List<RevocationInformation> revocationInformation;
	@Requirement
	public CertificateValidation certificatePathValidation;
    @Requirement (optional = true)
    public PrivateInformation privateInformation;
    @Requirement (optional = true)
    public IOService ioService;
	@Requirement
	public TrustAnchorInterface trustAnchorInterface;

	/**
	 * Um Verifier para assinaturas CMS
	 */
	private CmsVerifier cmsVerifier;
	/**
	 * Um {@link Signer} para assinaturas CMS
	 */
	private CmsSigner cmsSigner;
	/**
	 * Gerenciador de listas de certificados e CRLs
	 */
	private SignatureIdentityInformation signatureIdentityInformation;

	/**
	 * Construtor
	 * @param application Uma aplicação com seus componentes
	 */
	public CmsSignatureComponent(Application application) {
		super(application);
		this.defineRoleProvider(Verifier.class.getName(), this.getVerifier());
		this.defineRoleProvider(Signer.class.getName(), this.getSigner());
		this.defineRoleProvider(RevocationInformation.class.getName(), this.getSignatureIdentityInformation());
		this.defineRoleProvider(CertificateCollection.class.getName(), this.getSignatureIdentityInformation());
	}

	/**
	 * Retorna um assinador CMS
	 * @return Um assinador CMS
	 */
	private Signer getSigner() {
		if (this.cmsSigner == null) {
			this.cmsSigner = new CmsSigner(this);
		}

		return this.cmsSigner;
	}

	/**
	 * Retorna o Verifier para assinaturas CMS
	 * @return O Verifier para assinaturas CMS
	 */
	public CmsVerifier getVerifier() {

		if (this.cmsVerifier == null) {
			this.cmsVerifier = new CmsVerifier(this);
		}

		return this.cmsVerifier;

	}

	/**
	 * Retorna o gerenciador das listas de certificados e CRLs
	 * @return O gerenciador das listas de certificados e CRLs
	 */
	public SignatureIdentityInformation getSignatureIdentityInformation() {

		if (this.signatureIdentityInformation == null) {
			this.signatureIdentityInformation = new SignatureIdentityInformation(this);
		}

		return this.signatureIdentityInformation;

	}

	/**
	 * Inicia o componente
	 */
	@Override
	public void startOperation() {
	}

	/**
	 * Limpa as informações do componente
	 */
	@Override
	public void clear() {
		// TODO Auto-generated method stub
	}

}
