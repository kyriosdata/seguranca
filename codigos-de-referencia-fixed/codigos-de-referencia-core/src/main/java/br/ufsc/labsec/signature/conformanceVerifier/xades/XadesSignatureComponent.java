package br.ufsc.labsec.signature.conformanceVerifier.xades;

import java.util.List;

import br.ufsc.labsec.component.Application;
import br.ufsc.labsec.component.Component;
import br.ufsc.labsec.component.Requirement;
import br.ufsc.labsec.signature.CertificateCollection;
import br.ufsc.labsec.signature.CertificateValidation;
import br.ufsc.labsec.signature.CoSigner;
import br.ufsc.labsec.signature.CounterSigner;
import br.ufsc.labsec.signature.IOService;
import br.ufsc.labsec.signature.PrivateInformation;
import br.ufsc.labsec.signature.RevocationInformation;
import br.ufsc.labsec.signature.SignaturePolicyInterface;
import br.ufsc.labsec.signature.Signer;
import br.ufsc.labsec.signature.tsa.TimeStamp;
import br.ufsc.labsec.signature.tsa.TimeStampAttributeIncluder;
import br.ufsc.labsec.signature.tsa.TimeStampVerifierInterface;
import br.ufsc.labsec.signature.Verifier;

/**
 * Representa um componente de assinatura XAdES.
 * Estende {@link Component}.
 */
public class XadesSignatureComponent extends Component {

    @Requirement
    public List<CertificateCollection> certificateCollection;
    @Requirement
    public List<RevocationInformation> revocationInformation;
    @Requirement
    public SignaturePolicyInterface signaturePolicyInterface; 
    @Requirement
    public CertificateValidation certificateValidation;
    @Requirement (optional = true)
    public IOService ioService;
    @Requirement (optional = true)
    public PrivateInformation privateInformation; 
    @Requirement (optional = true)
    public TimeStamp timeStamp; 
    @Requirement (optional = true)
    public TimeStampAttributeIncluder timeStampAttributeIncluder;
    @Requirement
    public TimeStampVerifierInterface timeStampVerifier;

	/**
	 * Um Verifier para assinaturas XAdES
	 */
    private XadesVerifier verifier;
	/**
	 * Gerenciador de listas de certificados e CRLs
	 */
    private SignatureIdentityInformation signatureVerifierInformation;
	/**
	 * Um {@link Signer} para assinaturas XAdES
	 */
    private AbstractXadesSigner signer;
	/**
	 * Um assinador de contra assinaturas XAdES
	 */
	private CounterSigner counterSigner;
	/**
	 * Um assinador de co-assinaturas XAdES
	 */
	private CoSigner coSigner;

	/**
	 * Construtor
	 * @param application Uma aplicação com seus componentes
	 */
    public XadesSignatureComponent(Application application) {
        super(application);

        this.defineRoleProvider(Verifier.class.getName(), this.getVerifier());
        this.defineRoleProvider(RevocationInformation.class.getName(), this.getSignatureIdentityInformation());
        this.defineRoleProvider(CertificateCollection.class.getName(), this.getSignatureIdentityInformation());
        this.defineRoleProvider(PrivateInformation.class.getName(), this.getPrivateInformation());
        this.defineRoleProvider(Signer.class.getName(), this.getSigner());
        this.defineRoleProvider(CounterSigner.class.getName(), this.getCounterSigner());
        this.defineRoleProvider(CoSigner.class.getName(), this.getCoSigner());
    }

	/**
	 * Retorna o gerenciador das listas de certificados e CRLs
	 * @return O gerenciador das listas de certificados e CRLs
	 */
    public SignatureIdentityInformation getSignatureIdentityInformation() {
        if (this.signatureVerifierInformation == null) {
            this.signatureVerifierInformation = new SignatureIdentityInformation(this);
        }
        return this.signatureVerifierInformation;
    }

	/**
	 * Retorna o {@link Verifier} para assinaturas XAdES
	 * @return O {@link Verifier} para assinaturas XAdES
	 */
    public XadesVerifier getVerifier() {
        if (this.verifier == null) {
            this.verifier = new XadesVerifier(this);
        }
        return this.verifier;
    }

	/**
	 * Inicia o componente
	 */
	@Override
	public void startOperation() {
	}

	/**
	 * Retorna as informações do assinante
	 * @return As informações do assinante
	 */
    private PrivateInformation getPrivateInformation() {
        if (this.privateInformation == null) {
            //TODO this.privateInformation = new NSSIdentitySelector();
        }
        return this.privateInformation;
    }

	/**
	 * Retorna um assinador XAdES
	 * @return Um assinador XAdES
	 */
    private AbstractXadesSigner getSigner() {
        if (this.signer == null) {
            this.signer = new XadesSigner(this);
        }
        return this.signer;
    }

	/**
	 * Retorna um assinador de contra assinaturas XAdES
	 * @return Um assinador XAdES
	 */
	private CounterSigner getCounterSigner() {
		if (this.counterSigner == null) {
			this.counterSigner = new XadesCounterSigner(this);
		}
		return this.counterSigner;
	}

	/**
	 * Retorna um assinador de co-assinaturas XAdES
	 * @return Um assinador XAdES
	 */
    private Object getCoSigner() {
    	if (this.coSigner == null) {
			this.coSigner = new XadesCoSigner(this);
		}
		return this.coSigner;
	}

	/**
	 * Limpa as informações do componente
	 */
    @Override
    public void clear() {
        // TODO Auto-generated method stub

    }

}
