package br.ufsc.labsec.signature.conformanceVerifier.cades;

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
import br.ufsc.labsec.signature.conformanceVerifier.cades.attributes.TimeStampVerifier;

/**
 * Representa um componente de assinatura CAdES.
 * Estende {@link Component}.
 */
public class CadesSignatureComponent extends Component {

    @Requirement
    public SignaturePolicyInterface signaturePolicyInterface;
    @Requirement
    public List<CertificateCollection> certificateCollection;
    @Requirement
    public List<RevocationInformation> revocationInformation; 
    @Requirement
    public CertificateValidation certificateValidation;
    @Requirement (optional = true)
    public TimeStamp timeStamp;    
    @Requirement (optional = true)
    public IOService ioService;    
    @Requirement (optional = true)
    public PrivateInformation privateInformation;

    /**
     * Um {@link Verifier} para assinaturas CAdES
     */
    private CadesVerifier cadesVerifier;
    /**
     * Gerenciador de listas de certificados e CRLs
     */
    private SignatureIdentityInformation signatureIdentityInformation;
    /**
     * Verificador de carimbo de tempo
     */
    private TimeStampVerifier timeStampVerifier;
    /**
     * Um {@link Signer} para assinaturas CAdES
     */
	private AbstractCadesSigner cadesSigner;
    /**
     * Um assinador de contra assinaturas CAdES
     */
	private CadesCounterSigner cadesCounterSigner;
    /**
     * Um assinador de co-assinaturas CAdES
     */
	private CadesCoSigner cadesCoSigner;

    /**
     * Construtor
     * @param application Uma aplicação com seus componentes
     */
    public CadesSignatureComponent(Application application) {
        super(application);
        this.defineRoleProvider(Verifier.class.getName(), this.getVerifier());
        this.defineRoleProvider(RevocationInformation.class.getName(), this.getSignatureIdentityInformation());
        this.defineRoleProvider(CertificateCollection.class.getName(), this.getSignatureIdentityInformation());
        this.defineRoleProvider(TimeStampVerifierInterface.class.getName(), this.getTimeStampVerifier());
        this.defineRoleProvider(Signer.class.getName(), this.getCadesSigner());
        this.defineRoleProvider(CoSigner.class.getName(),this.getCadesCoSigner());
        this.defineRoleProvider(CounterSigner.class.getName(), this.getCadesCounterSigner());
        this.defineRoleProvider(TimeStampAttributeIncluder.class.getName(), this.getCadesSigner());
    }

    /**
     * Retorna um assinador de co-assinaturas CAdES
     * @return Um assinador CAdES
     */
	private CadesCoSigner getCadesCoSigner() {
        if (this.cadesCoSigner == null) {
            this.cadesCoSigner = new CadesCoSigner(this);
        }
        return this.cadesCoSigner;
	}

    /**
     * Retorna um assinador de contra assinaturas CAdES
     * @return Um assinador CAdES
     */
	private CadesCounterSigner getCadesCounterSigner() {
        if (this.cadesCounterSigner == null) {
            this.cadesCounterSigner = new CadesCounterSigner(this);
        }
        return this.cadesCounterSigner;
	}

    /**
     * Retorna um assinador CAdES
     * @return Um assinador CAdES
     */
	private AbstractCadesSigner getCadesSigner() {
        if (this.cadesSigner == null) {
            this.cadesSigner = new CadesSigner(this);
        }
        return this.cadesSigner;
	}

    /**
     * Inicia o componente
     */
    @Override
    public void startOperation() {
    }

    /**
     * Retorna o verificador de carimbo de tempo
     * @return O verificador de carimbo de tempo
     */
    public TimeStampVerifier getTimeStampVerifier() {
        if (this.timeStampVerifier == null) {
            this.timeStampVerifier = new TimeStampVerifier(this);
        }
        return this.timeStampVerifier;
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
     * Retorna o {@link Verifier} para assinaturas CAdES
     * @return O {@link Verifier} para assinaturas CAdES
     */
    public CadesVerifier getVerifier() {
        if (this.cadesVerifier == null) {
            this.cadesVerifier = new CadesVerifier(this);
        }

        return this.cadesVerifier;
    }

    /**
     * Limpa as informações do componente
     */
    @Override
    public void clear() {
        timeStamp = null;
        certificateCollection = null;
        revocationInformation = null;
    }

}
