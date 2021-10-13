package br.ufsc.labsec.signature.conformanceVerifier.xml;

import java.util.List;

import br.ufsc.labsec.component.Application;
import br.ufsc.labsec.component.Component;
import br.ufsc.labsec.component.Requirement;
import br.ufsc.labsec.signature.*;
import br.ufsc.labsec.signature.conformanceVerifier.validationService.TrustAnchorInterface;
import br.ufsc.labsec.signature.signer.signatureSwitch.XmlSigner;

/**
 * Representa um componente de assinatura XML.
 * Estende {@link Component}.
 */
public class XmlSignatureComponent extends Component {

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
     * Um {@link Verifier} para assinaturas XML
     */
    private XmlVerifier xmlVerifier;
    private XmlSigner xmlSigner;
    /**
     * Gerencia as listas de certificados e CRLs
     */
    private SignatureIdentityInformation signatureIdentityInformation;

    /**
     * Construtor da classe
     * @param application Uma aplicação com seus componentes
     */
    public XmlSignatureComponent(Application application) {
        super(application);
        this.defineRoleProvider(Verifier.class.getName(), this.getVerifier());
        this.defineRoleProvider(Signer.class.getName(), this.getSigner());
        this.defineRoleProvider(RevocationInformation.class.getName(), this.getSignatureIdentityInformation());
        this.defineRoleProvider(CertificateCollection.class.getName(), this.getSignatureIdentityInformation());
    }

    /**
     * Retorna o {@link Verifier} para assinaturas XML
     * @return O {@link Verifier} para assinaturas XML
     */
    public XmlVerifier getVerifier() {

        if (this.xmlVerifier == null) {
            this.xmlVerifier = new XmlVerifier(this);
        }

        return this.xmlVerifier;

    }

    /**
     * Retorna o {@link Signer} para assinaturas XML
     * @return O {@link Signer} para assinaturas XML
     */
    public XmlSigner getSigner() {

        if (this.xmlSigner == null) {
            this.xmlSigner = new XmlSigner(this);
        }

        return this.xmlSigner;
    }

    /**
     * Retorna o {@link SignatureIdentityInformation}
     * @return O {@link SignatureIdentityInformation}
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
