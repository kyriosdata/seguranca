/**
 *
 */
package br.ufsc.labsec.signature.conformanceVerifier.pades;

import br.ufsc.labsec.component.Application;
import br.ufsc.labsec.component.Component;
import br.ufsc.labsec.component.Requirement;
import br.ufsc.labsec.signature.*;
import br.ufsc.labsec.signature.conformanceVerifier.cades.CadesSignatureComponent;
import br.ufsc.labsec.signature.conformanceVerifier.signaturePolicy.SignaturePolicyProxy;

import java.util.List;

/**
 * Representa um componente de assinatura PAdES.
 * Estende {@link Component}.
 */
public class PadesSignatureComponent extends Component {

    @Requirement
    public Signer cadesSigner;
    @Requirement
    public Verifier cadesVerifier;
    @Requirement
    public SignaturePolicyInterface signaturePolicyInterface;
    @Requirement
    public CertificateValidation certificateValidation;

    /**
     * Um {@link Signer} para assinaturas PAdES
     */
    private PadesSigner padesSigner;
    /**
     * O {@link Verifier} para assinaturas PAdES
     */
    private PadesVerifier padesVerifier;
    /**
     * Componente de assinatura CAdES
     */
    private CadesSignatureComponent cadesComponent;
    public List<CertificateCollection> certificateCollection;
    public List<RevocationInformation> revocationInformation;

    /**
     * Construtor
     * @param application Uma aplicação com seus componentes
     */
    public PadesSignatureComponent(Application application) {
        super(application);
        defineRoleProvider(Signer.class.getName(), this.getSigner());
        defineRoleProvider(Verifier.class.getName(), this.getVerifier());
        cadesComponent =
                (CadesSignatureComponent) getApplication().getComponent(CadesSignatureComponent.class.getName());
    }

    /**
     * Inicia o componente
     */
    @Override
    public void startOperation() {
        // TODO Auto-generated method stub
    }

    /**
     * Limpa as informações do componente
     */
    @Override
    public void clear() {
        padesSigner = null;
        padesVerifier = null;
        certificateCollection = null;
        revocationInformation = null;
    }

    /**
     * Retorna um assinador CAdES
     * @return Um assinador CAdES
     */
    public Signer getCadesSigner() {
        return cadesSigner;
    }

    /**
     * Retorna o {@link Verifier} para assinaturas CAdES
     * @return O {@link Verifier} para assinaturas CAdES
     */
    public Verifier getCadesVerifier() {
        return cadesVerifier;
    }

    /**
     * Retorna o {@link Verifier} para assinaturas PAdES
     * @return O {@link Verifier} para assinaturas PAdES
     */
    public Verifier getVerifier() {
        if (this.padesVerifier == null) {
            this.padesVerifier = new PadesVerifier(this);
        }
        return this.padesVerifier;
    }

    /**
     * Retorna um assinador PAdES
     * @return Um assinador PAdES
     */
    public Signer getSigner() {
        if (this.padesSigner == null) {
            this.padesSigner = new PadesSigner(this);
        }
        return this.padesSigner;
    }

    /**
     * Retorna o componente de assinaturas CAdES
     * @return O componente de assinaturas CAdES
     */
    public CadesSignatureComponent getCadesSignatureComponent() {
        if (this.cadesComponent == null) {
            this.cadesComponent =
                    (CadesSignatureComponent) getApplication().getComponent(CadesSignatureComponent.class.getName());
        }
        return this.cadesComponent;
    }

    /**
     * Retorna a política de assinatura
     * @return A política de assinatura
     */
    public SignaturePolicyProxy getSignaturePolicy() {
        return (SignaturePolicyProxy) signaturePolicyInterface;
    }

}
