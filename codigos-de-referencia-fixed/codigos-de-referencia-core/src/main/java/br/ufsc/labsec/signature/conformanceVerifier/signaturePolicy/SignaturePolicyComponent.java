package br.ufsc.labsec.signature.conformanceVerifier.signaturePolicy;

import br.ufsc.labsec.component.Application;
import br.ufsc.labsec.component.Component;
import br.ufsc.labsec.component.Requirement;
import br.ufsc.labsec.signature.SignaturePolicyInterface;
import br.ufsc.labsec.signature.conformanceVerifier.validationService.TrustAnchorInterface;

/**
 * Esta classe representa um componente de política de assinatura
 */
public class SignaturePolicyComponent extends Component {

    /**
     * Política de assinatura
     */
    private SignaturePolicyProxy signaturePolicy;
    @Requirement
    public TrustAnchorInterface trustAnchorInterface;

    /**
     * Construtor
     * @param application Uma aplicação com seus componentes
     */
    public SignaturePolicyComponent(Application application) {
        super(application);
        this.defineRoleProvider(SignaturePolicyInterface.class.getName(), this.getSignaturePolicy());
    }

    /**
     * Retorna a política de assinatura
     * @return A política de assinatura
     */
    public SignaturePolicyProxy getSignaturePolicy() {
        if (this.signaturePolicy == null) {
            this.signaturePolicy = new SignaturePolicyProxy(this);
        }

        return this.signaturePolicy;
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
        this.signaturePolicy = null;
    }

}
