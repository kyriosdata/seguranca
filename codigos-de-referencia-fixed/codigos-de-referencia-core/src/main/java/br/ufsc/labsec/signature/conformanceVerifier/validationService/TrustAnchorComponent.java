package br.ufsc.labsec.signature.conformanceVerifier.validationService;

import br.ufsc.labsec.component.Application;
import br.ufsc.labsec.component.Component;

/**
 * Representa um componente de uma âncora de confiança.
 * Estende {@link Component}.
 */
public class TrustAnchorComponent extends Component {

    /**
     * Âncoras de confiança
     */
    private TrustAnchorProxy trustAnchor;

    /**
     * Construtor
     * @param application Uma aplicação com seus componentes
     */
    public TrustAnchorComponent(Application application) {
        super(application);
        this.defineRoleProvider(TrustAnchorInterface.class.getName(), this.getTrustAnchorProxy());
    }

    /**
     * Retorna a instância de {@link TrustAnchorProxy}
     * @return A instância de {@link TrustAnchorProxy}
     */
    public TrustAnchorProxy getTrustAnchorProxy() {
        if (this.trustAnchor == null) {
            this.trustAnchor = new TrustAnchorProxy(this);
        }

        return this.trustAnchor;
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
        this.trustAnchor = null;
    }

}
