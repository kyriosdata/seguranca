package br.ufsc.labsec.signature.conformanceVerifier.validationService;

import java.util.List;

import br.ufsc.labsec.component.Application;
import br.ufsc.labsec.component.Component;
import br.ufsc.labsec.component.Requirement;
import br.ufsc.labsec.signature.CertificateCollection;
import br.ufsc.labsec.signature.CertificateValidation;
import br.ufsc.labsec.signature.RevocationInformation;

/**
 * Representa um componente de repositório PKCS12.
 * Estende {@link Component}.
 */
public class ValidationServiceRepository extends Component {

    @Requirement
    public List<CertificateCollection> aditionalCertificateCollection;
    @Requirement
    public List<RevocationInformation> aditionalRevocationInformation;

    /**
     * Instância do serviço de validação
     */
    private CertificateValidationService certificateValidationService;

    /**
     * Construtor. Cria o componente PKCS12
     * @param application Uma aplicação com seus componentes
     */
    public ValidationServiceRepository(Application application) {
        super(application);

        this.defineRoleProvider(CertificateValidation.class.getName(), this.getCertificateValidationService()); //INTERFACE DELA
    }

    /**
     * Retorna o caminho do repositório
     * @return O caminho do repositório
     */
    public String getRepositoryPath() {

        return this.application.getComponentParam(this, "repositoryPath");
    }

    /**
     * Retorna a instância do serviço de validação
     * @return O serviço de validação
     */
    private CertificateValidation getCertificateValidationService() {
        if (this.certificateValidationService == null) {
            this.certificateValidationService = new CertificateValidationService(this);
        }

        return this.certificateValidationService;
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
        // TODO Auto-generated method stub

    }

    /**
     * Retorna o caminho do arquivo de cache
     * @return O caminho do arquivo de cache
     */
    public String getCachePath() {
        return this.application.getComponentParam(this, "cachePath");
    }

}
