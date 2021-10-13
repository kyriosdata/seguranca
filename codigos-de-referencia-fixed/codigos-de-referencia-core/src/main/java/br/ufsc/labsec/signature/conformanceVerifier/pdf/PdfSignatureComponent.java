package br.ufsc.labsec.signature.conformanceVerifier.pdf;

import br.ufsc.labsec.component.Application;
import br.ufsc.labsec.component.Component;
import br.ufsc.labsec.component.Requirement;
import br.ufsc.labsec.signature.IOService;
import br.ufsc.labsec.signature.Signer;
import br.ufsc.labsec.signature.signer.signatureSwitch.PdfSigner;

/**
 * Representa um componente de assinatura PDF.
 * Estende {@link Component}.
 */
public class PdfSignatureComponent extends Component {

	@Requirement (optional = true)
	public Signer cmsSigner;
    @Requirement (optional = true)
    public IOService ioService;

	/**
	 * Um {@link Signer} para assinaturas PDF
	 */
	private Signer pdfSigner;

	/**
	 * Construtor
	 * @param application Uma aplicação com seus componentes
	 */
	public PdfSignatureComponent(Application application) {
		super(application);
		this.defineRoleProvider(Signer.class.getName(), this.getSigner());
	}

	/**
	 * Retorna um assinador PDF
	 * @return Um assinador PDF
	 */
	private Signer getSigner() {
		if(this.pdfSigner == null){
			this.pdfSigner = new PdfSigner(this);
		}
		return this.pdfSigner;
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
