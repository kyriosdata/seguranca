package br.ufsc.labsec.signature.conformanceVerifier.xades;

import java.io.File;
import java.util.logging.Level;

import br.ufsc.labsec.component.Application;
import br.ufsc.labsec.signature.CoSigner;
import br.ufsc.labsec.signature.conformanceVerifier.xades.exceptions.SignatureModeException;
import br.ufsc.labsec.signature.conformanceVerifier.xades.exceptions.XadesSignatureContainerException;
import br.ufsc.labsec.signature.signer.FileFormat;

/**
 * Esta classe adiciona uma co-assinatura XAdES a um documento.
 * Estende {@link XadesSigner} e implementa {@link CoSigner}.
 */
public class XadesCoSigner extends XadesSigner implements CoSigner {

	/**
	 * Construtor
	 * @param xadesSignatureComponent Componente de assinatura XAdES
	 */
	public XadesCoSigner(XadesSignatureComponent xadesSignatureComponent) {
		super(xadesSignatureComponent);
	}

	/**
	 * Verifica se o documento pode ser co-assinado
	 * @param signatureAdress O endereço do arquivo de assinatura
	 * @return Indica se o documento pode ser co-assinado
	 */
	@Override
	public boolean canCoSign(String signatureAdress) {
		
		boolean ret = false;
		
		try {
			XadesSignatureContainer sig = new XadesSignatureContainer(new File(signatureAdress));
			
			ContainedSignatureMode modeToTest = sig.getMode(0);
			
			if(modeToTest.equals(ContainedSignatureMode.ENVELOPED)) ret = true;
			
		} catch (XadesSignatureContainerException | SignatureModeException e) {
			Application.logger.log(Level.FINE, "Não foi possível testar o modo da assinatura,", e);
		}
		
		return ret;
	}

	/**
	 * Inicializa o gerador de contêiner de assinatura
	 * @param signatureAdress O endereço do arquivo de assinatura
	 * @param contentPath O endereço do conteúdo assinado
	 * @param policyOid O OID da política usada
	 */
	@Override
	public void selectTarget(String signatureAdress, String contentPath, String policyOid) {
		super.selectTarget(signatureAdress, policyOid);
	}

	/**
	 * Realiza a co-assinatura
	 * @return Indica se a co-assinatura foi realizada com sucesso
	 */
	@Override
	public boolean coSign() {
		super.setMode(FileFormat.ENVELOPED, null);
		
		return super.sign();
	}


}
