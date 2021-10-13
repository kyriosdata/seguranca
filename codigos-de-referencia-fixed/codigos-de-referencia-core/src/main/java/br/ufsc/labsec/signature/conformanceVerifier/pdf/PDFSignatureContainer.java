package br.ufsc.labsec.signature.conformanceVerifier.pdf;

import java.io.File;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.util.logging.Level;

import br.ufsc.labsec.signature.signer.FileFormat;
import br.ufsc.labsec.signature.signer.SignerType;
import org.apache.pdfbox.io.IOUtils;
import org.apache.pdfbox.pdmodel.PDDocument;
import org.apache.pdfbox.pdmodel.interactive.digitalsignature.SignatureInterface;

import br.ufsc.labsec.signature.Signer;
import br.ufsc.labsec.component.Application;

/**
 * Esta classe representa um contêiner de assinaturas PDF.
 */
public class PDFSignatureContainer implements SignatureInterface{

	/**
	 * Componente de assinatura PDF
	 */
	private PdfSignatureComponent pdfSignatureComponent;
	/**
	 * Bytes da assiatura gerada
	 */
	private byte[] buffer;
	/**
	 * O documento assinado
	 */
	private PDDocument pdfDocument;
	/**
	 * Bytes do conteúdo assinado
	 */
	private byte[] bytes;

	/**
	 * Construtor
	 * @param pdfSignatureComponent Componente de assinatura PDF
	 * @param bytes Bytes do documento
	 * @param pdfDocument O documento assinado
	 */
	public PDFSignatureContainer(PdfSignatureComponent pdfSignatureComponent, byte[] bytes, 
			PDDocument pdfDocument) {
	
		this.pdfSignatureComponent = pdfSignatureComponent;	
		this.pdfDocument = pdfDocument;
		this.bytes = bytes;
	}

	/**
	 * Gera um Stream da assinatura
	 * @param outputStream O Stream que será preenchido com a assinatura
	 */
	public void encode(OutputStream outputStream) {
		try {
			if (bytes != null) {
				outputStream.write(this.bytes, 0, this.bytes.length);
				outputStream.flush();
			} else {
				pdfDocument.save(outputStream);
			}
		} catch (IOException e) {
			e.printStackTrace();
			Application.logger.log(Level.SEVERE,"Erro ao gerar o stream da assinatura.");
		}
		
	}

	/**
	 * Realiza uma assinatura destacada
	 * @param target Stream do conteúdo a ser assinado
	 * @return Os bytes da assinatura
	 * @throws IOException Exceção em caso de erro nos bytes da assinatura
	 */
	@Override
	public byte[] sign(InputStream target) throws IOException {

		Signer signer = this.pdfSignatureComponent.cmsSigner;
		signer.selectTarget(target, SignerType.CMS_STR);
		signer.setMode(FileFormat.DETACHED, null);

		if (signer.sign()) {
			InputStream signatureStream = signer.getSignatureStream();
			this.buffer = IOUtils.toByteArray(signatureStream);

		}
		return this.buffer;
	}
}
