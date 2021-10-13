package br.ufsc.labsec.signature.conformanceVerifier.pdf;

import java.io.IOException;
import java.io.InputStream;
import java.io.FileInputStream;
import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.FileNotFoundException;

import org.apache.pdfbox.cos.COSName;
import org.apache.pdfbox.pdmodel.PDDocument;
import org.apache.pdfbox.pdmodel.interactive.digitalsignature.PDSignature;

/**
 * Esta classe gera contêineres de assinaturas no formato PDF.
 */
public class SignatureContainerGenerator {

	/**
	 * Componente de assinatura PDF
	 */
	private PdfSignatureComponent pdfSignatureComponent;
	/**
	 * Endereço do documento assinado
	 */
	private String target;

	/**
	 * Construtor
	 * @param pdfSignatureComponent Componente de assinatura PDF
	 * @param target Endereço do documento assinado
	 */
	public SignatureContainerGenerator(PdfSignatureComponent pdfSignatureComponent, String target) {
		this.pdfSignatureComponent = pdfSignatureComponent;
		this.target = target;
	}

	/**
	 * Gera o contêiner de assinatura PDF
	 * @return O contêiner de assinatura PDF
	 */
	public PDFSignatureContainer generate() {
		PDDocument pdfDocument = null;
		InputStream is1 = null;
		byte[] bytes = null;
		InputStream contentForPDF = null;
		
		try {
			is1 = new FileInputStream(this.target);
		} catch (FileNotFoundException e) {
			e.printStackTrace();
		} 
		
		
		try {
			ByteArrayOutputStream baos = new ByteArrayOutputStream();
			byte[] buf = new byte[1024];
			int n = 0;
			
			while ((n = is1.read(buf)) >= 0) {
				baos.write(buf, 0, n);
			}
			bytes = baos.toByteArray();
			contentForPDF = new ByteArrayInputStream(bytes);
			
		} catch (IOException e1) {
			e1.printStackTrace();
		}
		
		try {
			pdfDocument = PDDocumentUtils.openPDDocument(contentForPDF);
		} catch (IOException e1) {
			e1.printStackTrace();
		}
		
		
		PDSignature dicSignature = new PDSignature();
		dicSignature.setType(COSName.getPDFName("Sig"));

		
		
		PDFSignatureContainer container = new PDFSignatureContainer(this.pdfSignatureComponent, bytes, pdfDocument);
		
		try {
			pdfDocument.addSignature(dicSignature, container);
			pdfDocument.close();
		} catch (IOException e) {
			e.printStackTrace();
		}

		return container;
	}
	
}
