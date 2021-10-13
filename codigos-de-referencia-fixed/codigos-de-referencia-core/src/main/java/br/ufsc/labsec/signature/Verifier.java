package br.ufsc.labsec.signature;

import java.util.List;

import br.ufsc.labsec.signature.conformanceVerifier.cms.exceptions.SignatureNotICPBrException;
import br.ufsc.labsec.signature.conformanceVerifier.report.Report;
import br.ufsc.labsec.signature.conformanceVerifier.report.Report.ReportType;
import br.ufsc.labsec.signature.conformanceVerifier.report.SignatureReport;
import br.ufsc.labsec.signature.exceptions.EncodingException;
import br.ufsc.labsec.signature.exceptions.SignatureAttributeException;
import br.ufsc.labsec.signature.exceptions.VerificationException;

public interface Verifier {

    /**
     * Define qual o arquivo que será verificado
     * @throws VerificationException 
     */
    void selectTarget(byte[] target, byte[] signedContent) throws VerificationException;

    /**
     * Informa quais as assinaturas presentes no arquivo indicado
     * 
     * @throws SignatureAttributeException
     * @throws EncodingException
     */
    List<String> getSignaturesAvailable() throws EncodingException, SignatureAttributeException;

    /**
     * Define qual a assinatura dentro do arquivo que será verificada
     */
    void selectSignature(String target);


    /**
     * Obtém o resultado da validação da assinatura selecionada
     */
    SignatureReport getValidationResult();


    /**
     * Obtém uma lista dos atributos que podem ser inseridos na assinatura
     * selecionada
     */
    List<String> getAvailableAttributes();

    /**
     * Adiciona um atributo na assinatura selecionada se for possível
     * 
     * @param attribute - Nome do atributo que deve ser inserido
     */
    boolean addAttribute(String attribute);

    /**
     * Limpa os estados do verificador para que este esteja pronto para uma nova
     * verificação
     */
    boolean clear();

    Report report(byte[] target, byte[] signedContent, ReportType type) throws VerificationException;
    
	boolean isSignature(String filePath);

	boolean needSignedContent();

	List<String> getMandatedAttributes();

	boolean supports(byte[] signature, byte[] detached) throws SignatureNotICPBrException;

}
