package br.ufsc.labsec.signature.tsa;

import java.sql.Time;
import java.util.List;

import br.ufsc.labsec.signature.AttributeParams;
import br.ufsc.labsec.signature.SignaturePolicyInterface;
import br.ufsc.labsec.signature.conformanceVerifier.cades.attributes.TimeStampVerifier;
import br.ufsc.labsec.signature.conformanceVerifier.report.SignatureReport;
import br.ufsc.labsec.signature.conformanceVerifier.report.TimeStampReport;
import br.ufsc.labsec.signature.exceptions.AIAException;
import br.ufsc.labsec.signature.exceptions.NotInICPException;

public interface TimeStampVerifierInterface {
    
    /**
     * Inicializa um {@link TimeStampVerifier}
     * 
     * @param timeStamp Carimbo a ser verificado
     * @param timeStampIdentifier Identificador do carimbo do tempo
     * @param policyInterface A política de assinatura
     * @param timeReference Referencia do tempo de validação
     * @param oidStamps Identificadores dos carimbos na assinatura
     * @param isLast Indica se é o último carimbo a ser verificado
     * @return Indica se a atribuição ocorreu com sucesso
     */
    
    boolean setTimeStamp(byte[] timeStamp, String timeStampIdentifier, SignaturePolicyInterface policyInterface,
                         Time timeReference, List<String> oidStamps, boolean isLast);

    /**
     * Valida os atributos do carimbo do tempo.
     * @param report O arquivo a ser validade.
     * @return Indica se o carimbo é válido
     */
    boolean verify(SignatureReport report) throws NotInICPException;

    /**
     * Retorna a lista dos erros que ocorreram na última validação.
     * @return A lista de erros
     */
    List<Exception> getValidationErrors();

    
    /**
     * @param attributeId - identificador do atributo 
     * @param params - parâmetros do atributo
     */
    void addAttribute(String attributeId, AttributeParams params);

    
    /**
     * @param attributeId - identificador do atributo 
     * @param index - posição na assinatura do atributo a ser retirado
     */
    void removeAttribute(String attributeId, int index);

    /**
     * Adicionar os dados de validação dos atributos no repositório antes de validar a assinatura
	 * @param report - A estrutura de report para inserção dos dados de validação. 
     */
    void setupValidationData(TimeStampReport report) throws AIAException;

    Time getTimeStampGenerationTime();

}
