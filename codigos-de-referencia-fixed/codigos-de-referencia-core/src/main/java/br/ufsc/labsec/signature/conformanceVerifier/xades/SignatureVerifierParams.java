/*

Desenvolvido pelo Laboratório de Segurança em Computação (LabSEC) do Departamento de Informática e Estatística (INE),
da Universidade Federal de Santa Catarina (UFSC).

Apoio: Colégio Notarial do Brasil (CNB) e Instituto Nacional de Tecnologia da Informação (ITI).

 */

package br.ufsc.labsec.signature.conformanceVerifier.xades;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import br.ufsc.labsec.signature.conformanceVerifier.xades.attributes.unsigned.ArchiveTimeStamp;
import br.ufsc.labsec.signature.conformanceVerifier.xades.attributes.unsigned.SigAndRefsTimeStamp;
import br.ufsc.labsec.signature.conformanceVerifier.xades.attributes.unsigned.SignatureTimeStamp;

/**
 * Esta classe carrega os parâmetros da classe {@link SignatureVerifier}. Tais
 * parâmetros permitem definir qual a ordem em que os carimbos devem ser
 * validados para que a inferência de tempo do validador funcione corretamente.
 * <p>
 * 
 * Define também quais são os atributos obrigatórios para os carimbos do tempo.
 */
public class SignatureVerifierParams {

    /**
     * Lista ordenada que indica a prioridade dos carimbos de tempo para a verificação
     */
    private List<String> timeStampPriorityList;
    /**
     * Mapeamento entre identificadores de carimbos e uma lista de seus atributos não-assinados
     */
    private Map<String, List<String>> timeStampMandatedUnsignedAttributes;
    /**
     * Mapeamento entre identificadores de carimbos e uma lista de seus atributos assinados
     */
    private Map<String, List<String>> timeStampMandatedSignedAttributes;

    /**
     * Instancia a classe de parâmetros de verificação da assinatura.<br>
     * A lista de prioridades dos carimbos do tempo é opcional e se não passada
     * será adotada uma lista padrão que segue o DOC-ICP-15-03 versão 2.0.<br>
     * Quando esse construtor é usado as listas padrão de atributos obrigatórios
     * dos carimbos do tempo não serão criadas
     */
    public SignatureVerifierParams() {
        this.makeDefaultList();
        this.timeStampMandatedSignedAttributes = new HashMap<String, List<String>>();
        this.timeStampMandatedUnsignedAttributes = new HashMap<String, List<String>>();
    }

    /**
     * Instancia a classe de parâmetros de verificação da assinatura.<br>
     * A lista de prioridades dos carimbos do tempo é opcional e se não passada
     * será adotada uma lista padrão que segue o DOC-ICP-15-03 versão 2.0.<br>
     * Quando esse construtor é usado as listas padrão de atributos obrigatórios
     * dos carimbos do tempo não serão criadas
     * 
     * @param timeStampPriorityList A lista de prioridades de verificação dos
     *            carimbos do tempo
     */
    public SignatureVerifierParams(List<String> timeStampPriorityList) {
        if (timeStampPriorityList != null) {
            this.timeStampPriorityList = new ArrayList<String>(timeStampPriorityList);
        } else {
            this.makeDefaultList();
        }
        this.timeStampMandatedSignedAttributes = new HashMap<String, List<String>>();
        this.timeStampMandatedUnsignedAttributes = new HashMap<String, List<String>>();
    }

    /**
     * Instancia a classe de parâmetros de verificação da assinatura.<br>
     * Quando esse construtor é usado, as listas padrão de atributos
     * obrigatórios dos carimbos do tempo são definidas através dos parâmetros
     * <code>timeStampMandatedSignedAttributes</code> e
     * <code>timeStampMandatedUnsignedAttributes</code>
     * 
     * @param timeStampPriorityList Lista de prioridades de verificação dos
     *            carimbos do tempo
     * @param timeStampMandatedSignedAttributes Atributos assinados obrigatórios
     *            do carimbo do tempo
     * @param timeStampMandatedUnsignedAttributes Atributos não-assinados
     *            obrigatórios do carimbo do tempo
     */
    public SignatureVerifierParams(List<String> timeStampPriorityList, Map<String, List<String>> timeStampMandatedSignedAttributes,
            Map<String, List<String>> timeStampMandatedUnsignedAttributes) {
        this(timeStampPriorityList);
        this.timeStampMandatedSignedAttributes.putAll(timeStampMandatedSignedAttributes);
        this.timeStampMandatedUnsignedAttributes.putAll(timeStampMandatedUnsignedAttributes);
    }

    /**
     * Instancia a lista padrão de prioridades de carimbos do tempo
     */
    private void makeDefaultList() {
        this.timeStampPriorityList = new ArrayList<String>();
        this.timeStampPriorityList.add(ArchiveTimeStamp.IDENTIFIER);
        this.timeStampPriorityList.add(SigAndRefsTimeStamp.IDENTIFIER);
        this.timeStampPriorityList.add(SignatureTimeStamp.IDENTIFIER);
    }

    /**
     * Define os atributos obrigatórios assinados para um tipo de carimbo do
     * tempo
     * 
     * @param timeStamp O identificador do carimbo do tempo
     * @param mandatedAttributes A lista de atributos obrigatórios assinados
     *            para o tipo do carimbo do tempo indicado
     */
    public void setTimeStampMandatedSignedAttributes(String timeStamp, List<String> mandatedAttributes) {
        this.timeStampMandatedSignedAttributes.put(timeStamp, new ArrayList<String>(mandatedAttributes));
    }

    /**
     * Define os atributos obrigatórios não assinados para um tipo de carimbo do
     * tempo
     * 
     * @param timeStamp O identificador do carimbo do tempo
     * @param mandatedAttributes A lista de atributos obrigatórios não assinados
     *            para o tipo do carimbo do tempo indicado
     */
    public void setTimeStampMandatedUnsignedAttributes(String timeStamp, List<String> mandatedAttributes) {
        this.timeStampMandatedUnsignedAttributes.put(timeStamp, new ArrayList<String>(mandatedAttributes));
    }

    /**
     * Retorna a lista de prioridades de carimbos do tempo atual
     * 
     * @return A lista de prioridades de carimbos do tempo atual
     */
    public List<String> getTimeStampPriorityList() {
        return new ArrayList<String>(this.timeStampPriorityList);
    }

    /**
     * Retorna a lista de atributos obrigatórios assinados para o carimbo do
     * tempo indicado. Caso não tenha sido atribuida uma lista de atributos, a
     * lista retornada será vazia
     * 
     * @param timeStamp O identificador do carimbo do tempo
     * @return A lista de atributos obrigatórios assinados do carimbo dado
     */
    public List<String> getTimestampMandatedSignedAttributes(String timeStamp) {
        List<String> mandatedAttributes = this.timeStampMandatedSignedAttributes.get(timeStamp);
        List<String> result = new ArrayList<String>();
        if (mandatedAttributes != null) {
            result.addAll(mandatedAttributes);
        }
        return result;
    }

    /**
     * Retorna a lista de atributos obrigatórios não assinados para o carimbo do
     * tempo indicado. Caso não tenha sido atribuida uma lista de atributos, a
     * lista retornada será vazia
     *
     * @param timeStamp O identificador do carimbo do tempo
     * @return A lista de atributos obrigatórios assinados do carimbo dado
     */
    public List<String> getTimestampMandatedUnsignedAttributes(String timeStamp) {
        List<String> mandatedAttributes = this.timeStampMandatedUnsignedAttributes.get(timeStamp);
        List<String> result = new ArrayList<String>();
        if (mandatedAttributes != null) {
            result.addAll(mandatedAttributes);
        }
        return result;
    }
}
