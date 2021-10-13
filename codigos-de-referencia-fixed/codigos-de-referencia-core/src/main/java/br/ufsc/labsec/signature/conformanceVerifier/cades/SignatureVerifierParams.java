/*

Desenvolvido pelo Laboratório de Segurança em Computação (LabSEC) do Departamento de Informática e Estatística (INE),
da Universidade Federal de Santa Catarina (UFSC).

Apoio: Colégio Notarial do Brasil (CNB) e Instituto Nacional de Tecnologia da Informação (ITI).

 */

package br.ufsc.labsec.signature.conformanceVerifier.cades;

import br.ufsc.labsec.signature.conformanceVerifier.cades.attributes.unsigned.IdAaEtsArchiveTimeStampV2;
import br.ufsc.labsec.signature.conformanceVerifier.cades.attributes.unsigned.IdAaEtsEscTimeStamp;
import br.ufsc.labsec.signature.conformanceVerifier.cades.attributes.unsigned.IdAaSignatureTimeStampToken;

import java.util.ArrayList;
import java.util.List;

/**
 * Esta classe carrega os parâmetros da classe {@link SignatureVerifier}.
 * Tais parâmetros permitem definir qual a ordem em que os carimbos devem ser
 * validados para que a inferência de tempo do validador funcione corretamente.
 * 
 * Define também quais são os atributos obrigatórios para os carimbos do tempo.
 */
public class SignatureVerifierParams {

    /**
     * Lista ordenada que indica a prioridade dos carimbos de tempo para a verificação
     */
    private List<String> timeStampPriorityList;

    /**
     * Instancia a classe de parâmetros de verificação da assinatura.<br>
     * A lista de prioridades dos carimbos do tempo é opcional e se não passada
     * será adotada uma lista padrão que segue o DOC-ICP-15-03 versão 2.0.<br>
     * Quando esse construtor é usado as listas padrão de atributos obrigatórios
     * dos carimbos do tempo não serão criadas
     */
    SignatureVerifierParams() {
        this.timeStampPriorityList = new ArrayList<>();
        this.timeStampPriorityList.add(IdAaEtsArchiveTimeStampV2.IDENTIFIER);
        this.timeStampPriorityList.add(IdAaEtsEscTimeStamp.IDENTIFIER);
        this.timeStampPriorityList.add(IdAaSignatureTimeStampToken.IDENTIFIER);
    }

    /**
     * Retorna a lista de prioridades de carimbos do tempo atual
     * @return A lista de prioridades de carimbos do tempo atual
     */
    public List<String> getTimeStampPriorityList() {
        return new ArrayList<>(this.timeStampPriorityList);
    }

}
