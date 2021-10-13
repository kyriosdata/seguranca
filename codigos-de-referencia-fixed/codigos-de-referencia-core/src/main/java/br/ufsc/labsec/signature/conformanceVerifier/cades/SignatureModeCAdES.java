/*

Desenvolvido pelo Laboratório de Segurança em Computação (LabSEC) do Departamento de Informática e Estatística (INE),
da Universidade Federal de Santa Catarina (UFSC).

Apoio: Colégio Notarial do Brasil (CNB) e Instituto Nacional de Tecnologia da Informação (ITI).

 */

package br.ufsc.labsec.signature.conformanceVerifier.cades;


/**
 * Esta classe representa o modo de encapsulamento de uma assinatura
 */
public enum SignatureModeCAdES {
    /**
     * Conteúdo destacado da assinatura
     */
    DETACHED {
    },
    /**
     * Contra-assinatura
     */
    COUNTERSIGNED {
    },
    /**
     * Conteúdo é embarcado na assinatura. Esse formato existe apenas para o
     * CAdES, mas é equivalente ao Enveloping do XAdES.
     */
    ATTACHED {
    }


}
