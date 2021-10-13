/*

Desenvolvido pelo Laboratório de Segurança em Computação (LabSEC) do Departamento de Informática e Estatística (INE),
da Universidade Federal de Santa Catarina (UFSC).

Apoio: Colégio Notarial do Brasil (CNB) e Instituto Nacional de Tecnologia da Informação (ITI).

 */

package br.ufsc.labsec.signature;

import br.ufsc.labsec.signature.conformanceVerifier.xades.XadesContentToBeSigned;
import br.ufsc.labsec.signature.conformanceVerifier.cades.CadesContentToBeSigned;

/**
 * Representa o conteúdo a ser assinado. Esta interface é estendida pelas
 * classes {@link XadesContentToBeSigned} e {@link CadesContentToBeSigned}.
 */
public interface ContentToBeSigned {
}
