/*

Desenvolvido pelo Laboratório de Segurança em Computação (LabSEC) do Departamento de Informática e Estatística (INE),
da Universidade Federal de Santa Catarina (UFSC).

Apoio: Colégio Notarial do Brasil (CNB) e Instituto Nacional de Tecnologia da Informação (ITI).

 */

package br.ufsc.labsec.signature.conformanceVerifier.cades.attributes;

import br.ufsc.labsec.signature.conformanceVerifier.cades.attributes.unsigned.IdCounterSignature;
import br.ufsc.labsec.signature.conformanceVerifier.xades.attributes.unsigned.CounterSignature;

/**
 * Interface usada para definir métodos comuns entre as classes que a
 * implementam: {@link IdCounterSignature} e {@link CounterSignature}
 */
public interface CounterSignatureInterface extends SignatureAttribute {
}
