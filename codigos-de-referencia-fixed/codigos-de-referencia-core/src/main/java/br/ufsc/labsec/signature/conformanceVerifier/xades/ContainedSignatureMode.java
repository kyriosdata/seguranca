/*

Desenvolvido pelo Laboratório de Segurança em Computação (LabSEC) do Departamento de Informática e Estatística (INE),
da Universidade Federal de Santa Catarina (UFSC).

Apoio: Colégio Notarial do Brasil (CNB) e Instituto Nacional de Tecnologia da Informação (ITI).

 */

package br.ufsc.labsec.signature.conformanceVerifier.xades;

/**
 * Contém os modos de assinaturas existentes
 */
public enum ContainedSignatureMode {
    DETACHED, ATTACHED, ENVELOPING, ENVELOPED, DETACHED_ENVELOPED, DETACHED_ENVELOPING, ENVELOPING_ENVELOPED, DETACHED_ENVELOPING_ENVELOPED
}
