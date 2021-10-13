/*

Desenvolvido pelo Laboratório de Segurança em Computação (LabSEC) do Departamento de Informática e Estatística (INE),
da Universidade Federal de Santa Catarina (UFSC).

Apoio: Colégio Notarial do Brasil (CNB) e Instituto Nacional de Tecnologia da Informação (ITI).

 */

package br.ufsc.labsec.signature.conformanceVerifier.cades;

import org.bouncycastle.cms.CMSSignedData;
import org.bouncycastle.cms.SignerInformation;

import br.ufsc.labsec.signature.conformanceVerifier.cades.SignatureContainer;

/**
 * Esta interface representa uma referência para um contêiner ou uma assinatura superior
 */
public interface CmsParent {

    /**
     * Substitui o primeiro assinante que tiver o mesmo identificador do
     * assinante passado como parâmetro.
     * Esse método deve ser usado quando uma contra-assinatura sofre alguma
     * alteração (por exemplo: adição de um novo atributo não assinado), assim a
     * assinatura que contém a contra-assinatura deverá utilizar este método.
     * @param signerToReplace O assinante a ser substituído
     */
    void replaceChildSignature(SignerInformation signerToReplace);

    /**
     * Retorna o conteúdo assinado
     * @return O conteúdo assinado
     */
    CMSSignedData getSignedData();

    /**
     * Retorna o conteúdo a ser assinado
     * @return O conteúdo a ser assinado
     */
    byte[] getContentToBeSigned();

    /**
     * Retorna o contêiner da assinatura
     * @return O contêiner da assinatura
     */
    SignatureContainer getContainer();
}
