/*

Desenvolvido pelo Laboratório de Segurança em Computação (LabSEC) do Departamento de Informática e Estatística (INE),
da Universidade Federal de Santa Catarina (UFSC).

Apoio: Colégio Notarial do Brasil (CNB) e Instituto Nacional de Tecnologia da Informação (ITI).

 */

package br.ufsc.labsec.signature.conformanceVerifier.cades;

import java.util.List;

import br.ufsc.labsec.signature.ContentToBeSigned;
import br.ufsc.labsec.signature.Signer;
import br.ufsc.labsec.signature.conformanceVerifier.cades.attributes.SignatureAttribute;
import br.ufsc.labsec.signature.conformanceVerifier.xades.exceptions.AlgorithmException;
import br.ufsc.labsec.signature.conformanceVerifier.xades.exceptions.ToBeSignedException;
import br.ufsc.labsec.signature.exceptions.EncodingException;
import br.ufsc.labsec.signature.exceptions.PbadException;
import br.ufsc.labsec.signature.exceptions.SignatureAttributeException;

/**
 * Esta interface é implementada pela classe {@link CadesContainerGenerator}.
 * Não deve ser utilizada pelo usuário.
 */
public interface ContainerGenerator {

    /**
     * Determina o conteúdo que será assinado
     * @param contentsToBeSigned O conteúdo para assinatura
     */
    public void setContentsToBeSigned(List<ContentToBeSigned> contentsToBeSigned);

    /**
     * Determina quais atributos serão usados no processo de assinatura
     * @param attributeList	Lista de atributos a serem inseridos na assinatura
     * @throws SignatureAttributeException
     */
    public void setAttributes(List<SignatureAttribute> attributeList) throws SignatureAttributeException;

    /**
     * Gera a assinatura a partir dos atributos e conteúdos informados
     * @return Um contêiner de assinatura que contém a assinatura gerada
     */
    public SignatureContainer generate();

    /**
     * Seleciona o assinante que será usado no processo de assinatura
     * @param signer Os dados do assinante
     */
    public void setSigner(SignerData signer);

}
