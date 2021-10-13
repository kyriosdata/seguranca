/*

Desenvolvido pelo Laboratório de Segurança em Computação (LabSEC) do Departamento de Informática e Estatística (INE),
da Universidade Federal de Santa Catarina (UFSC).

Apoio: Colégio Notarial do Brasil (CNB) e Instituto Nacional de Tecnologia da Informação (ITI).

 */

package br.ufsc.labsec.signature.conformanceVerifier.xades;

import java.security.InvalidAlgorithmParameterException;
import java.security.NoSuchAlgorithmException;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import javax.xml.crypto.dsig.CanonicalizationMethod;
import javax.xml.crypto.dsig.Transform;
import javax.xml.crypto.dsig.XMLSignatureFactory;
import javax.xml.crypto.dsig.spec.TransformParameterSpec;
import javax.xml.crypto.dsig.spec.XPathFilter2ParameterSpec;
import javax.xml.crypto.dsig.spec.XPathFilterParameterSpec;
import javax.xml.crypto.dsig.spec.XPathType;

import org.w3c.dom.Element;

import br.ufsc.labsec.signature.conformanceVerifier.xades.exceptions.SignatureModeException;

/**
 * Representa o modo de encapsulamento de uma assinatura.
 */
public enum SignatureModeXAdES {
    /**
     * Conteúdo destacado da assinatura.
     */
    DETACHED {
        @Override
        public boolean needSpecificDocument() {
            return false;
        }

        @Override
        public List<Transform> getTransforms(List<NodeOperation> operations) throws SignatureModeException {
            return null;
        }

        @Override
        public String getName() {
            return "Destacada";
        }

    },
    /**
     * Conteúdo é embarcado na assinatura. Esse formato existe apenas para o
     * XAdES, mas é equivalente ao Attached do CAdES.
     */
    ENVELOPING {
        @Override
        public boolean needSpecificDocument() {
            return false;
        }

        @Override
        public List<Transform> getTransforms(List<NodeOperation> operations) throws SignatureModeException {
            List<Transform> transforms = new ArrayList<Transform>();
            XMLSignatureFactory factory = XMLSignatureFactory.getInstance();
            TransformParameterSpec params = new XPathFilterParameterSpec("(//. | //@* | //namespace::*)[ancestor-or-self::object]");
            Transform transform;
            try {
                transform = factory.newTransform(CanonicalizationMethod.XPATH, params);
            } catch (NoSuchAlgorithmException noSuchAlgorithmException) {
                throw new SignatureModeException(SignatureModeException.NO_SUCH_ALGORITHM, noSuchAlgorithmException);
            } catch (InvalidAlgorithmParameterException invalidAlgorithmParameterException) {
                throw new SignatureModeException(invalidAlgorithmParameterException);
            }
            transforms.add(transform);

            return transforms;
        }

        @Override public String getName() {
            return "Anexada";
        }
    },
    /**
     * Assinatura é embarcada no documento. Esse formato existe apenas para o
     * XAdES, não tem equivalente no CAdES.
     */
    ENVELOPED {
        @Override
        public boolean needSpecificDocument() {
            return true;
        }

        @Override
        public List<Transform> getTransforms(List<NodeOperation> operations) throws SignatureModeException {
            List<Transform> transforms = new ArrayList<Transform>();
            XMLSignatureFactory factory = XMLSignatureFactory.getInstance();
            TransformParameterSpec params = new XPathFilterParameterSpec("not(ancestor-or-self::ds:Signature)");

            Transform transform;
            try {
                transform = factory.newTransform(CanonicalizationMethod.XPATH, params);
            } catch (NoSuchAlgorithmException noSuchAlgorithmException) {
                throw new SignatureModeException(SignatureModeException.NO_SUCH_ALGORITHM, noSuchAlgorithmException);
            } catch (InvalidAlgorithmParameterException invalidAlgorithmParameterException) {
                throw new SignatureModeException(invalidAlgorithmParameterException);
            }
            transforms.add(transform);

            return transforms;
        }

        @Override public String getName() {
            return "Embarcada";
        }
    },
    /**
     * Assinatura internamente destacada
     */
    INTERNALLYDETACHED {
        @Override
        public boolean needSpecificDocument() {
            return true;
        }

        @Override
        public List<Transform> getTransforms(List<NodeOperation> operations) throws SignatureModeException {
            List<Transform> transforms = new ArrayList<Transform>();
            XMLSignatureFactory factory = XMLSignatureFactory.getInstance();
            Transform transform;
            try {
                transform = factory.newTransform(Transform.ENVELOPED, (TransformParameterSpec) null);
            } catch (NoSuchAlgorithmException noSuchAlgorithmException) {
                throw new SignatureModeException(SignatureModeException.NO_SUCH_ALGORITHM, noSuchAlgorithmException);
            } catch (InvalidAlgorithmParameterException invalidAlgorithmParameterException) {
                throw new SignatureModeException(invalidAlgorithmParameterException);
            }
            transforms.add(transform);

            return transforms;
        }

        @Override public String getName() {
            return "Internamente destacada";
        }
    },
    /**
     * Contra-assinatura
     */
    COUNTERSIGNED {
        @Override
        public boolean needSpecificDocument() {

            return true;
        }

        @Override
        public List<Transform> getTransforms(List<NodeOperation> operations) throws SignatureModeException {
            return null;
        }

        @Override public String getName() {
            return "Contra-assinatura";
        }
    };

    /**
     * Informa se a assinatura exige um {@link org.w3c.dom.Document} específico.
     * @return <code> true </code> se a assinatura for do tipo
     *         <code> ENVELOPED </code> ou <code> COUNTERSIGNED </code>.
     */
    public abstract boolean needSpecificDocument();

    /**
     * Retorna as tranformações necessárias para um dado modo de assinar. Quando
     * vai se fazer uma assinatura do tipo <code>ENVELOPED</code>, precisa-se
     * saber qual é a tag que irá conter as assinaturas, para que essa seja
     * excluída da assinatura abrindo assim a possibilidade de executar
     * contra-assinaturas.
     * @param operations A lista de operações dos nodos da assinatura
     * 
     * @return A lista de transformações
     * @throws SignatureModeException
     */
    public abstract List<Transform> getTransforms(List<NodeOperation> operations) throws SignatureModeException;

    /**
     * Retorna o nome do modo de assinatura
     * @return O nome do momod de assinatura
     */
    public abstract String getName();

    /**
     * Quando o modo de assinatura for do tipo <code>COUNTERSIGNED</code>, ele
     * deve ser identificado na referência.
     * 
     * @return O modo de assinatura
     */
    public String getType() {
        String type = null;
        if (this == COUNTERSIGNED)
            type = "http://uri.etsi.org/01903#CountersignedSignature";
        return type;
    }
}
