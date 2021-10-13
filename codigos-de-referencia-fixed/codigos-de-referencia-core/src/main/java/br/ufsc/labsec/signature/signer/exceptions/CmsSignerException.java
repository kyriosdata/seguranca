package br.ufsc.labsec.signature.signer.exceptions;

import org.bouncycastle.cms.CMSException;

public class CmsSignerException extends CMSException {

    public CmsSignerException(String message) {
        super(message);
    }
}
