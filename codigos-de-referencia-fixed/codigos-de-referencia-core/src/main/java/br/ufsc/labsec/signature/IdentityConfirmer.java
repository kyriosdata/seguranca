package br.ufsc.labsec.signature;

public interface IdentityConfirmer {

	char[] confirm(String message);

	void askIdentity();

}
