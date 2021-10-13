package br.ufsc.labsec.component;

import java.lang.annotation.Retention;
import java.lang.annotation.RetentionPolicy;

/**
 * Anotação utilizada para que o componente informe quais os serviços
 * necessários para a sua operação
 */
@Retention(RetentionPolicy.RUNTIME)
public @interface Requirement {
	boolean optional() default false;
}
