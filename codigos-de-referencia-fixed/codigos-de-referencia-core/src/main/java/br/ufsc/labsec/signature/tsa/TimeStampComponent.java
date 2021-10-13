package br.ufsc.labsec.signature.tsa;

import br.ufsc.labsec.component.Application;
import br.ufsc.labsec.component.Component;

/**
 * Esta classe representa um componente de carimbo de tempo
 */
public class TimeStampComponent extends Component {

	/**
	 * Carimbo de tempo
	 */
    private TimeStamp timeStamp;
	
	public TimeStampComponent(Application application) {
		super(application);
		this.defineRoleProvider(TimeStamp.class.getName(), this.getTimeStamp());
	}

	@Override
	public void startOperation() {
		// TODO Auto-generated method stub
	}

	@Override
	public void clear() {
		// TODO Auto-generated method stub
	}

	/**
	 * Retorna o carimbo de tempo
	 * @return O carimbo de tempo
	 */
	public TimeStamp getTimeStamp() {
		if(this.timeStamp == null) {
			this.timeStamp = new TimeStampProvider(this);
		}
		return this.timeStamp;
	}

}
