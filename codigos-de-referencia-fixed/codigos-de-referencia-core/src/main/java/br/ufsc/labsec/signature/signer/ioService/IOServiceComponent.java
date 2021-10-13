package br.ufsc.labsec.signature.signer.ioService;

import br.ufsc.labsec.component.Application;
import br.ufsc.labsec.component.Component;
import br.ufsc.labsec.signature.IOService;

public class IOServiceComponent extends Component {


    private IOService ioService;
	
	public IOServiceComponent(Application application) {
		super(application);
		this.defineRoleProvider(IOService.class.getName(), this.getIOService());
	}

	@Override
	public void startOperation() {
		// TODO Auto-generated method stub

	}

	@Override
	public void clear() {
		// TODO Auto-generated method stub

	}
	
	public IOService getIOService() {
		if(this.ioService == null) {
			this.ioService = new IOServiceImp();
		}
		return this.ioService;
	}

}
