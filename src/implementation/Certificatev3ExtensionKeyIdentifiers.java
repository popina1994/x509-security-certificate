package implementation;

public class Certificatev3ExtensionKeyIdentifiers extends Certificatev3ExtensionAbstract{
	private boolean isKeyIdentifierEnabled;

	public Certificatev3ExtensionKeyIdentifiers(boolean isCritical, boolean isKeyIdentifierEnabled) {
		super(isCritical);
		this.isKeyIdentifierEnabled = isKeyIdentifierEnabled;
	}


	public boolean isKeyIdentifierEnabled() {
		return isKeyIdentifierEnabled;
	}
	
	

}
