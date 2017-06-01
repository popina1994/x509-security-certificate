package implementation;

public abstract class Certificatev3ExtensionAbstract {
	private boolean isCritical;

	public Certificatev3ExtensionAbstract(boolean isCritical) {
		super();
		this.isCritical = isCritical;
	}

	public boolean isCritical() {
		return isCritical;
	}
}
