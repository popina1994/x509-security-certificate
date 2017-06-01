package implementation;

public class CertificatePublicKey {
	private String publicKeyAlgorithm;
	private int publicKeyLength;
	public CertificatePublicKey(String publicKeyAlgorithm, int publicKeyLength) {
		super();
		this.publicKeyAlgorithm = publicKeyAlgorithm;
		this.publicKeyLength = publicKeyLength;
	}
	public String getPublicKeyAlgorithm() {
		return publicKeyAlgorithm;
	}
	public int getPublicKeyLength() {
		return publicKeyLength;
	}
}
