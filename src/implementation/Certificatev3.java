package implementation;

public class Certificatev3 {
	private int version;
	private CertificateSubject certificateSubject;
	private String serialNumber;
	private String issuer;
	private CertificateValidity certificateValidity;
	private CertificatePublicKey certificatePublicKey;
	private Certificatev3Extension certificateV3Extension;
	public Certificatev3(int version, CertificateSubject certificateSubject, String serialNumber,
			CertificateValidity certificateValidity, CertificatePublicKey certificatePublicKey,
			Certificatev3Extension certificateV3Extension) {
		super();
		this.version = version;
		this.certificateSubject = certificateSubject;
		this.serialNumber = serialNumber;
		this.certificateValidity = certificateValidity;
		this.certificatePublicKey = certificatePublicKey;
		this.certificateV3Extension = certificateV3Extension;
	}
	public int getVersion() {
		return version;
	}
	public CertificateSubject getCertificateSubject() {
		return certificateSubject;
	}
	public String getSerialNumber() {
		return serialNumber;
	}
	public CertificateValidity getCertificateValidity() {
		return certificateValidity;
	}
	public CertificatePublicKey getCertificatePublicKey() {
		return certificatePublicKey;
	}
	public Certificatev3Extension getCertificateV3Extension() {
		return certificateV3Extension;
	}
	
	
}
