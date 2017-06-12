package implementation;

import java.util.Date;

public class CertificateValidity {
	private Date notBefore;
	private Date notAfter;
	
	public CertificateValidity(Date notBefore, Date notAfter) {
		super();
		this.notBefore = notBefore;
		this.notAfter = notAfter;
	}
	public Date getNotBefore() {
		return notBefore;
	}
	public Date getNotAfter() {
		return notAfter;
	}
	
	
	
	
}
