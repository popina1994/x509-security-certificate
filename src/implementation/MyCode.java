package implementation;

import java.io.File;
import java.util.Date;
import java.util.Enumeration;
import java.util.LinkedHashMap;
import java.util.List;

import javax.swing.SpringLayout.Constraints;

import org.bouncycastle.operator.ContentSigner;

import code.GuiException;
import gui.Constants;
import x509.v3.CodeV3;
import x509.v3.GuiV3;

public class MyCode extends CodeV3 {
	private static MyKeyStore myKeyStore = new MyKeyStore();
	private static final int IDX_ISSUER_ALTERNATIVE_NAME = 6;
	
	public MyCode(boolean[] algorithm_conf, boolean[] extensions_conf) throws GuiException {
		super(algorithm_conf, extensions_conf);
		// TODO Auto-generated constructor stub
	}

	@Override
	public boolean exportCertificate(File arg0, int arg1) {
		// TODO Auto-generated method stub
		return false;
	}

	@Override
	public boolean exportKeypair(String alias, String file, String password) {
		
		return myKeyStore.exportKeypair(alias, file, password);
	}

	@Override
	public boolean generateCSR(String keypairName) {
		return myKeyStore.generateCSR(keypairName);
	}

	@Override
	public String getIssuer(String issuerAlias) {
		// TODO Auto-generated method stub
		return myKeyStore.getIssuer(issuerAlias);
	}

	@Override
	public String getIssuerPublicKeyAlgorithm(String issuerAlias) {
		// TODO Auto-generated method stub
		return myKeyStore.getIssuerPublicKeyAlgorithm(issuerAlias);
	}

	@Override
	public List<String> getIssuers(String keypairName) {
		return myKeyStore.getIssuers(keypairName);
	}

	@Override
	public int getRSAKeyLength(String alias) {
		Certificatev3 certificatev3 = myKeyStore.loadKeyPair(alias);
		if (certificatev3 == null)
		{
			return 0;
		}
		return certificatev3.getCertificatePublicKey().getPublicKeyLength();
	}

	@Override
	public boolean importCertificate(File arg0, String arg1) {
		// TODO Auto-generated method stub
		return false;
	}

	@Override
	public boolean importKeypair(String alias, String file, String password) {
		// TODO Auto-generated method stub
		return myKeyStore.importKeyPair(alias, file, password);
	}

	private static final int ERROR_CODE_LOAD_KEY_PAIR = -1;
	private static final int NOT_SIGNED_CODE_LOAD_KEY_PAIR = 0;
	private static final int SIGNED_CODE_LOAD_KEY_PAIR = 1;
	private static final int TRUSTED_CODE_LOAD_KEY_PAIR = 2;
	
	@Override
	public int loadKeypair(String alias) {
		Certificatev3 certificate = myKeyStore.loadKeyPair(alias);
		if (certificate == null)
		{
			return ERROR_CODE_LOAD_KEY_PAIR;
		}
		access.setSubjectCountry(certificate.getCertificateSubject().getCountry());
		access.setSubjectState(certificate.getCertificateSubject().getState());
		access.setSubjectLocality(certificate.getCertificateSubject().getLocality());
		access.setSubjectOrganization(certificate.getCertificateSubject().getOrganization());
		access.setSubjectOrganizationUnit(certificate.getCertificateSubject().getOrganizationUnit());
		access.setSubjectCommonName(certificate.getCertificateSubject().getCommonName());
		access.setSubjectSignatureAlgorithm(certificate.getCertificateSubject().getSignatureAlgorithm());
		access.setPublicKeySignatureAlgorithm(certificate.getCertificateSubject().getSignatureAlgorithm());
		
		
		access.setVersion(certificate.getVersion());
		access.setSerialNumber(certificate.getSerialNumber());
		
		access.setNotAfter(certificate.getCertificateValidity().getNotAfter());
		access.setNotBefore(certificate.getCertificateValidity().getNotBefore());
		
		access.setPublicKeyAlgorithm(certificate.getCertificatePublicKey().getPublicKeyAlgorithm());
		access.setPublicKeyParameter(Integer.toString(certificate.getCertificatePublicKey().getPublicKeyLength()));
		
		access.setCritical(Constants.BC, certificate.getCertificateV3Extension().getExtBasicConstraint().isCritical());
		access.setCA(certificate.getCertificateV3Extension().getExtBasicConstraint().isCertificateAuthority());
		access.setPathLen(certificate.getCertificateV3Extension().getExtBasicConstraint().getPathLength());;
		
		access.setCritical(Constants.IAN, certificate.getCertificateV3Extension().getExtIssuerAlternativeNames().isCritical());
		String[] alternativeNames = certificate.getCertificateV3Extension().getExtIssuerAlternativeNames().getIssuerAlternativeNames();
		if (alternativeNames.length > 0)
		{
			access.setAlternativeName(Constants.IAN, alternativeNames[0]);
		}
		
		
		access.setCritical(Constants.AKID, certificate.getCertificateV3Extension().getExtKeyIdentifiers().isCritical());
		access.setEnabledKeyIdentifiers(certificate.getCertificateV3Extension().getExtKeyIdentifiers().isKeyIdentifierEnabled());
		access.setSubjectKeyID(certificate.getCertificateV3Extension().getExtKeyIdentifiers().getSubjectKeyIdentifier());;
		
		//access.setIssuer(v);
		access.setIssuer("Test");
		//access.issu
		
		
		return NOT_SIGNED_CODE_LOAD_KEY_PAIR;
	}

	@Override
	public Enumeration<String> loadLocalKeystore() {
		return myKeyStore.loadLocalKeyStore();
	}

	@Override
	public boolean removeKeypair(String alias) {
		return myKeyStore.removeKeyPairCertificate(alias);
	}

	@Override
	public void resetLocalKeystore() {
		myKeyStore.resetLocalKeyStore();
	}

	@Override
	public boolean saveKeypair(String alias) {
		String country = access.getSubjectCountry();
		String state = access.getSubjectState();
		String locality = access.getSubjectLocality();
		String organization = access.getSubjectOrganization();
		String organizationUnit = access.getSubjectOrganizationUnit();
		String commonName = access.getSubjectCommonName();
		String signatureAlgorithm = access.getPublicKeySignatureAlgorithm();
		CertificateSubject certificateSubject = new CertificateSubject(country, state, locality, 
				organization, organizationUnit, commonName, signatureAlgorithm);
		
		int version = access.getVersion();
		String serialNumber = access.getSerialNumber();
		
		Date notBefore = access.getNotBefore();
		Date notAfter = access.getNotAfter();
		CertificateValidity certificateValidity = new CertificateValidity(notBefore, notAfter);
		
		String publicKeyLength = access.getPublicKeyParameter();
		String publicKeyAlgorithm  = access.getPublicKeyAlgorithm();
		int intPublicKeyLength = Integer.parseInt(publicKeyLength);
		CertificatePublicKey certificatePublicKey = new CertificatePublicKey(publicKeyAlgorithm, intPublicKeyLength);
		
		boolean enabledKeyIdentifiers = access.getEnabledKeyIdentifiers();
		boolean isCriticalKeyIdentifiers = access.isCritical(Constants.AKID);
		Certificatev3ExtensionKeyIdentifiers keyIdentifiers = new Certificatev3ExtensionKeyIdentifiers(
													isCriticalKeyIdentifiers, enabledKeyIdentifiers);
		
		String[] alternativeName = access.getAlternativeName(Constants.IAN);
		boolean isCriticalIssuerAlternativeName = access.isCritical(Constants.IAN);
		Certificatev3ExtensionIssuerAlternativeName issuerAlternativeName = new Certificatev3ExtensionIssuerAlternativeName(
				isCriticalIssuerAlternativeName, alternativeName);
		
		String pathLength = access.getPathLen();
		boolean isCertificateAuthority = access.isCA();
		boolean isCriticalBasicConstraint = access.isCritical(Constants.BC);
		Certificatev3ExtensionBasicConstraint basicConstraint = new Certificatev3ExtensionBasicConstraint(
				isCriticalBasicConstraint, pathLength, isCertificateAuthority);
		
		Certificatev3Extension certificateV3Extension = new Certificatev3Extension(
				basicConstraint, issuerAlternativeName, keyIdentifiers);
		
		Certificatev3 certificatex509v3 = new Certificatev3(version, certificateSubject, 
											serialNumber, certificateValidity, 
											certificatePublicKey, certificateV3Extension);
		return myKeyStore.generateKeyPairCertificate(alias, certificatex509v3);
	}

	@Override
	public boolean signCertificate(String issuerAlias, String algorithmSign) {
		return myKeyStore.signCertificate(issuerAlias, algorithmSign);
	}

}
