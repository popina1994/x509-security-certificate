package implementation;

import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.IOException;
import java.math.BigInteger;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.cert.Certificate;
import java.security.cert.CertificateEncodingException;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.security.interfaces.RSAPublicKey;
import java.util.Date;
import java.util.Enumeration;

import javax.swing.text.AbstractDocument.Content;

import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.x500.RDN;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x500.X500NameBuilder;
import org.bouncycastle.asn1.x500.style.BCStyle;
import org.bouncycastle.asn1.x500.style.IETFUtils;
import org.bouncycastle.asn1.x509.BasicConstraints;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.ExtensionsGenerator;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.X509v3CertificateBuilder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.cert.jcajce.JcaX509CertificateHolder;
import org.bouncycastle.cert.jcajce.JcaX509v1CertificateBuilder;
import org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;

import code.X509;

public class MyKeyStore {
	KeyStore  keyStore = null;
	
	static final char [] ARR_PASSWORD = "Baba1234!".toCharArray();
	static final String KEY_STORE_NAME = "KeyStore.jks";
	static final String KEY_STORE_DEFAULT_JAVA_NAME = "JKS";
	
	
	private static boolean checkIfExist(String fileName)
	{
		File file = new File(fileName);
		return file.exists();
	}
	
	private KeyStore getKeyStore()
	{
		if (keyStore == null)
		{
			if (!loadKeyStore())
			{
				return null;
			}
		}
		return keyStore;
	}
	
	public boolean loadKeyStore()
	{
		FileInputStream fileInputStream  = null;
		try 
		{
			keyStore = KeyStore.getInstance(KEY_STORE_DEFAULT_JAVA_NAME);
			if (!checkIfExist(KEY_STORE_NAME))
			{
				keyStore.load(null, null);
			}
			else
			{
				fileInputStream = new FileInputStream(KEY_STORE_NAME);
				keyStore.load(fileInputStream, ARR_PASSWORD);
			}
		} 
		catch (FileNotFoundException e)
		{
			
		}
		catch (CertificateException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
			return false;
		} catch (KeyStoreException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
			return false;
		} catch (NoSuchAlgorithmException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
			return false;
		} catch (IOException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
			return false;
		}
		finally 
		{
			if (fileInputStream != null)
			{
				try {
					fileInputStream.close();
				} catch (IOException e) {
					// TODO Auto-generated catch block
					e.printStackTrace();
				}
			}
		}
		return true;
	}
	
	private boolean saveKeyStore()
	{
		FileOutputStream fileOutputStream = null;
		try {
			fileOutputStream = new FileOutputStream(KEY_STORE_NAME);
			keyStore.store(fileOutputStream, ARR_PASSWORD);
		} catch (FileNotFoundException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
			return false;
		} catch (KeyStoreException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
			return false;
		} catch (NoSuchAlgorithmException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
			return false;
		} catch (CertificateException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
			return false;
		} catch (IOException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
			return false;
		}
		finally {
			if (fileOutputStream != null)
			{
				try {
					fileOutputStream.close();
				} catch (IOException e) {
					// TODO Auto-generated catch block
					e.printStackTrace();
					return false;
				}
			}
		}
		return true;
	}
	
	private void deleteKeyStore()
	{
		FileOutputStream fileOutputStream = null;
		
		if (checkIfExist(KEY_STORE_NAME))
		{
			File file = new File(KEY_STORE_NAME);
			file.delete();
			keyStore = null;
		}
	}
	
	private static KeyPair generateKeyPair(CertificatePublicKey certificatePublicKey)
	{
		String algorithm = certificatePublicKey.getPublicKeyAlgorithm();
		int keySize = certificatePublicKey.getPublicKeyLength();
		KeyPairGenerator keyPairGenerator;
		try {
			keyPairGenerator = KeyPairGenerator.getInstance(algorithm);
			keyPairGenerator.initialize(keySize);
			KeyPair keyPair = keyPairGenerator.generateKeyPair();
			return keyPair;
		} catch (NoSuchAlgorithmException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
		return null;
		
	}
	
	private static X509Certificate generateCertificate(KeyPair keyPair, Certificatev3 certificatev3)
	{
		// builder for extension 
		X500NameBuilder x500NameBuilder = new X500NameBuilder(BCStyle.INSTANCE);
		x500NameBuilder.addRDN(BCStyle.CN, certificatev3.getCertificateSubject().getCommonName());
		x500NameBuilder.addRDN(BCStyle.ST, certificatev3.getCertificateSubject().getState());
		x500NameBuilder.addRDN(BCStyle.L, certificatev3.getCertificateSubject().getLocality());
		x500NameBuilder.addRDN(BCStyle.O,certificatev3.getCertificateSubject().getOrganization());
		x500NameBuilder.addRDN(BCStyle.OU, certificatev3.getCertificateSubject().getOrganizationUnit());
		x500NameBuilder.addRDN(BCStyle.CN, certificatev3.getCertificateSubject().getCommonName());
		
		X500Name x500Name = x500NameBuilder.build();
		X509v3CertificateBuilder certificateBuilder = new JcaX509v3CertificateBuilder(
				x500Name, /* issuer */
				new BigInteger(certificatev3.getSerialNumber()), /* serial number */
				certificatev3.getCertificateValidity().getNotBefore(), /* not before */
				certificatev3.getCertificateValidity().getNotAfter(), /* not after */
				x500Name, /* subject */
				keyPair.getPublic() /* public key*/
				);
		
		//certificateBuilder.addExtension(Extension.basicConstraints, new BasicConstraints(arg0));
		//certificateBuilder.addExtension(Extension.keyI)
		ContentSigner contentSigner = null;
		try {
			contentSigner = new JcaContentSignerBuilder(certificatev3.getCertificateSubject().getSignatureAlgorithm()).
											build(keyPair.getPrivate());
		} catch (OperatorCreationException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
			return null;
		};
		X509CertificateHolder certificateHolder = certificateBuilder.build(contentSigner);
		
		X509Certificate certificate = null;
		try {
			certificate = new JcaX509CertificateConverter().getCertificate(certificateHolder);
		} catch (CertificateException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
			return null;
		}
		return certificate;
		
	}

	public boolean generateKeyPairCertificate(String alias, Certificatev3 certificatev3) {
		//KeyStore
		KeyPair keyPair = generateKeyPair(certificatev3.getCertificatePublicKey());
		X509Certificate  certificate = generateCertificate(keyPair, certificatev3);
		Certificate [] chainCertficate = new Certificate[1];
		chainCertficate[0] = certificate;
		
		try {
			if (getKeyStore() == null)
			{
				return false;
			}
			getKeyStore().setKeyEntry(alias, keyPair.getPrivate(), ARR_PASSWORD, chainCertficate);
			if (!saveKeyStore())
			{
				return false;
			}
		} catch (KeyStoreException e) {
			e.printStackTrace();
			return false;
			
		}
		return true;
	}
	
	public boolean removeKeyPairCertificate(String alias)
	{
		if (getKeyStore() == null)
		{
			return false;
		}
		try {
			getKeyStore().deleteEntry(alias);
			if (!saveKeyStore())
			{
				return false;
			}
		} catch (KeyStoreException e) {
			e.printStackTrace();
			return false;
		}
		return true;
	}
	
	public Enumeration<String> loadLocalKeyStore()
	{
		if (!loadKeyStore())
		{
			return null;
		}
		try 
		{
			return getKeyStore().aliases();
		}
		catch (KeyStoreException exception)
		{
			exception.printStackTrace();
			return null;
		}
	}
	
	public void resetLocalKeyStore()
	{
		deleteKeyStore();
	}
	
	private static String getFromRDNString(RDN rdn)
	{
		return IETFUtils.valueToString(rdn.getFirst().getValue());
	}
	
	private static String getStringWithStyle(X500Name x500Name, ASN1ObjectIdentifier style)
	{
		RDN rdn = x500Name.getRDNs(style)[0];
		return getFromRDNString(rdn);
	}
	
	public Certificatev3 loadKeyPair(String alias)
	{
		String country = null;
		String state = null;
		String locality = null;
		String organization = null;
		String organizationUnit = null;
		String commonName = null;
		String signatureAlgorithm = null;
		
		Integer publicKeyLength = null;
		String publicKeyAlgorithm = null;
		
		Integer version = null;
		String serialNumber = null;
		Date notBefore = null;
		Date notAfter = null;
		RDN rdn =  null;
		if (getKeyStore() == null)
		{
			return null;
		}
		Certificatev3 certificateV3 = null;
		try {
			X509Certificate certificate = null;
			certificate =  (X509Certificate)getKeyStore().getCertificate(alias);
			X500Name x500name = new JcaX509CertificateHolder(certificate).getSubject();
			
			country = getStringWithStyle(x500name, BCStyle.CN);
			state = getStringWithStyle(x500name, BCStyle.ST);
			locality = getStringWithStyle(x500name, BCStyle.L);
			organization = getStringWithStyle(x500name, BCStyle.O);
			organizationUnit = getStringWithStyle(x500name, BCStyle.OU);
			commonName = getStringWithStyle(x500name, BCStyle.CN);
			signatureAlgorithm = certificate.getSigAlgName();
			CertificateSubject certificateSubject = new CertificateSubject(country, state, locality, organization, 
					organizationUnit, commonName, signatureAlgorithm);
			
			version = certificate.getVersion();
			serialNumber = ""+certificate.getSerialNumber();
			
			notBefore = certificate.getNotBefore();
			notAfter = certificate.getNotAfter();
			CertificateValidity certificateValidity = new CertificateValidity(notBefore, notAfter);
			
			publicKeyAlgorithm = certificate.getPublicKey().getAlgorithm();
			RSAPublicKey rsaPublicKey = (RSAPublicKey)certificate.getPublicKey();
			publicKeyLength = rsaPublicKey.getModulus().bitLength();
			CertificatePublicKey certificatePublicKey = new CertificatePublicKey(publicKeyAlgorithm, 
					publicKeyLength);
			
			Certificatev3Extension certificatev3Extension = null;
			certificateV3 = new Certificatev3(version, certificateSubject, 
					serialNumber, certificateValidity, certificatePublicKey, certificatev3Extension);
		} catch (KeyStoreException e) {
			e.printStackTrace();
			return null;
		} catch (CertificateEncodingException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
			return null;
		}
		
		return certificateV3;
	}
}
