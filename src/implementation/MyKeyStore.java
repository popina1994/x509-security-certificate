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
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;

import javax.swing.text.AbstractDocument.Content;

import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x500.X500NameBuilder;
import org.bouncycastle.asn1.x500.style.BCStyle;
import org.bouncycastle.asn1.x509.BasicConstraints;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.X509v3CertificateBuilder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
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
			if (!loadLocalKeyStore())
			{
				return null;
			}
		}
		return keyStore;
	}
	
	public boolean loadLocalKeyStore()
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
	
	private void saveKeyStore()
	{
		FileOutputStream fileOutputStream = null;
		try {
			fileOutputStream = new FileOutputStream(KEY_STORE_NAME);
			keyStore.store(fileOutputStream, ARR_PASSWORD);
		} catch (FileNotFoundException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (KeyStoreException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (NoSuchAlgorithmException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (CertificateException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (IOException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
		finally {
			if (fileOutputStream != null)
			{
				try {
					fileOutputStream.close();
				} catch (IOException e) {
					// TODO Auto-generated catch block
					e.printStackTrace();
				}
			}
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
	
	private static X509Certificate generateCertificate(KeyPair keyPair, Certificatex509v3 certificatex509v3)
	{
		// builder for extension 
		X500NameBuilder x500NameBuilder = new X500NameBuilder(BCStyle.INSTANCE);
		x500NameBuilder.addRDN(BCStyle.CN, certificatex509v3.getCertificateSubject().getCommonName());
		x500NameBuilder.addRDN(BCStyle.ST, certificatex509v3.getCertificateSubject().getState());
		x500NameBuilder.addRDN(BCStyle.L, certificatex509v3.getCertificateSubject().getLocality());
		x500NameBuilder.addRDN(BCStyle.O,certificatex509v3.getCertificateSubject().getOrganization());
		x500NameBuilder.addRDN(BCStyle.OU, certificatex509v3.getCertificateSubject().getOrganizationUnit());
		x500NameBuilder.addRDN(BCStyle.CN, certificatex509v3.getCertificateSubject().getCommonName());
		
		X500Name x500Name = x500NameBuilder.build();
		X509v3CertificateBuilder certificateBuilder = new JcaX509v3CertificateBuilder(
				x500Name, /* issuer */
				new BigInteger(certificatex509v3.getSerialNumber()), /* serial number */
				certificatex509v3.getCertificateValidity().getNotBefore(), /* not before */
				certificatex509v3.getCertificateValidity().getNotAfter(), /* not after */
				x500Name, /* subject */
				keyPair.getPublic() /* public key*/
				);
		//certificateBuilder.addExtension(Extension.basicConstraints, new BasicConstraints(arg0));
		//certificateBuilder.addExtension(Extension.keyI)
		ContentSigner contentSigner = null;
		try {
			contentSigner = new JcaContentSignerBuilder(certificatex509v3.getCertificateSubject().getSignatureAlgorithm()).
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

	public boolean generateKeyPairCertificate(String alias, Certificatex509v3 certificatex509v3) {
		//KeyStore
		KeyPair keyPair = generateKeyPair(certificatex509v3.getCertificatePublicKey());
		X509Certificate  certificate = generateCertificate(keyPair, certificatex509v3);
		Certificate [] chainCertficate = new Certificate[1];
		chainCertficate[0] = certificate;
		
		try {
			if (getKeyStore() == null)
			{
				return false;
			}
			getKeyStore().setKeyEntry(alias, keyPair.getPrivate(), ARR_PASSWORD, chainCertficate);
			saveKeyStore();
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
			saveKeyStore();
		} catch (KeyStoreException e) {
			e.printStackTrace();
			return false;
		}
		return true;
	}
}
