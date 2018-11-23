/*
 * Copyright 2004 - 2013 Wayne Grant
 *           2013 - 2018 Kai Kramer
 *
 * This file is part of KeyStore Explorer.
 *
 * KeyStore Explorer is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * KeyStore Explorer is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with KeyStore Explorer.  If not, see <http://www.gnu.org/licenses/>.
 */
package org.gstjs.sign;

import java.io.Closeable;
import java.io.File;
import java.io.IOException;
import java.security.KeyStore;
import java.security.PrivateKey;
import java.security.Security;
import java.security.cert.X509Certificate;
import java.text.MessageFormat;
import java.util.ResourceBundle;
import java.util.jar.JarFile;

import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.gstjs.crypto.CryptoException;
import org.gstjs.crypto.digest.DigestType;
import org.gstjs.crypto.keypair.KeyPairType;
import org.gstjs.crypto.keypair.KeyPairUtil;
import org.gstjs.crypto.signing.JarSigner;
import org.gstjs.crypto.signing.SignatureType;
import org.gstjs.crypto.x509.X509CertUtil;
import org.gstjs.utilities.io.IOUtils;

import iaik.pkcs.pkcs11.Module;
import iaik.pkcs.pkcs11.Session;
import iaik.pkcs.pkcs11.Slot;
import sun.security.pkcs11.SunPKCS11;

import org.apache.commons.cli.CommandLine;
import org.apache.commons.cli.Option;
import org.apache.commons.cli.Options;
import org.apache.commons.cli.Option.Builder;
import org.apache.commons.cli.CommandLineParser;
import org.apache.commons.cli.DefaultParser;
import org.apache.commons.cli.ParseException;

/**
 * Dialog that displays the presents JAR signing options.
 *
 */
public class SignJar {

	private static ResourceBundle res = ResourceBundle.getBundle("org.gstjs.sign.resources");

	private File inputJarFile;
	private File outputJarFile;
	private String signatureName;
	private SignatureType signatureType;
	private DigestType digestType;
	private String tsaUrl;

	private PrivateKey signPrivateKey;
	private KeyPairType signKeyPairType;

	private String inputJar;
	private String outputJar;

	/**
	 * Creates a new DSignJar dialog.
	 *
	 * @param parent
	 *            The parent frame
	 * @param signPrivateKey
	 *            Signing key pair's private key
	 * @param signKeyPairType
	 *            Signing key pair's type
	 * @param signatureName
	 *            Default signature name
	 * @throws CryptoException
	 *             A crypto problem was encountered constructing the dialog
	 */
	public SignJar(PrivateKey signPrivateKey, KeyPairType signKeyPairType, String signatureName)
			throws CryptoException {
		this.signPrivateKey = signPrivateKey;
		this.signKeyPairType = signKeyPairType;
		initComponents(signatureName);
	}

	private void initComponents(String signatureName) throws CryptoException {

		// inputJar="C:\\Users\\sprosper.NSPROSPER203503\\Desktop\\test.jar";
		// outputJar="C:\\Users\\sprosper.NSPROSPER203503\\Desktop\\test_signed.jar";
		this.signatureName = signatureName;

		signatureType = SignatureType.SHA256_RSA;
		digestType = DigestType.SHA256;

		// inputJarFile = new File(inputJar);
		// outputJarFile = new File(outputJar);

		// tsaUrl="http://rfc3161timestamp.globalsign.com/advanced";
	}

	/**
	 * Get chosen input JAR file.
	 *
	 * @return Input JAR file
	 */
	public File getInputJar() {
		return inputJarFile;
	}

	/**
	 * Get chosen output JAR file.
	 *
	 * @return Output JAR file
	 */
	public File getOutputJar() {
		return outputJarFile;
	}

	/**
	 * Get chosen signature name.
	 *
	 * @return Signature name or null if dialog cancelled
	 */
	public String getSignatureName() {
		return signatureName;
	}

	/**
	 * Get chosen signature type.
	 *
	 * @return Signature type or null if dialog cancelled
	 */
	public SignatureType getSignatureType() {
		return signatureType;
	}

	/**
	 * Get chosen digest type.
	 *
	 * @return Digest type or null if dialog cancelled
	 */
	public DigestType getDigestType() {
		return digestType;
	}

	/**
	 * Get chosen TSA URL.
	 *
	 * @return TSA URL or null if dialog cancelled
	 */
	public String getTimestampingServerUrl() {
		return tsaUrl;
	}

	private boolean verifySignatureName(String signatureName) {
		/*
		 * Verify that the supplied signature name is valid for use in the signing of a
		 * JAR file, ie contains only alphanumeric characters and the characters '-' or
		 * '_'
		 */
		for (int i = 0; i < signatureName.length(); i++) {
			char c = signatureName.charAt(i);

			if ((c < 'a' || c > 'z') && (c < 'A' || c > 'Z') && (c < '0' || c > '9') && c != '-' && c != '_') {
				return false;
			}
		}

		return true;
	}

	private void okPressed() {

		File inputJarFile = new File(inputJar);

		if (!inputJarFile.isFile()) {
			// CONTROL ERROR
			return;
		}

		JarFile jarFile = null;
		try {
			jarFile = new JarFile(inputJarFile);
		} catch (IOException ex) {
			String problemStr = MessageFormat.format(res.getString("DSignJar.NoOpenJar.Problem"),
					inputJarFile.getName());

			String[] causes = new String[] { res.getString("DSignJar.NotJar.Cause"),
					res.getString("DSignJar.CorruptedJar.Cause") };

			// Problem problem = new Problem(problemStr, causes, ex);

			return;
		} finally {
			IOUtils.closeQuietly((Closeable) jarFile);
		}

		boolean signDirectly = false;

		File outputJarFile;
		if (signDirectly) {
			outputJarFile = inputJarFile;
		} else {
			if (outputJar.length() == 0) {
				// CONTROL ERROR
				return;
			}
			outputJarFile = new File(outputJar);
		}

		if (signatureName.length() == 0) {
			// CONTROL ERROR
			return;
		}

		if (!verifySignatureName(signatureName)) {
			// CONTROL ERROR
			return;
		}

		this.inputJarFile = inputJarFile;
		this.outputJarFile = outputJarFile;
		this.signatureName = signatureName;
	}

	// for quick testing
	public static void main(String[] args) throws Exception {

		String providerArg=null;
		String password=null;
		String alias=null;
		String signer = "Stefano Jar Signer";
		String signatureName=null;
		String tsaUrl = null;
		String inputJar = null;
		File inputJarFile = null;
		boolean test = false;

		CommandLine commandLine;
		
		Option option_tsa = Option.builder("tsa").required(false).desc("TimeStamp URL").longOpt("tsa").numberOfArgs(1)
				.build();
		Option option_providerArg = Option.builder("providerArg").required(true).desc("Configurazione Token")
				.longOpt("providerArg").numberOfArgs(1).build();
		Option option_storepass = Option.builder("storepass").required(true).desc("Password Token")
				.longOpt("storepass").numberOfArgs(1).build();
		Option option_test = Option.builder().required(false).desc("The test option").longOpt("test").build();
		
		Options options = new Options();
		CommandLineParser parser = new DefaultParser();

		options.addOption(option_test);
		options.addOption(option_tsa);
		options.addOption(option_providerArg);
		options.addOption(option_storepass);		

		try {
			commandLine = parser.parse(options, args);

			if (commandLine.hasOption("test")) {
				System.out.println("Option test is present.  This is a flag option.");
				test = true;
			}

			if (commandLine.hasOption("tsa")) {
				tsaUrl = commandLine.getOptionValue("tsa");
				if (test) System.out.print("tsa is present.  The value is: ");
				if (test) System.out.println(commandLine.getOptionValue("tsa"));
			}

			if (commandLine.hasOption("storepass")) {
				password = commandLine.getOptionValue("storepass");
				if (test) System.out.print("storepass is present.  The value is: ");
				if (test) System.out.println(commandLine.getOptionValue("storepass"));
			}

			if (commandLine.hasOption("providerArg")) {
				providerArg = commandLine.getOptionValue("providerArg");
				if (test)
					System.out.print("Option providerArg is present.  The value is: ");
				if (test)
					System.out.println(commandLine.getOptionValue("providerArg"));
				File f = new File(providerArg);
				if (!f.exists() || f.isDirectory()) {
					System.out.print("File di configurazione \"" + providerArg + "\" non trovato!");
					System.exit(3);
				}
			}

			{
				String[] remainder = commandLine.getArgs();
				if (remainder.length < 2) {
					System.out.print("Specificare jar da firmare e alias da utilizzare!");
					System.exit(4);
				}
				inputJar = remainder[0];
				inputJarFile = new File(inputJar);
				if (!inputJarFile.exists() || inputJarFile.isDirectory()) {
					System.out.print("File da firmare \"" + inputJar + "\" non trovato!");
					System.exit(3);
				}
				alias = remainder[1];
				if (test)
					System.out.print("Remaining arguments: ");
				if (test)
					for (String argument : remainder) {
						System.out.print(argument);
						System.out.print(" ");
					}

				if (test)
					System.out.println();
			}

		} catch (ParseException exception) {
			System.out.print("Parse error: ");
			System.out.println(exception.getMessage());
			System.exit(2);
		}

		System.out.println("Recupero chiave e certificato dal token ...");

		Security.addProvider(new BouncyCastleProvider());
		SunPKCS11 p = new sun.security.pkcs11.SunPKCS11(providerArg);
		
		/*
		// IAIK PKCS#11 Wrapper -------------------------------------------

	    Module pkcs11Module = Module.getInstance("c:\\WINDOWS\\system32\\eTPKCS11.dll");
	    pkcs11Module.initialize(null);

	    Slot[] slots = pkcs11Module.getSlotList(true);

	    Session session = slots[0].getToken().openSession(true, true, null, null);
	    session.login(Session.UserType.USER, password.toCharArray());
	    
	    session.logout();
	    session.closeSession();
	    // slots[0].getToken().closeAllSessions();
	    pkcs11Module.finalize(null);
	    */
		
		Security.addProvider(p);
		KeyStore keyStore = KeyStore.getInstance("PKCS11");
		keyStore.load(null, password.toCharArray());

		PrivateKey privateKey = (PrivateKey) keyStore.getKey(alias, password.toCharArray());
		if (privateKey == null) {
			System.out.println("Chiave privata non trovata per alias: " + alias);
			System.exit(1);
		}
		X509Certificate[] certs = X509CertUtil
				.orderX509CertChain(X509CertUtil.convertCertificates(keyStore.getCertificateChain(alias)));
		KeyPairType keyPairType = KeyPairUtil.getKeyPairType(privateKey);
		
		signatureName = alias.substring(0, 7);
		SignJar mySignJar = new SignJar(privateKey, keyPairType, signatureName);

		SignatureType signatureType = mySignJar.getSignatureType();
		if (signatureType == null) {
			return;
		}
		DigestType digestType = mySignJar.getDigestType();
		System.out.println("Sto firmando il jar ...");
		JarSigner.sign(inputJarFile, privateKey, certs, signatureType, signatureName, signer, digestType, tsaUrl, null);
		System.out.println("jar firmato!");
	}
}
