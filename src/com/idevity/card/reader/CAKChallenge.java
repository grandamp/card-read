/******************************************************************************
 * The following code belongs to IDevity and is provided though commercial
 * license or by acceptance of an NDA only.
 * 
 * $Id: CAKChallenge.java 299 2013-12-23 00:40:06Z tejohnson $
 * 
 * @author Matthew Ambs (matt@idevity.com)
 * @author Eugene Yu (eugene@idevity.com)
 * @author Todd E. Johnson (todd@idevity.com)
 * @author LaChelle Levan (lachelle@idevity.com)
 * 
 * @version $Revision: 299 $
 * 
 * Changed: $LastChangedDate: 2013-12-22 19:40:06 -0500 (Sun, 22 Dec 2013) $
 *****************************************************************************/

package com.idevity.card.reader;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.SecureRandom;
import java.security.Signature;
import java.security.SignatureException;
import java.security.cert.X509Certificate;
import java.security.interfaces.ECPublicKey;
import java.security.interfaces.RSAPublicKey;
import java.util.Enumeration;
import java.util.Vector;

import org.keysupport.asn1.ASN1Exception;
import org.keysupport.encoding.der.structures.AlgorithmIdentifier;
import org.keysupport.encoding.der.structures.DigestInfo;
import org.keysupport.keystore.CipherEngine;
import org.keysupport.keystore.DigestEngine;
import org.keysupport.keystore.PaddingEngine;
import org.keysupport.nist80073.cardedge.DynamicAuthTempl;
import org.keysupport.nist80073.cardedge.PIVAPDUInterface;
import org.keysupport.smartcardio.CommandAPDU;
import org.keysupport.util.DataUtil;

import android.util.Log;

import com.idevity.android.CardChannel;

/**
 * @author Matthew Ambs (matt@idevity.com)
 * @author Eugene Yu (eugene@idevity.com)
 * @author Todd E. Johnson (todd@idevity.com)
 * @author LaChelle Levan (lachelle@idevity.com)
 * 
 * @version $Revision: 299 $
 */
public class CAKChallenge {

	/*
	 * Inputs for Generation:
	 * 	-Certificate
	 * 
	 * Outputs for Generation:
	 * 	-nonce (plaintext)
	 *  -Signed value (ciphertext)
	 * 	-Signature validity
	 * 
	 * Inputs for Verification:
	 * 	-Certificate
	 * 	-nonce (plaintext)
	 *  -Signed value (ciphertext)
	 * 
	 * Outputs for Verification:
	 * 	-Signature validity
	 * 
	 * For generation This class will:
	 * 
	 * 1. Determine the Card Authentication Key size and Algorithm
	 * 
	 * 2. Generate a suitable nonce:
	 * 
	 * Per SP 800-56B, Page 31:
	 * 
	 * http://csrc.nist.gov/publications/nistpubs/800-56B/sp800-56B.pdf
	 * 
	 * "1. A random value that is generated anew for each nonce, using an approved random bit 
	 *     generator. The security strength of the RBG used to obtain each random value shall be 
	 *     greater than or equal to the security strength associated with the length (in bits) of the 
	 *     modulus n of the cryptographic algorithm used in the key establishment scheme (see SP 
	 *     800-57-Part 1, Table 2 [8]). The length (in bits) of the RBG output shall be at least as 
	 *     great as the number of bits of security associated with the key establishment scheme. A 
	 *     nonce containing a component of this type is called a random nonce." 
	 * 
	 * SP 800-57-Part 1, Table 2:
	 * ___________________________________________________________________
	 * |Bits of Security|Symmetric key alg|FFC (DSA)|IFC (RSA)|ECC (ECDSA)|
	 * |----------------|-----------------|---------|---------|-----------|
	 * |256             |AES-256          |L = 15360|k = 15360|f = 512    |
	 * |                |                 |N = 512  |         |           |
	 * --------------------------------------------------------------------
	 * 
	 * Requirement: Our nonce shall be random.
	 * Requirement: Our random nonce shall be 64 bytes (512 bit).
	 * 
	 * 3.  Upon generating the nonce, it will be digested using the appropriate
	 * 		digest algorithm:
	 * 
	 * Requirement:  For RSA-2048 and above, the digest alg shall be SHA-256
	 * Requirement:  For P-256, the digest alg shall be SHA-256
	 * Requirement:  For P-384, the digest alg shall be SHA-384
	 * 
	 * 4. (conditional)  If RSA, the SHA-256 product will be padded using PKCS#1 v1.5
	 * 
	 * 5. The product will be sent to the card via an external authenticate command
	 *    and the product will be encrypted with the Card Authentication private key.
	 *
	 * 6. The signed product will be provided back to this class for signature verification.
	 */

	/**
	 * Field debug.
	 * (value is true)
	 */
	private static final boolean debug = false;
	/**
	 * Field TAG.
	 */
	private static final String TAG = CAKChallenge.class.getSimpleName();
	/**
	 * Field cardAuth.
	 */
	private X509Certificate cardAuth;
	/**
	 * Field cakPopNonce.
	 */
	private byte[] cakPopNonce;
	/**
	 * Field gaapdus.
	 */
	private Enumeration<CommandAPDU> gaApdus;
	/**
	 * Field cakPopSig.
	 */
	private byte[] cakPopSig;

	/**
	 * Default constructor for generation
	 * 
	 * @param cardAuth
	 * @throws ASN1Exception 
	 * @throws IOException 
	 */
	public CAKChallenge(X509Certificate cardAuth) throws IOException, ASN1Exception {
		if (debug) {
			Log.d(TAG, "Setting Certificate");
		}
		this.cardAuth = cardAuth;
		if (debug) {
			Log.d(TAG, "Generating Nonce");
		}
		generateNonce();
		if (debug) {
			Log.d(TAG, "Getting APDUs for POP");
		}
		genDatAPDUs();
	}

	/**
	 * Default constructor for validation
	 * 
	 * @param cardAuth
	 * @param nonce
	 * @param signature
	 */
	public CAKChallenge(X509Certificate cardAuth, byte[] nonce, byte[] signature) {
		if (debug) {
			Log.d(TAG, "Setting Certificate");
		}
		this.cardAuth = cardAuth;
		if (debug) {
			Log.d(TAG, "Setting Nonce");
		}
		this.cakPopNonce = nonce;
		if (debug) {
			Log.d(TAG, "Setting Signature");
		}
		this.cakPopSig = signature;
	}

	/**
	 * Method genDatAPDUs.
	 * @return Enumeration<CommandAPDU>
	 * @throws ASN1Exception
	 * @throws IOException
	 */
	private void genDatAPDUs() throws ASN1Exception,
			IOException {

		byte[] rbDigest = null;

		String keyAlgo = cardAuth.getPublicKey().getAlgorithm();
		if (debug) {
			Log.d(TAG, "Card Authentication Certificate Key Type: " + keyAlgo);
		}

		/*
		 * Determine RSA or ECC
		 */
		if (keyAlgo.equalsIgnoreCase("RSA")) {

			RSAPublicKey pub = (RSAPublicKey) cardAuth.getPublicKey();

			byte pivkeytype = 0;

			int modsize = pub.getModulus().toByteArray().length;
			if (modsize >= 128 && modsize <= 256) {
				modsize = 128;
				pivkeytype = CipherEngine.RSA_1024;
			}
			if (modsize >= 256 && modsize <= 384) {
				modsize = 256;
				pivkeytype = CipherEngine.RSA_2048;
			}

			/*
			 * Digest the data to be signed
			 */
			rbDigest = DigestEngine.sHA256Sum(cakPopNonce, "OpenSSLFIPSProvider");
			if (debug) {
				Log.d(TAG, "SHA-256 Digest of our " + cakPopNonce.length
						+ " byte random:\n" + DataUtil.byteArrayToString(rbDigest));
				Log.d(TAG, "RSA Mod is " + modsize + " bytes.");
			}

			AlgorithmIdentifier ai = new AlgorithmIdentifier(
					CipherEngine.SHA256, null);
			DigestInfo di = new DigestInfo(ai, rbDigest);
			byte[] diBytes = di.getBytes();
			byte[] message = PaddingEngine.pkcs1v1_5Pad(diBytes, modsize);

			DynamicAuthTempl gaReq = new DynamicAuthTempl(
					DynamicAuthTempl.POP_TO_TERM_RSA, message);

			this.gaApdus = generalAuthenticate(pivkeytype,
					CipherEngine.CARD_AUTH_KEY, gaReq.getEncoded());

		} else {
			ECPublicKey pub = (ECPublicKey) cardAuth.getPublicKey();

			byte pivkeytype = 0;
			int wSize = pub.getW().getAffineX().toByteArray().length;
			if (wSize >= 32 && wSize <= 48) {
				wSize = 32;
				pivkeytype = CipherEngine.ECC_CURVE_P256;
				/*
				 * Digest the data to be signed
				 */
				rbDigest = DigestEngine.sHA256Sum(cakPopNonce, "OpenSSLFIPSProvider");
				if (debug) {
					Log.d(TAG,
						"SHA-256 Digest of our " + cakPopNonce.length
								+ " byte random:\n"
								+ DataUtil.byteArrayToString(rbDigest));
				}
			}
			if (wSize >= 48 && wSize <= 64) {
				wSize = 48;
				pivkeytype = CipherEngine.ECC_CURVE_P384;
				/*
				 * Digest the data to be signed
				 */
				rbDigest = DigestEngine.sHA384Sum(cakPopNonce, "OpenSSLFIPSProvider");
				if (debug) {
					Log.d(TAG,
						"SHA-384 Digest of our " + cakPopNonce.length
								+ " byte random:\n"
								+ DataUtil.byteArrayToString(rbDigest));
				}
			}
			if (debug) {
				Log.d(TAG, "Key Size: " + wSize);
			}

			DynamicAuthTempl gaReq = new DynamicAuthTempl(
					DynamicAuthTempl.POP_TO_TERM_ECC, rbDigest);

			this.gaApdus = generalAuthenticate(pivkeytype,
					CipherEngine.CARD_AUTH_KEY, gaReq.getEncoded());
		}
	}

	/**
	 * Method validatePOP()
	 * 
	 * In the future, we may want to envelope the entire signature into
	 * a CMS Signed Data object, which would result in the ability "digitally sign"
	 * data.  For now, we will guess the signing algorithm based on the certifcate's
	 * public key and signature value.
	 */
	public boolean validatePOP() throws SignatureException {

		boolean pop = false;
		String signingAlgorithm = null;
		Signature sig = null;
		/*
		 * We need to determine Signature type based on the
		 * certificate and signature value.
		 */
		
		String keyAlgo = cardAuth.getPublicKey().getAlgorithm();
		if (debug) {
			Log.d(TAG, "Card Authentication Certificate Key Type: " + keyAlgo);
		}

		/*
		 * Determine RSA or ECC
		 * 
		 * TODO: Change signature format to a CMS Signed message
		 * 
		 * This should work fine for now, as we generate the signature,
		 * so we can predict the signature algorithm (one of 3)
		 */
		if (keyAlgo.equalsIgnoreCase("RSA")) {
			signingAlgorithm = "SHA256withRSA";
		} else {
			ECPublicKey pub = (ECPublicKey) cardAuth.getPublicKey();
			
			int wSize = pub.getW().getAffineX().toByteArray().length;
			if (wSize >= 32 && wSize <= 48) {
				signingAlgorithm = "SHA256withECDSA";
			} else {
				signingAlgorithm = "SHA384withECDSA";
			}
		}
		try {
			if (debug) {
				Log.d(TAG, "Card Authentication POP Signing Algo: " + signingAlgorithm);
			}
			sig = Signature.getInstance(signingAlgorithm, "OpenSSLFIPSProvider");
			sig.initVerify(this.cardAuth.getPublicKey());
			sig.update(this.cakPopNonce);
			pop = sig.verify(this.cakPopSig);
		} catch (NoSuchAlgorithmException e) {
			throw new SignatureException("Bad Signing Algorithm: "
					+ e.getLocalizedMessage());
		} catch (InvalidKeyException e) {
			throw new SignatureException("Invalid Key: " + e.getLocalizedMessage());
		} catch (SignatureException e) {
			throw new SignatureException("Bad Signature: " + e.getLocalizedMessage());
		} catch (NoSuchProviderException e) {
			throw new SignatureException("Bad Provider: " + e.getLocalizedMessage());
		}
		return pop;
	}

	/**
	 * Method generalAuthenticate.
	 * 
	 * @param algRef
	 *            byte
	 * @param keyRef
	 *            byte
	 * @param dat
	 *            byte[]
	 * @return Enumeration<CommandAPDU> 
	 * @throws IOException 
	 */
	private static Enumeration<CommandAPDU> generalAuthenticate(byte algRef,
			byte keyRef, byte[] dat) throws IOException {
		byte[] apdu_data;
		ByteArrayOutputStream baos = new ByteArrayOutputStream();
		Vector<CommandAPDU> apdus = new Vector<CommandAPDU>();

		apdu_data = dat;

		if ((apdu_data.length) >= CardChannel.MAX_APDU_SIZE) {
			baos.write(PIVAPDUInterface.PIV_GEN_AUTH_CC_HEADER);
			baos.write(algRef);
			baos.write(keyRef);
			baos.write(CardChannel.MAX_APDU_SIZE - 5);
			baos.write(apdu_data);
			apdu_data = baos.toByteArray();
			baos.reset();
			byte[][] cc_apdu_data = DataUtil.getArrays(apdu_data,
					CardChannel.MAX_APDU_SIZE, false);
			for (int i = 0; i < cc_apdu_data.length; i++) {
				if (i == 0) {
					baos.write(cc_apdu_data[i]);
					if (debug) {
						Log.d(TAG,
							"Adding APDU: "
									+ DataUtil.byteArrayToString(baos
											.toByteArray()));
					}
					apdus.add(new CommandAPDU(baos.toByteArray()));
					baos.reset();
				} else if (i == (cc_apdu_data.length - 1)) {
					baos.write(PIVAPDUInterface.PIV_GEN_AUTH_HEADER);
					baos.write(algRef);
					baos.write(keyRef);
					baos.write(cc_apdu_data[i].length);
					baos.write(cc_apdu_data[i]);
					baos.write((byte) 0x00); // Add Le
					if (debug) {
						Log.d(TAG,
							"Adding APDU: "
									+ DataUtil.byteArrayToString(baos
											.toByteArray()));
					}
					apdus.add(new CommandAPDU(baos.toByteArray()));
					baos.reset();
				} else {
					baos.write(PIVAPDUInterface.PIV_GEN_AUTH_CC_HEADER);
					baos.write(algRef);
					baos.write(keyRef);
					baos.write(cc_apdu_data[i].length);
					baos.write(cc_apdu_data[i]);
					if (debug) {
						Log.d(TAG,
							"Adding APDU: "
									+ DataUtil.byteArrayToString(baos
											.toByteArray()));
					}
					apdus.add(new CommandAPDU(baos.toByteArray()));
					baos.reset();
				}
			}
		} else {
			// Typically the case when algRef=CipherEngine.THREE_KEY_3DES_ECB &&
			// keyRef=CipherEngine.CARD_MGMT_KEY
			baos.write(PIVAPDUInterface.PIV_GEN_AUTH_HEADER);
			baos.write(algRef);
			baos.write(keyRef);
			baos.write(dat.length);
			baos.write(dat);
			apdus.add(new CommandAPDU(baos.toByteArray()));
		}
		Enumeration<CommandAPDU> apduse = apdus.elements();
		return apduse;
	}

	/**
	 * Method generateNonce.
	 */
	private void generateNonce() {

		SecureRandom rand = null;

		this.cakPopNonce = new byte[64];
		try {
			rand = SecureRandom
					.getInstance("NativePRNG", "OpenSSLFIPSProvider");
			rand.nextBytes(cakPopNonce);
		} catch (NoSuchAlgorithmException e) {
			Log.e(TAG, e.getLocalizedMessage());
		} catch (NoSuchProviderException e) {
			Log.e(TAG, e.getLocalizedMessage());
		} catch (Throwable e) {
			Log.e(TAG, e.getLocalizedMessage());
		}

	}

	/**
	 * @return the gaApdus
	 */
	public Enumeration<CommandAPDU> getGenAuthAPDUs() {
		return gaApdus;
	}

	/**
	 * @return the cakPopNonce
	 */
	public byte[] getCAKPoPNonce() {
		return cakPopNonce;
	}

	/**
	 * @return the cakPopSig
	 */
	public byte[] getCAKPoPSignature() {
		return cakPopSig;
	}

	/**
	 * @param cakPopSig the cakPopSig to set
	 */
	public void setCAKPoPSignature(byte[] cakPopSig) {
		this.cakPopSig = cakPopSig;
	}

}
