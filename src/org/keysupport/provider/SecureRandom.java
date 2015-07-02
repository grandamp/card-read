/******************************************************************************
 * The following code belongs to IDevity and is provided though commercial
 * license or by acceptance of an NDA only.
 * 
 * $Id: SecureRandom.java 293 2013-12-19 15:49:22Z tejohnson $
 * 
 * @author Matthew Ambs (matt@idevity.com)
 * @author Eugene Yu (eugene@idevity.com)
 * @author Todd E. Johnson (todd@idevity.com)
 * @author LaChelle Levan (lachelle@idevity.com)
 * 
 * @version $Revision: 293 $ 
 * 
 * Changed: $LastChangedDate: 2013-12-19 10:49:22 -0500 (Thu, 19 Dec 2013) $
 *****************************************************************************/

package org.keysupport.provider;

import java.security.SecureRandomSpi;

/**
 * @author tejohnson
 * 
 */
public class SecureRandom extends SecureRandomSpi {

	/**
	 * 
	 */
	private static final long serialVersionUID = 2073934780429061187L;

	native void jniFIPSRandBytes(byte[] buf);

	/**
	 * 
	 */
	public SecureRandom() {
		/*
		 * Default constructor
		 */
	}

	/*
	 * (non-Javadoc)
	 * 
	 * @see java.security.SecureRandomSpi#engineGenerateSeed(int)
	 */
	@Override
	protected byte[] engineGenerateSeed(int numBytes) {
		byte[] buff = new byte[numBytes];
		engineNextBytes(buff);
		return buff;
	}

	/*
	 * (non-Javadoc)
	 * 
	 * @see java.security.SecureRandomSpi#engineNextBytes(byte[])
	 */
	@Override
	protected void engineNextBytes(byte[] bytes) {
		/*
		 * All jni calls use the OpenSSL Default SP800-90 DRBG
		 */
		jniFIPSRandBytes(bytes);
	}

	/*
	 * (non-Javadoc)
	 * 
	 * @see java.security.SecureRandomSpi#engineSetSeed(byte[])
	 */
	@Override
	protected void engineSetSeed(byte[] seed) {
		/*
		 * We ingnore any seeding attempts
		 */
	}

}
