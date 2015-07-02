/******************************************************************************
 * The following code belongs to IDevity and is provided though commercial
 * license or by acceptance of an NDA only.
 * 
 * $Id: CardReader80073.java 307 2014-02-03 00:56:22Z tejohnson $
 * 
 * @author Matthew Ambs (matt@idevity.com)
 * @author Eugene Yu (eugene@idevity.com)
 * @author Todd E. Johnson (todd@idevity.com)
 * @author LaChelle Levan (lachelle@idevity.com)
 * 
 * @version $Revision: 307 $
 * 
 * Changed: $LastChangedDate: 2014-02-02 19:56:22 -0500 (Sun, 02 Feb 2014) $
 *****************************************************************************/

package com.idevity.card.reader;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.security.Security;
import java.security.SignatureException;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.Calendar;
import java.util.Enumeration;

import org.keysupport.asn1.ASN1Exception;
import org.keysupport.encoding.Tag;
import org.keysupport.nist80073.cardedge.DynamicAuthTempl;
import org.keysupport.nist80073.cardedge.PIVAPDUInterface;
import org.keysupport.nist80073.cardedge.PIVDataTempl;
import org.keysupport.nist80073.datamodel.CMSSignedDataObject;
import org.keysupport.nist80073.datamodel.PIVCardHolderUniqueID;
import org.keysupport.nist80073.datamodel.PIVCertificate;
import org.keysupport.provider.OpenSSLFIPSProvider;
import org.keysupport.smartcardio.CommandAPDU;
import org.keysupport.smartcardio.ResponseAPDU;
import org.keysupport.util.DataUtil;

import android.content.Context;
import android.content.pm.PackageInfo;
import android.content.pm.PackageManager;
import android.content.pm.PackageManager.NameNotFoundException;
import android.os.Build;
import android.util.Log;

import com.idevity.android.CardChannel;
import com.idevity.android.HistoricalBytes;
import com.idevity.android.InvalidResponseException;
import com.idevity.card.data.CardData80073;

/**
 * @author Matthew Ambs (matt@idevity.com)
 * @author Eugene Yu (eugene@idevity.com)
 * @author Todd E. Johnson (todd@idevity.com)
 * @author LaChelle Levan (lachelle@idevity.com)
 * 
 * @version $Revision: 307 $
 */
public class CardReader80073 {

	private static final String TAG = CardReader80073.class.getSimpleName();

	private boolean debug = false;
	private boolean pop = false;
	private Context ctx;
	private CardChannel channel;
	private CardData80073 carddata;
	private boolean dataavailable = false;
	private int threadcount = 0;
	private StringBuffer log;
	private boolean logupdated = false;
	private boolean isRunning = false;
	private Thread readerThread;
	private long timeStart = System.currentTimeMillis();

	/**
	 * Constructor for CardReader80073.
	 * 
	 * @param ctx
	 *            Context
	 * @param pop 
	 */
	public CardReader80073(Context ctx, boolean debug, boolean pop) {
		this.ctx = ctx;
		this.debug = debug;
		this.pop = pop;
		this.log = new StringBuffer();
		this.timeStart = System.currentTimeMillis();
		if (debug) {
			log("800-73-3 Reader Initialized");
		}
	}

	/**
	 * Method start.
	 * 
	 * @param tag
	 *            CardChannel
	 * @throws IOException
	 */
	public void start(CardChannel tag) {
		this.timeStart = Calendar.getInstance().getTimeInMillis();
		this.channel = tag;
		this.carddata = new CardData80073();
		threadcount++;
		if (debug) {
			log("800-73-3 Reader Thread: " + threadcount);
		}

		Runnable r = new Runnable() {
			@Override
			public void run() {
				try {
					dataavailable = false;
					ResponseAPDU response;
					/*
					 * Select the PIV Application
					 */
					if (debug) {
						PackageManager manager = ctx.getPackageManager();
						PackageInfo info = null;
						String packageName = "";
						int versionCode = -1;
						String moduleVersion = "";
						byte[] moduleSig = new byte[20];
						try {
							info = manager.getPackageInfo(ctx.getPackageName(),
									0);
							packageName = info.packageName;
							versionCode = info.versionCode;
							OpenSSLFIPSProvider openSsl = (OpenSSLFIPSProvider) Security.getProvider("OpenSSLFIPSProvider");
							moduleVersion = openSsl.getOpenSSLVersion();
							openSsl.getOpenSSLFIPSSig(moduleSig);
						} catch (NameNotFoundException e) {
							Log.e(TAG, "Can not obtain Package Info");
						}
						StringBuffer platform_header = new StringBuffer();
						platform_header
								.append("\n########  Device and OS Information ########\n");
						platform_header
								.append("############################################\n");
						platform_header.append("Device Manufacturer:       "
								+ Build.MANUFACTURER + "\n");
						platform_header.append("Device Model:              "
								+ Build.MODEL + "\n");
						platform_header.append("Device Model Code Name:    "
								+ Build.BOARD + "\n");
						platform_header.append("Android Brand:             "
								+ Build.BRAND + "\n");
						platform_header.append("Android Version Code Name: "
								+ Build.VERSION.CODENAME + "\n");
						platform_header.append("Android Rel Version:       "
								+ Build.VERSION.RELEASE + "\n");
						platform_header.append("Android Inc Version:       "
								+ Build.VERSION.INCREMENTAL + "\n");
						platform_header.append("Android SDK Version:       "
								+ Build.VERSION.SDK_INT + "\n");
						platform_header.append("App Package Name:          "
								+ packageName + "\n");
						platform_header.append("App Version Code:          "
								+ versionCode + "\n");
						platform_header.append("OpenSSL Version:           "
								+ moduleVersion + "\n");
						platform_header.append("OpenSSL FIPS Incore Sig:   "
								+ DataUtil.byteArrayToString(moduleSig) + "\n");
						platform_header
								.append("############################################");
						log(platform_header.toString());
					}
					/*
					 * Check historical bytes from the RATS, and see if the PIV Card application is
					 * implicitly selected.  Otherwise, perform an explicit select.
					 */
					log("############   Card Information  ###########");
					byte[] historicalBytes = channel.getHistoricalBytes();
					log("Historical Bytes: " + DataUtil.byteArrayToString(historicalBytes));
					HistoricalBytes hb = new HistoricalBytes(historicalBytes);
					if (debug) {
						log("Application Implicitly Selected: " + (hb.isAppImplicitSelected() ? "Yes":"No"));
						if (hb.isAppImplicitSelected()) {
							String AID = null;
							if (hb.getSelectedAppAID() == null) {
								AID = "Not provided";
							} else {
								AID = DataUtil.byteArrayToString(hb.getSelectedAppAID());
							}
							log("Application Identifier: " + AID);
						}
						log("Selection by full select: " + (hb.allowsFullSelect() ? "Yes":"No"));
						log("Selection by partial select: " + (hb.allowsPartialSelect() ? "Yes":"No"));
					}
					if (!hb.isAppImplicitSelected()) {
						if (debug) {
							log("Selecting PIV Card Application");
						}
						response = transmit(new CommandAPDU(PIVAPDUInterface.SELECT_PIV));
						log("Response from select: " + DataUtil.byteArrayToString(response.getBytes()));
					}
					log("############################################\n");

					/*
					 * Obtain and Store CHUID Object
					 */
					if (debug) {
						log("Getting the CHUID");
					}
					PIVDataTempl chuid = getPIVData(new Tag(Tag.PIV_CHUID));
					if (chuid != null) {
						carddata.setPIVCardHolderUniqueID(chuid);
					}
					/*
					 * Obtain and Store Card Auth Certificate if present
					 */
					if (debug) {
						log("Checking for a Card Auth Certificate");
					}
					PIVCertificate cardAuthPC = getCardAuthCert();
					X509Certificate cardAuth = null;
					
					/*
					 * Check to make sure it is not some silly
					 * empty encoding (suspect this may be the
					 * case for State and HHS creds)
					 */
					
					if (cardAuthPC != null) {
						try {
							cardAuth = cardAuthPC.getCertificate();
						} catch (NullPointerException e) { 
							if (debug) {
								log("Error: Empty Certificate Object Received!");
								Log.e(TAG, "Error: Empty Certificate Object Received!");
							}
						}
						
						if (cardAuth != null) {
							/*
							 * CAK POP Test
							 */
							if (pop) {
								PIVDataTempl cac = getPIVData(new Tag(Tag.PIV_CERT_CARDAUTH));
								if (cac != null) {
									carddata.setCardAuthCertificate(cac);
								}
								CAKChallenge popTest = new CAKChallenge(cardAuth);
								if (debug) {
									log("Performing CAK Proof of Possession Test");
								}
								/*
								 * Transmit enumeration of APDUs and obtain the
								 * signed response.
								 */
								DynamicAuthTempl gaResp = generalAuthenticate(popTest.getGenAuthAPDUs());
								byte[] signature = gaResp.getTemplateValue();
								if (signature != null) {
									carddata.setCAKPoPNonce(popTest.getCAKPoPNonce());
									carddata.setCAKPoPSig(signature);
									if (debug) {
										Log.d(TAG, "Signature: " + DataUtil.byteArrayToString(signature));
									}
								}
							}
						}
					}

					
					/*
					 * Debug Output to pretty print CHUID, verify signature and
					 * pretty print the signature signing cert, and pretty print
					 * the Card Auth Cert
					 */
					if (debug) {
						log("############# BEGIN CHUID #############");
						byte[] chuidData = chuid.getData();
						if (chuidData == null) {
							chuidData = chuid.getEncoded();
						}
						PIVCardHolderUniqueID chuid2 = new PIVCardHolderUniqueID(chuidData);
						log(chuid2.toString());
						log("Verifying CHUID Signature:");
						CMSSignedDataObject chuidSig = null;
						try {
							chuidSig = new CMSSignedDataObject(
									chuid2.getSignatureBytes(),
									chuid2.getSignatureDataBytes());
							chuidSig.setProviderName("OpenSSLFIPSProvider");
						} catch (SignatureException e) {
							log("Problem with Signature: " + e.getMessage());
						}
						if (chuidSig != null) {
							log("######### BEGIN CONTENT SIGNER ########");
							log(chuidSig.getSigner().toString());
							log("######### END CONTENT SIGNER ##########");
							try {
								if (chuidSig.verifySignature(false)) {
									log("Signature Verified!");
								} else {
									log("Signature Verification Failed!");
								}
							} catch (SignatureException e) {
								log("Problem with Signature: " + e.getMessage());
							}
						}
						log("############## END CHUID ##############");
						if (cardAuth != null) {
							log("############# BEGIN CARDAUTH #############");
							log(cardAuth.toString());
							log("############## END CARDAUTH ##############");

							if (carddata.getCAKPoPNonce() != null && carddata.getCAKPoPSig() != null) {
								log("####### BEGIN PROOF OF POSSESSION ########");
								CAKChallenge popVerify = new CAKChallenge(cardAuth, carddata.getCAKPoPNonce(), carddata.getCAKPoPSig());
								try {
									if (popVerify.validatePOP()) {
										log("Proof of Possession Verified!");
									} else {
										log("Proof of Possession Failed!");
									}
								} catch (SignatureException e) {
									log("Problem with Proof of Possession: " + e.getMessage());
								}
								log("######## END PROOF OF POSSESSION #########");
							}

						}
					}
					/*
					 * State that we have a CardData Object available for
					 * consumption
					 */
					setCardData(carddata);
					dataavailable = true;
				} catch (IOException e) {
					Log.e(TAG, "Error: " + e.getMessage());
					if (debug) {
						Log.d(TAG, String.format("Stopping reader thread '%s'",
								readerThread.getName()));
					}
					stop();
					return;
				} catch (NullPointerException e) {
					Log.e(TAG, "Error: " + e.getMessage());
					if (debug) {
						Log.d(TAG, String.format("Stopping reader thread '%s'",
								readerThread.getName()));
					}
					stop();
					return;
				} catch (InvalidResponseException e) {
					log("Invalid Response Received by reader: " + e.getLocalizedMessage());
					Log.e(TAG, "Error: " + e.getMessage());
					if (debug) {
						Log.d(TAG, String.format("Stopping reader thread '%s'",
								readerThread.getName()));
					}
					stop();
					return;
				} catch (CertificateException e) {
					log("Problem with Card Auth Certificate: " + e.getLocalizedMessage());
					Log.e(TAG, "Error: " + e.getMessage());
					if (debug) {
						Log.d(TAG, String.format("Stopping reader thread '%s'",
								readerThread.getName()));
					}
					stop();
					return;
				} catch (ASN1Exception e) {
					log("Problem with CAK POP Test: " + e.getLocalizedMessage());
					Log.e(TAG, "Error: " + e.getMessage());
					if (debug) {
						Log.d(TAG, String.format("Stopping reader thread '%s'",
								readerThread.getName()));
					}
					stop();
					return;
				}
				if (debug) {
					Log.d(TAG, String.format("Stopping reader thread '%s'",
							readerThread.getName()));
				}
				stop();
				return;
			}
		};
		readerThread = new Thread(r); // $codepro.audit.disable
										// disallowUnnamedThreadUsage
		readerThread.setName("800-73 reader thread#" + readerThread.getId());
		readerThread.start();
		isRunning = true;
		if (debug) {
			Log.d(TAG,
					String.format("Started reader thread '%s'",
							readerThread.getName()));
		}
	}

	private void setCardData(CardData80073 carddata) {
		this.carddata = carddata;
	}

	/**
	 * Method transmit.
	 * 
	 * @param command
	 *            CommandAPDU
	 * @return ResponseAPDU
	 * @throws IOException
	 * @throws InvalidResponseException 
	 */
	private ResponseAPDU transmit(CommandAPDU command) throws IOException, InvalidResponseException {
		ResponseAPDU response;
		log(String.format("[%s] --> %s", "Reader",
				DataUtil.byteArrayToString(command.getBytes())));
		//Temp debug logging
		//Log.i(TAG, String.format("[%s] --> %s", "Reader",
		//		DataUtil.byteArrayToString(command.getBytes())));
		response = channel.transmit(command);
		log(String.format("[%s] <-- %s", "Reader",
				DataUtil.byteArrayToString(response.getBytes())));
		//Temp debug logging
		//Log.i(TAG, String.format("[%s] <-- %s", "Reader",
		//		DataUtil.byteArrayToString(response.getBytes())));
		return response;
	}

	/**
	 * Method generalAuthenticate
	 * @throws InvalidResponseException 
	 * @throws IOException 
	 */
	private DynamicAuthTempl generalAuthenticate(Enumeration<CommandAPDU> capdus) throws InvalidResponseException, IOException {

		DynamicAuthTempl gaResp = null;
		CommandAPDU gaapdu = null;
		ResponseAPDU response = null;

		try {
			while (capdus.hasMoreElements()) {
				gaapdu = capdus.nextElement();
				response = transmit(gaapdu);
			}
			if (response == null) {
				throw new IOException("Response was null");
			}
			int status_word = response.getSW();
			int SW1 = response.getSW1();
			int SW2 = response.getSW2();

			if (SW1 == 0x61) {
				ByteArrayOutputStream rbaos = new ByteArrayOutputStream();
				rbaos.write(response.getData());
				while (SW1 == 0x61) {
					// Craft a GET-DATA APDU to collect the bytes remaining
					if (SW2 == 0x00) {
						response = transmit(new CommandAPDU(
								DataUtil.stringToByteArray("00C0000000")));
					} else {
						CommandAPDU remain = new CommandAPDU(0x00, 0xc0, 0x00,
								0x00, SW2);
						response = transmit(remain);
					}
					rbaos.write(response.getData());
					SW1 = response.getSW1();
					SW2 = response.getSW2();
				}
				gaResp = new DynamicAuthTempl(rbaos.toByteArray());
			} else if (status_word == PIVAPDUInterface.PIV_SW_SUCCESSFUL_EXECUTION) {
				if (response.getData().length <= 2) {
					log("Response APDU is empty.");
					gaResp = null;
				} else {
					gaResp = new DynamicAuthTempl(response.getData());
				}
			} else if (status_word == PIVAPDUInterface.PIV_SW_OBJECT_OR_APPLICATION_NOT_FOUND) {
				log("Tag Not Found.");
				gaResp = null;
			} else if (status_word == PIVAPDUInterface.PIV_SW_SECURITY_CONDITION_NOT_SATISFIED) {
				log("Security Condition Not Satisfied");
				gaResp = null;
			} else {
				log("Error");
				gaResp = null;
			}
		} catch (java.io.IOException ex) {
			throw new IOException(ex);
		}
		return gaResp;
	}
	
	/**
	 * Method getPIVData.
	 * 
	 * @param pivObjectTag
	 *            Tag
	 * @return CommandAPDU
	 * @throws IOException
	 */
	public static CommandAPDU getDataAPDU(Tag pivObjectTag) throws IOException {
		ByteArrayOutputStream baos = new ByteArrayOutputStream();
		byte[] tag_bytes = pivObjectTag.getBytes();
		baos.write(PIVAPDUInterface.PIV_GET_DATA_HEADER);
		baos.write(tag_bytes.length + 2);
		baos.write((byte) 0x5c);
		baos.write(tag_bytes.length);
		baos.write(tag_bytes);
		baos.write(0x00);
		return new CommandAPDU(baos.toByteArray());
	}

	/**
	 * Method getPIVData.
	 * 
	 * @param pivObjectTag
	 *            Tag
	 * @return PIVDataTempl
	 * @throws IOException
	 * @throws InvalidResponseException 
	 */
	private PIVDataTempl getPIVData(Tag pivObjectTag) throws IOException, InvalidResponseException {
		PIVDataTempl data = null;
		try {
			ResponseAPDU response = transmit(getDataAPDU(pivObjectTag));
			int status_word = response.getSW();
			int SW1 = response.getSW1();
			int SW2 = response.getSW2();

			if (SW1 == 0x61) {
				ByteArrayOutputStream rbaos = new ByteArrayOutputStream();
				rbaos.write(response.getData());
				while (SW1 == 0x61) {
					// Craft a GET-DATA APDU to collect the bytes remaining
					if (SW2 == 0x00) {
						response = transmit(new CommandAPDU(
								DataUtil.stringToByteArray("00C0000000")));
					} else {
						CommandAPDU remain = new CommandAPDU(0x00, 0xc0, 0x00,
								0x00, SW2);
						response = transmit(remain);
					}
					rbaos.write(response.getData());
					SW1 = response.getSW1();
					SW2 = response.getSW2();
				}
				data = new PIVDataTempl(rbaos.toByteArray());
			} else if (status_word == PIVAPDUInterface.PIV_SW_SUCCESSFUL_EXECUTION) {
				if (response.getData().length <= 2) {
					log("Response APDU is empty.");
					data = null;
				} else {
					data = new PIVDataTempl(response.getData());
				}
			} else if (status_word == PIVAPDUInterface.PIV_SW_OBJECT_OR_APPLICATION_NOT_FOUND) {
				log("Tag Not Found.");
				data = null;
			} else if (status_word == PIVAPDUInterface.PIV_SW_SECURITY_CONDITION_NOT_SATISFIED) {
				log("Security Condition Not Satisfied");
				data = null;
			} else {
				log("Error");
				data = null;
			}
		} catch (java.io.IOException ex) {
			throw new IOException(ex);
		}
		return data;
	}

	/**
	 * Method log.
	 * 
	 * @param msg
	 *            String
	 */
	public void log(String msg) {
		long checkpoint = System.currentTimeMillis() - this.timeStart;
		log.append("[" + checkpoint + "ms]" + msg + "\n");
		logupdated = true;
	}

	/**
	 * Method getCardHolderUniqueID.
	 * 
	 * @return PIVCardHolderUniqueID
	 * @throws IOException
	 * @throws InvalidResponseException 
	 */
	public PIVCardHolderUniqueID getCardHolderUniqueID() throws IOException, InvalidResponseException {
		PIVDataTempl data = getPIVData(new Tag(Tag.PIV_CHUID));
		return new PIVCardHolderUniqueID(data.getData());
	}

	/**
	 * Method getCardAuthCert.
	 * 
	 * @return PIVCertificate
	 * @throws IOException
	 * @throws InvalidResponseException 
	 */
	public PIVCertificate getCardAuthCert() throws IOException, InvalidResponseException {
		PIVDataTempl data = getPIVData(new Tag(Tag.PIV_CERT_CARDAUTH));
		PIVCertificate cert = null;
		if (data != null) {
			cert = new PIVCertificate(data.getData());
		}
		return cert;
	}

	/**
	 * Method cardDataAvailable.
	 * 
	 * @return boolean
	 */
	public boolean cardDataAvailable() {
		return dataavailable;
	}

	/**
	 * Method getData.
	 * 
	 * @return CardData80073
	 */
	public CardData80073 getData() {
		dataavailable = false;
		return carddata;
	}

	/**
	 * Method isRunning.
	 * 
	 * @return boolean
	 */
	public boolean isRunning() {
		return isRunning;
	}

	/**
	 * Method logUpdated.
	 * 
	 * @return boolean
	 */
	public boolean logUpdated() {
		return logupdated;
	}

	/**
	 * Method getLog.
	 * 
	 * @return String
	 */
	public String getLog() {
		logupdated = false;
		String retlog = log.toString();
		log = new StringBuffer();
		return retlog;
	}

	public synchronized void stop() {
		if (debug) {
			Log.d(TAG, "stopping reader thread");
		}
		if (readerThread != null) {
			readerThread.interrupt();
			isRunning = false;

			if (debug) {
				Log.d(TAG, "reader thread running: " + isRunning);
			}
		}
		if (debug) {
			Log.d(TAG, "Resetting reader state");
		}
		if (channel != null) {
			// try {
			if (channel.isConnected()) {
				channel.close();
			}
			channel = null;
			// } catch (IOException e) {
			// Log.w(TAG, "Error closing channel: " + e.getMessage(), e);
			// }
		}
	}

}
