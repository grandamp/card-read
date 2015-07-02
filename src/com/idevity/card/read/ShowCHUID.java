package com.idevity.card.read;

import java.security.SignatureException;
import java.security.cert.CertificateExpiredException;
import java.security.cert.CertificateNotYetValidException;
import java.security.cert.X509Certificate;

import org.keysupport.nist80073.cardedge.PIVDataTempl;
import org.keysupport.nist80073.datamodel.CMSSignedDataObject;
import org.keysupport.nist80073.datamodel.PIVCardHolderUniqueID;

import android.os.Bundle;
import android.support.v4.app.Fragment;
import android.util.Log;
import android.view.LayoutInflater;
import android.view.View;
import android.view.ViewGroup;
import android.widget.ImageView;
import android.widget.TextView;

import com.idevity.card.data.CardData80073;

/******************************************************************************
 * The following code belongs to IDevity and is provided though commercial
 * license or by acceptance of an NDA only.
 * 
 * $Id: ShowCHUID.java 286 2013-12-16 23:58:14Z tejohnson $
 * 
 * @author Matthew Ambs (matt@idevity.com)
 * @author Eugene Yu (eugene@idevity.com)
 * @author Todd E. Johnson (todd@idevity.com)
 * @author LaChelle Levan (lachelle@idevity.com)
 * 
 * @version $Revision: 286 $
 * 
 *          Changed: $LastChangedDate: 2013-07-18 15:42:18 -0400 (Thu, 18 Jul
 *          2013) $
 *****************************************************************************/
public class ShowCHUID extends Fragment {

	private static final String TAG = ShowCHUID.class.getSimpleName();
	private static final boolean debug = true;

	/**
	 * Method onCreateView.
	 * 
	 * @param inflater
	 *            LayoutInflater
	 * @param container
	 *            ViewGroup
	 * @param savedInstanceState
	 *            Bundle
	 * @return View
	 */
	@Override
	public View onCreateView(LayoutInflater inflater, ViewGroup container,
			Bundle savedInstanceState) {

		Globals g = Globals.getInstance();
		String issuer = new String();
		String subject = new String();
		String validfrom = new String();
		String validto = new String();
		boolean certvalid = true;
		boolean sigvalid = false;
		CMSSignedDataObject chuidSig = null;
		X509Certificate pcs = null;

		View chuidLayout = inflater.inflate(R.layout.activity_show_chuid,
				container, false);
		// get card data

		byte[] _data = g.getCard();
		CardData80073 carddata = new CardData80073(_data);

		// get chuid
		PIVCardHolderUniqueID chuid = null;
		PIVDataTempl chuidInDataTempl = carddata.getPIVCardHolderUniqueID();
		if (chuidInDataTempl != null) {
			byte[] chuidData = chuidInDataTempl.getData();
			if (chuidData == null) {
				chuidData = chuidInDataTempl.getEncoded();
			}
			chuid = new PIVCardHolderUniqueID(chuidData);
		}		
		if (chuid != null) {
			try {
				// get chuid signature object
				chuidSig = new CMSSignedDataObject(chuid.getSignatureBytes(),
						chuid.getSignatureDataBytes());
				chuidSig.setProviderName("OpenSSLFIPSProvider");
				// validate the signature, don't do PDVAL
				sigvalid = chuidSig.verifySignature(false);
			} catch (SignatureException e) {
				Log.e(TAG, "Error: " + e.getMessage());
			}
			// get x509 cert
			if (chuidSig != null) {
				pcs = chuidSig.getSigner();
			}
			// get values from x509
			if (pcs != null) {
				issuer = pcs.getIssuerDN().getName();
				subject = pcs.getSubjectDN().getName();
				validfrom = pcs.getNotBefore().toString();
				validto = pcs.getNotAfter().toString();
			}

		}

		ImageView sigthumbs = (ImageView) chuidLayout
				.findViewById(R.id.chuidindicator1);
		TextView sigtext = (TextView) chuidLayout
				.findViewById(R.id.chuid1);
		if (sigvalid) {
			sigthumbs.setImageResource(R.drawable.cert_good);
		} else {
			sigthumbs.setImageResource(R.drawable.cert_bad);
			sigtext.setTextColor(getResources().getColor(R.color.idredmain));
		}

		/*
		 * Note to self. I am not thrilled how Java almost forces you to assume
		 * a certificate if valid unless an exception is thrown!
		 */
		TextView vfText = (TextView) chuidLayout
				.findViewById(R.id.chuid4);
		TextView vtText = (TextView) chuidLayout
				.findViewById(R.id.chuid5);
		
		try {
			if (pcs != null) {
				pcs.checkValidity();
			}
		} catch (CertificateNotYetValidException e) {
			certvalid = false;
			vfText.setTextColor(getResources().getColor(R.color.idredmain));
			if (debug) {
				Log.d(TAG, "Error: Authentication Certificate Not Vaid Yet!");
			}
		} catch (CertificateExpiredException e) {
			certvalid = false;
			vtText.setTextColor(getResources().getColor(R.color.idredmain));
			if (debug) {
				Log.d(TAG, "Error: Card Authentication Certificate Expired!");
			}
		}
		ImageView certthumbs = (ImageView) chuidLayout
				.findViewById(R.id.chuidindicator2);
		TextView certtext = (TextView) chuidLayout
				.findViewById(R.id.chuid2);
		if (certvalid && pcs != null) {
			certthumbs.setImageResource(R.drawable.cert_good);
		} else {
			certthumbs.setImageResource(R.drawable.cert_bad);
			certtext.setTextColor(getResources().getColor(R.color.idredmain));
		}

		// setting all values in activity
		TextView editChuidSubject = (TextView) chuidLayout
				.findViewById(R.id.chuid_subject);
		editChuidSubject.setText(subject);

		TextView editValidFrom = (TextView) chuidLayout
				.findViewById(R.id.chuid_date);
		editValidFrom.setText(validfrom);

		TextView editValidTo = (TextView) chuidLayout
				.findViewById(R.id.chuid_expiry);
		editValidTo.setText(validto);

		TextView editIssuer = (TextView) chuidLayout
				.findViewById(R.id.chuid_issuer);
		editIssuer.setText(issuer);

		return chuidLayout;
	}
}
