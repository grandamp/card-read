package com.idevity.card.read;

import java.security.SignatureException;
import java.security.cert.CertificateExpiredException;
import java.security.cert.CertificateNotYetValidException;
import java.security.cert.X509Certificate;
import java.util.HashMap;

import org.keysupport.nist80073.cardedge.PIVDataTempl;
import org.keysupport.nist80073.datamodel.PIVCertificate;

import android.os.Bundle;
import android.support.v4.app.Fragment;
import android.util.Log;
import android.view.LayoutInflater;
import android.view.View;
import android.view.ViewGroup;
import android.widget.ImageView;
import android.widget.TextView;

import com.idevity.card.data.CardData80073;
import com.idevity.card.reader.CAKChallenge;

/******************************************************************************
 * The following code belongs to IDevity and is provided though commercial
 * license or by acceptance of an NDA only.
 * 
 * $Id: ShowCert.java 299 2013-12-23 00:40:06Z tejohnson $
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
public class ShowCert extends Fragment {

	private static final String TAG = ShowCert.class.getSimpleName();
	private static final boolean debug = false;

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

		byte[] _data = g.getCard();
		CardData80073 carddata = new CardData80073(_data);

		X509Certificate cardAuth = null;
		String issuer = new String();
		String subject = new String();
		String validfrom = new String();
		String validto = new String();
		try {
			PIVCertificate pca = null;
			PIVDataTempl dataTempl = carddata.getCardAuthCertificate();
			if (dataTempl != null) {
				byte[] data = dataTempl.getData();
				if (data == null) {
					data = dataTempl.getEncoded();
				}
				pca = new PIVCertificate(data);
			}			
			cardAuth = pca.getCertificate();
		} catch (NullPointerException e) { 
			if (debug) {
				Log.d(TAG, "Error: No Card Authentication Certificate Received");
			}
		} catch (Throwable e) {
			Log.e(TAG, "Error: " + e.getMessage());
		}
		if (cardAuth != null) {
			/*
			 * The default implementation does not decode the
			 * DN in a very human friendly form.  The following
			 * Map and Format variables will help to better decode
			 * the X500Principal object to a String value.
			 */
			HashMap<String, String> oidMap = new HashMap<String, String>();
			oidMap.put("2.5.4.5", "SERIALNUMBER");
			String dnFormat = "RFC1779";
			/*
			 * Get the values from the certificate
			 */
			issuer = cardAuth.getIssuerX500Principal().getName(dnFormat, oidMap);
			subject = cardAuth.getSubjectX500Principal().getName(dnFormat, oidMap);
			validfrom = cardAuth.getNotBefore().toString();
			validto = cardAuth.getNotAfter().toString();
			/*
			 * Populate the UI
			 */
			View certLayout = inflater.inflate(R.layout.activity_show_cert,
					container, false);
			ImageView valPeriodIndicator = (ImageView) certLayout
					.findViewById(R.id.cert_ind_vp);
			ImageView popIndicator = (ImageView) certLayout
					.findViewById(R.id.cert_ind_pop);
			TextView valPeriodLabel = (TextView) certLayout
					.findViewById(R.id.cert_vp_label);
			TextView popLabel = (TextView) certLayout
					.findViewById(R.id.cert_pop_label);
			TextView vfText = (TextView) certLayout
					.findViewById(R.id.cert_nb_label);
			TextView vtText = (TextView) certLayout
					.findViewById(R.id.cert_na_label);
			/*
			 * Assume the cert is good unless an exception
			 * is thrown below.
			 */
			valPeriodIndicator.setImageResource(R.drawable.cert_good);

			/*
			 * Note to self.  I am not thrilled how Java almost forces you
			 * to assume a certificate if valid unless an exception is thrown!
			 */
			try {
				cardAuth.checkValidity();
			} catch(CertificateNotYetValidException e) {
				valPeriodIndicator.setImageResource(R.drawable.cert_bad);
				valPeriodLabel.setTextColor(getResources().getColor(R.color.idredmain));
				vfText.setTextColor(getResources().getColor(R.color.idredmain));
				if (debug) {
					Log.d(TAG, "Error: Authentication Certificate Not Valid Yet!");
				}
			} catch(CertificateExpiredException e) {
				valPeriodIndicator.setImageResource(R.drawable.cert_bad);
				valPeriodLabel.setTextColor(getResources().getColor(R.color.idredmain));
				vtText.setTextColor(getResources().getColor(R.color.idredmain));
				if (debug) {
					Log.d(TAG, "Error: Card Authentication Certificate Expired!");
				}
			}
			CAKChallenge popVerify = new CAKChallenge(cardAuth, carddata.getCAKPoPNonce(), carddata.getCAKPoPSig());
			try {
				if (popVerify.validatePOP()) {
					popIndicator.setImageResource(R.drawable.cert_good);
					if (debug) {
						Log.d(TAG, "Proof of Possession Verified!");
					}
				} else {
					popIndicator.setImageResource(R.drawable.cert_bad);
					popLabel.setTextColor(getResources().getColor(R.color.idredmain));
					if (debug) {
						Log.d(TAG, "Proof of Possession Failed!");
					}
				}
			} catch (SignatureException e) {
				popIndicator.setImageResource(R.drawable.cert_bad);
				popLabel.setTextColor(getResources().getColor(R.color.idredmain));
				if (debug) {
					Log.d(TAG, "Problem with Proof of Possession: " + e.getMessage());
				}
			}
			TextView editCertSubject = (TextView) certLayout
					.findViewById(R.id.cert_sub_dn);
			editCertSubject.setText(subject);

			TextView editValidFrom = (TextView) certLayout
					.findViewById(R.id.cert_nb_date);
			editValidFrom.setText(validfrom);

			TextView editValidTo = (TextView) certLayout
					.findViewById(R.id.cert_na_date);
			editValidTo.setText(validto);

			TextView editIssuer = (TextView) certLayout
					.findViewById(R.id.cert_iss_dn);
			editIssuer.setText(issuer);
			return certLayout;
		} else {
			View certLayout = inflater.inflate(R.layout.activity_no_cert,
					container, false);
			return certLayout;
		}
	}
}
