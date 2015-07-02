package com.idevity.card.read;

import java.io.IOException;
import java.io.InputStream;
import java.util.Calendar;
import java.util.Date;
import java.util.InvalidPropertiesFormatException;
import java.util.Properties;

import org.keysupport.nist80073.cardedge.PIVDataTempl;
import org.keysupport.nist80073.datamodel.FASCN;
import org.keysupport.nist80073.datamodel.PIVCardHolderUniqueID;

import com.idevity.card.data.CardData80073;

import android.content.res.Resources;
import android.os.Bundle;
import android.util.Log;
import android.view.LayoutInflater;
import android.view.View;
import android.view.ViewGroup;
import android.widget.ImageView;
import android.widget.TextView;
import android.support.v4.app.Fragment;

/******************************************************************************
 * The following code belongs to IDevity and is provided though commercial
 * license or by acceptance of an NDA only.
 * 
 * $Id: ShowCard.java 267 2013-11-16 22:44:39Z LaChelle $
 * 
 * @author Matthew Ambs (matt@idevity.com)
 * @author Eugene Yu (eugene@idevity.com)
 * @author Todd E. Johnson (todd@idevity.com)
 * @author LaChelle Levan (lachelle@idevity.com)
 * 
 * @version $Revision: 267 $ 
 * 
 * Changed: $LastChangedDate: 2013-11-16 17:44:39 -0500 (Sat, 16 Nov 2013) $
 *****************************************************************************/
public final class ShowCard extends Fragment {

	private static final String TAG = ShowCard.class.getSimpleName();

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
		View cardLayout = inflater.inflate(R.layout.activity_show_card,
				container, false);

		Date now = Calendar.getInstance().getTime();
		
		byte[] _data = g.getCard();
		CardData80073 carddata = new CardData80073(_data);

		PIVCardHolderUniqueID chuid = null;
		PIVDataTempl chuidInDataTempl = carddata.getPIVCardHolderUniqueID();
		if (chuidInDataTempl != null) {
			byte[] chuidData = chuidInDataTempl.getData();
			if (chuidData == null) {
				chuidData = chuidInDataTempl.getEncoded();
			}
			chuid = new PIVCardHolderUniqueID(chuidData);
		}				
		FASCN fascn = null;
		try {
			fascn = chuid.getFASCN();
		} catch (Throwable e) {
			Log.e(TAG, "Error: " + e.getMessage());
		}

		String ac = new String();
		String sc = new String();
		String cn = new String();
		String pi = new String();
		String oc = new String();
		String oi = new String();
		String poa = new String();
		String expiryDate = new String();
		String guid = new String();
		String agencyname = new String();
		String orgname = new String();
		Date expires = now;

		if (fascn != null) {
			ac = fascn.getAgencyCode();
			sc = fascn.getSystemCode();
			cn = fascn.getCredentialNumber();
			pi = fascn.getPersonIdentifier();
			oc = fascn.getOrganizationalCategory();
			oi = fascn.getOrganizationalIdentifier();
			poa = fascn.getAssociationCategory();
			expiryDate = chuid.getExpirationDate().toString();
			expires = chuid.getExpirationDate();
			guid = chuid.getGUID().toString();
			// agencyname
			// orgname
		}
		
		ImageView sigthumbs = (ImageView) cardLayout
				.findViewById(R.id.validityIndicator1);
		TextView sigtext = (TextView) cardLayout
				.findViewById(R.id.validityLabel);
		TextView vtText = (TextView) cardLayout
				.findViewById(R.id.expirydateLabel);
		
		if (expires.after(now)) {
			sigthumbs.setImageResource(R.drawable.cert_good);
		} else {
			sigthumbs.setImageResource(R.drawable.cert_bad);
			sigtext.setTextColor(getResources().getColor(R.color.idredmain));
			vtText.setTextColor(getResources().getColor(R.color.idredmain));
		}


		// set agency code default
		TextView editAgencyCode = (TextView) cardLayout
				.findViewById(R.id.agencyCode);
		editAgencyCode.setText(ac);
		// set system code default
		TextView editSystemCode = (TextView) cardLayout
				.findViewById(R.id.systemCode);
		editSystemCode.setText(sc);
		// set credential number default
		TextView editCredNumber = (TextView) cardLayout
				.findViewById(R.id.credNumber);
		editCredNumber.setText(cn);
		// set pi number default
		TextView editPersonId = (TextView) cardLayout
				.findViewById(R.id.personId);
		editPersonId.setText(pi);
		// set org category
		String organizationalCategory = oc;
		if (organizationalCategory.equalsIgnoreCase("1")) {
			oc = "Federal";
		} else if (organizationalCategory.equalsIgnoreCase("2")) {
			oc = "State";
		} else if (organizationalCategory.equalsIgnoreCase("3")) {
			oc = "Commercial";
		} else if (organizationalCategory.equalsIgnoreCase("4")) {
			oc = "International";
		} else {
			// Default is "Federal"
			oc = "Federal";
		}
		TextView editOrgCat = (TextView) cardLayout
				.findViewById(R.id.orgCategory);
		editOrgCat.setText(oc);
		// set poa code
		String associationCategory = poa;
		if (associationCategory.equalsIgnoreCase("1")) {
			poa = "Employee";
		} else if (associationCategory.equalsIgnoreCase("2")) {
			poa = "Civil";
		} else if (associationCategory.equalsIgnoreCase("3")) {
			poa = "Executive";
		} else if (associationCategory.equalsIgnoreCase("4")) {
			poa = "Uniformed";
		} else if (associationCategory.equalsIgnoreCase("5")) {
			poa = "Contractor";
		} else if (associationCategory.equalsIgnoreCase("6")) {
			poa = "Affiliate";
		} else if (associationCategory.equalsIgnoreCase("7")) {
			poa = "Beneficiary";
		} else {
			// Default is "Employee"
			poa = "None Specified";
		}
		TextView editPoaCode = (TextView) cardLayout.findViewById(R.id.poaCode);
		editPoaCode.setText(poa);
		// set ord id
		TextView editOrgid = (TextView) cardLayout.findViewById(R.id.orgId);
		editOrgid.setText(oi);
		// set expiry date
		TextView editExpiry = (TextView) cardLayout
				.findViewById(R.id.expiryDate);
		editExpiry.setText(expiryDate);
		// set guid
		TextView editGuid = (TextView) cardLayout.findViewById(R.id.globadId);
		editGuid.setText(guid);

		Resources res = getResources();
		InputStream is = res.openRawResource(R.raw.sp80087);
		Properties codes = new Properties();
		try {
			codes.loadFromXML(is);
		} catch (InvalidPropertiesFormatException e) {
			Log.e(TAG, "Error: " + e.getMessage());
		} catch (IOException e) {
			Log.e(TAG, "Error: " + e.getMessage());
		}

		if (codes.getProperty(ac) == null) {
			agencyname = "Unknown Agency";
		} else {
			agencyname = codes.getProperty(ac);
		}
		/*
		 * set issuing agency from XML data
		 */
		TextView editAgencyname = (TextView) cardLayout
				.findViewById(R.id.issuingAgency);
		editAgencyname.setText(agencyname);

		if (codes.getProperty(oi) == null) {
			orgname = "Unknown Organization";
		} else {
			orgname = codes.getProperty(oi);
		}
		/*
		 * set organization name from XML data
		 */
		TextView editOrgname = (TextView) cardLayout
				.findViewById(R.id.issuingOrg);
		editOrgname.setText(orgname);

		return cardLayout;
	}

}
