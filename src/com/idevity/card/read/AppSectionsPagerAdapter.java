package com.idevity.card.read;

import android.content.SharedPreferences;
import android.support.v4.app.Fragment;
import android.support.v4.app.FragmentManager;
import android.support.v4.app.FragmentPagerAdapter;

/******************************************************************************
 * The following code belongs to IDevity and is provided though commercial
 * license or by acceptance of an NDA only.
 * 
 * $Id: AppSectionsPagerAdapter.java 196 2013-07-15 15:12:55Z tejohnson $
 * 
 * @author Matthew Ambs (matt@idevity.com)
 * @author Eugene Yu (eugene@idevity.com)
 * @author Todd E. Johnson (todd@idevity.com)
 * @author LaChelle Levan (lachelle@idevity.com)
 * 
 * @version $Revision: 196 $ 
 * 
 * Changed: $LastChangedDate: 2013-07-15 11:12:55 -0400 (Mon, 15 Jul 2013) $
 *****************************************************************************/
public class AppSectionsPagerAdapter extends FragmentPagerAdapter {

	private Globals g = Globals.getInstance();
	private boolean showLog = false;

	/**
	 * Constructor for AppSectionsPagerAdapter.
	 * 
	 * @param fm
	 *            FragmentManager
	 */
	public AppSectionsPagerAdapter(FragmentManager fm,
			SharedPreferences sharedPref) {
		super(fm);
		this.showLog = sharedPref.getBoolean(g.getShowLog(), false);
	}

	/**
	 * Method getItem.
	 * 
	 * @param i
	 *            int
	 * @return Fragment
	 */
	@Override
	public Fragment getItem(int i) {
		switch (i) {
		case 0:

			return new ShowCard();

		case 1:
			// change to show cert
			return new ShowCert();

		case 2:
			// change to show chuid
			return new ShowCHUID();

		case 3:
			// show log
			return new ShowLog();

		default:
			return new ShowCard();
		}

	}

	/**
	 * Method getCount.
	 * 
	 * @return int
	 */
	@Override
	public int getCount() {
		int tabs = 3;
		if (showLog) {
			tabs = 4;
		}
		return tabs;
	}

}