package com.idevity.card.read;

import java.util.Calendar;

import android.annotation.TargetApi;
import android.app.ActionBar;
import android.app.ActionBar.Tab;
import android.app.FragmentTransaction;
import android.content.Intent;
import android.content.SharedPreferences;
import android.nfc.NfcAdapter;
import android.nfc.NfcAdapter.ReaderCallback;
import android.nfc.Tag;
import android.os.Build;
import android.os.Bundle;
import android.preference.PreferenceManager;
import android.support.v4.app.FragmentActivity;
import android.support.v4.view.ViewPager;
import android.util.Log;
import android.view.Menu;
import android.view.MenuItem;

import com.idevity.card.data.CardData80073;

/******************************************************************************
 * The following code belongs to IDevity and is provided though commercial
 * license or by acceptance of an NDA only.
 * 
 * $Id: ReadMain.java 253 2013-11-11 23:30:49Z tejohnson $
 * 
 * @author Matthew Ambs (matt@idevity.com)
 * @author Eugene Yu (eugene@idevity.com)
 * @author Todd E. Johnson (todd@idevity.com)
 * @author LaChelle Levan (lachelle@idevity.com)
 * 
 * @version $Revision: 253 $
 * 
 *          Changed: $LastChangedDate: 2013-11-09 21:01:11 -0500 (Sat, 09 Nov
 *          2013) $
 *****************************************************************************/
public class ReadMain extends FragmentActivity implements ActionBar.TabListener {

	private static final String TAG = ReadMain.class.getSimpleName();
	private static final boolean debug = false;
	Globals g = Globals.getInstance();
	private CardData80073 carddata;
	private String logStringBuffer;
	private SharedPreferences sharedPref;
	NfcAdapter adapter = null;

	/**
	 * The {@link android.support.v4.view.PagerAdapter} that will provide
	 * fragments for each of the three primary sections of the app. We use a
	 * {@link android.support.v4.app.FragmentPagerAdapter} derivative, which
	 * will keep every loaded fragment in memory. If this becomes too memory
	 * intensive, it may be best to switch to a
	 * {@link android.support.v4.app.FragmentStatePagerAdapter}.
	 */
	AppSectionsPagerAdapter mAppSectionsPagerAdapter;

	/**
	 * The {@link ViewPager} that will display the four primary sections of the
	 * app, one at a time.
	 */
	ViewPager mViewPager;

	/**
	 * Method onCreate.
	 * 
	 * @param savedInstanceState
	 *            Bundle
	 */
	@TargetApi(19)
	@Override
	public void onCreate(Bundle savedInstanceState) {
		super.onCreate(savedInstanceState);
		setContentView(R.layout.activity_read_main);

		/*
		 * We will take over the NFC Interface while in the foreground so there
		 * is no additional read attempt.
		 * 
		 * If on KitKat, we will set a filter and ignore any callbacks.
		 */
		/****************** Initialize NFC ******************/
		if (debug) {
			Log.d(TAG, "Getting Adaptor...");
		}
		NfcAdapter adapter = NfcAdapter.getDefaultAdapter(this);
		/*
		 * Platform version specific handling: KitKat
		 */
		if (Build.VERSION.SDK_INT > Build.VERSION_CODES.JELLY_BEAN_MR2) {
			if (debug) {
				Log.d(TAG, "Setting Adaptor up for KitKat");
			}
			ReaderCallback listener = new ReaderCallback() {
				public void onTagDiscovered(Tag tag) {
					/*
					 * Discard the tags here
					 */
					tag = null;
				}
			};
			int flags = NfcAdapter.FLAG_READER_NFC_A
					| NfcAdapter.FLAG_READER_SKIP_NDEF_CHECK
					| NfcAdapter.FLAG_READER_NO_PLATFORM_SOUNDS;
			adapter.enableReaderMode(this, listener, flags, null);
		}

		// Get preferences / settings that have been saved
		// get the show log

		this.sharedPref = PreferenceManager.getDefaultSharedPreferences(this);
		boolean showLog = this.sharedPref.getBoolean(g.getShowLog(), false);

		// Create the adapter that will return a fragment for each of the three
		// primary sections
		// of the app.
		mAppSectionsPagerAdapter = new AppSectionsPagerAdapter(
				getSupportFragmentManager(), this.sharedPref);

		// Set up the action bar.
		final ActionBar actionBar = getActionBar();

		// Specify that the Home/Up button should not be enabled, since there is
		// no hierarchical
		// parent.
		actionBar.setHomeButtonEnabled(true);

		// Specify that we will be displaying tabs in the action bar.
		actionBar.setNavigationMode(ActionBar.NAVIGATION_MODE_TABS);

		// Set up the ViewPager, attaching the adapter and setting up a listener
		// for when the
		// user swipes between sections.
		mViewPager = (ViewPager) findViewById(R.id.pager);
		mViewPager.setAdapter(mAppSectionsPagerAdapter);
		mViewPager
				.setOnPageChangeListener(new ViewPager.SimpleOnPageChangeListener() {
					@Override
					public void onPageSelected(int position) {
						// When swiping between different app sections, select
						// the corresponding tab.
						// We can also use ActionBar.Tab#select() to do this if
						// we have a reference to the
						// Tab.
						actionBar.setSelectedNavigationItem(position);
					}
				});

		/*
		 * Use the following to determine content to show in the tabs. First,
		 * check to see if there is an active intent Also, check to see if there
		 * is an active saved instance state If, active intent - use active
		 * intent; if active intent = null, and saved instance state !null, use
		 * saved instance state; else return user to "main" instructions
		 */
		boolean hasIntent = false;
		boolean hasSavedData = false;

		try {
			if (getIntent().getExtras().getByteArray(g.getCardData()) != null) {
				hasIntent = true;
			}
		} catch (Throwable e) {
			Log.e(TAG, "Error: intent " + e.getMessage());
		}

		try {
			if (g.getCard() != null) {
				hasSavedData = true;
			}
		} catch (Throwable e) {
			Log.e(TAG, "Error: saved instance state " + e.getMessage());
		}

		// if intent, populate the variables with the intent values
		// else if saved instance, populate the same variables with the saved
		// instance state
		// else return user to read800-73 activity to read a new card

		if (hasIntent) {
			logStringBuffer = getIntent().getExtras().getString(
					g.getReaderLog());
			byte[] _data = getIntent().getExtras()
					.getByteArray(g.getCardData());
			this.carddata = new CardData80073(_data);
			if (debug) {
				Log.d(TAG, "Using new card data");
			}
			g.putCard(carddata.toByteArray());
			g.putLogData(logStringBuffer);

		} else if (hasSavedData) {
			logStringBuffer = g.getLogData();
			byte[] _data = g.getCard();
			this.carddata = new CardData80073(_data);
			Log.e(TAG, "Using saved card data");
		} else {
			Intent returnuser = new Intent(this, Read80073.class);
			startActivity(returnuser);
			Log.e(TAG, "No card data found; returning user to read a new card.");
		}

		/*
		 * For each of the sections in the app, add a tab to the action bar.
		 */
		Tab tabA = actionBar.newTab();
		tabA.setText(getString(R.string.TabRead_Title));
		tabA.setTabListener(this);
		actionBar.addTab(tabA);

		// this one will become the CAK tab
		Tab tabB = actionBar.newTab();
		tabB.setText(getString(R.string.TabCert_Title));
		tabB.setTabListener(this);
		actionBar.addTab(tabB);

		// this one will become the CHUID tab
		Tab tabC = actionBar.newTab();
		tabC.setText(getString(R.string.TabChuid_Title));
		tabC.setTabListener(this);
		actionBar.addTab(tabC);

		// this one will become the APDU log tab
		// only set up the tab is the preferences for Show Log = True

		if (showLog) {
			Tab tabD = actionBar.newTab();
			tabD.setText(getString(R.string.TabLog_Title));
			tabD.setTabListener(this);
			actionBar.addTab(tabD);
		}
	}

	/**
	 * Method onTabUnselected.
	 * 
	 * @param tab
	 *            ActionBar.Tab
	 * @param fragmentTransaction
	 *            FragmentTransaction
	 * @see android.app.ActionBar$TabListener#onTabUnselected(ActionBar.Tab,
	 *      FragmentTransaction)
	 */
	@Override
	public void onTabUnselected(ActionBar.Tab tab,
			FragmentTransaction fragmentTransaction) {
	}

	/**
	 * Method onTabSelected.
	 * 
	 * @param tab
	 *            ActionBar.Tab
	 * @param fragmentTransaction
	 *            FragmentTransaction
	 * @see android.app.ActionBar$TabListener#onTabSelected(ActionBar.Tab,
	 *      FragmentTransaction)
	 */
	@Override
	public void onTabSelected(ActionBar.Tab tab,
			FragmentTransaction fragmentTransaction) {
		// When the given tab is selected, switch to the corresponding page in
		// the ViewPager.
		mViewPager.setCurrentItem(tab.getPosition());
	}

	/**
	 * Method onTabReselected.
	 * 
	 * @param tab
	 *            ActionBar.Tab
	 * @param fragmentTransaction
	 *            FragmentTransaction
	 * @see android.app.ActionBar$TabListener#onTabReselected(ActionBar.Tab,
	 *      FragmentTransaction)
	 */
	@Override
	public void onTabReselected(ActionBar.Tab tab,
			FragmentTransaction fragmentTransaction) {
	}

	/**
	 * Method onCreateOptionsMenu.
	 * 
	 * @param menu
	 *            Menu
	 * @return boolean
	 */
	@Override
	public boolean onCreateOptionsMenu(Menu menu) {
		// Inflate the menu; this adds items to the action bar if it is present.
		getMenuInflater().inflate(R.menu.read_main, menu);
		return true;
	}

	/**
	 * Method onOptionsItemSelected.
	 * 
	 * @param item
	 *            MenuItem
	 * @return boolean
	 */
	@Override
	public boolean onOptionsItemSelected(MenuItem item) {
		// Handle item selection
		switch (item.getItemId()) {
		case R.id.action_share:
			shareData();
			return true;
		case R.id.action_about:
			Intent callinfo = new Intent(this, IdevityInfo.class);
			startActivity(callinfo);
			return true;
		case R.id.action_settings:
			Intent callsettings = new Intent(this, SettingsActivity.class);
			startActivity(callsettings);
			return true;
		default:
			return super.onOptionsItemSelected(item);
		}
	}

	private void shareData() {
		Intent sharingIntent = new Intent(android.content.Intent.ACTION_SEND);
		sharingIntent.setType("message/rfc822");
		String mail = g.getLogData();
		Calendar now = Calendar.getInstance();
		String[] defEmail = { this.sharedPref
				.getString(g.getDefaultEmail(), "") };
		String shareSubject = "IDevity ID One Reader Log (Android) - "
				+ now.getTime().toString();
		sharingIntent.putExtra(android.content.Intent.EXTRA_SUBJECT,
				shareSubject);
		sharingIntent.putExtra(android.content.Intent.EXTRA_TEXT, mail);
		sharingIntent.putExtra(android.content.Intent.EXTRA_EMAIL, defEmail);
		startActivity(Intent.createChooser(sharingIntent, "Share Via..."));
	}
	
	@TargetApi(19)
	@Override
	public void onDestroy() {
		if (debug) {
			Log.d(TAG, "onDestroy()");
		}
		/*
		 * Platform version specific handling: KitKat
		 */
		if (Build.VERSION.SDK_INT > Build.VERSION_CODES.JELLY_BEAN_MR2) {
			if (adapter != null) {
				if (debug) {
					Log.d(TAG, "disabling listener");
				}
				try {
					adapter.disableReaderMode(this);
				} catch (Throwable e) {
					Log.e(TAG, "Problem disabling reader mode: " + e.getLocalizedMessage());
				}
			}
		}
		super.onDestroy();
	}

	@TargetApi(19)
	@Override
	public void onPause() {
		if (debug) {
			Log.d(TAG, "onPause()");
		}
		/*
		 * Platform version specific handling: KitKat
		 */
		if (Build.VERSION.SDK_INT > Build.VERSION_CODES.JELLY_BEAN_MR2) {
			if (adapter != null) {
				if (debug) {
					Log.d(TAG, "disabling listener");
				}
				try {
					adapter.disableReaderMode(this);
				} catch (Throwable e) {
					Log.e(TAG, "Problem disabling reader mode: " + e.getLocalizedMessage());
				}
			}
		}
		super.onPause();
	}

}
