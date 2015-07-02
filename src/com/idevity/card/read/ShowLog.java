package com.idevity.card.read;

import android.os.Bundle;
import android.view.LayoutInflater;
import android.view.View;
import android.view.ViewGroup;
import android.widget.ScrollView;
import android.widget.TextView;
import android.support.v4.app.Fragment;

/******************************************************************************
 * The following code belongs to IDevity and is provided though commercial
 * license or by acceptance of an NDA only.
 * 
 * $Id: ShowLog.java 196 2013-07-15 15:12:55Z tejohnson $
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
public class ShowLog extends Fragment {

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

		// get the log string buffer from the fragment activity intent

		String logStringBuffer = g.getLogData();

		// Create the view
		View log = inflater.inflate(R.layout.activity_show_log, container,
				false);

		// Get the text view associated with the log
		TextView fullLog = (TextView) log.findViewById(R.id.readerlog2);
		ScrollView scroll = (ScrollView) log.findViewById(R.id.scrollViewLog);

		fullLog.setText(logStringBuffer);
		scroll.fullScroll(View.FOCUS_DOWN);

		// return the view
		return log;
	}

}
