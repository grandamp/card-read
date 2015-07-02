package com.idevity.android;

import android.app.Service;
import android.content.Intent;
import android.os.IBinder;

/******************************************************************************
 * The following code belongs to IDevity and is provided though commercial
 * license or by acceptance of an NDA only.
 * 
 * $Id: SmartCardService.java 235 2013-11-09 16:30:34Z tejohnson $
 * 
 * @author Matthew Ambs (matt@idevity.com)
 * @author Eugene Yu (eugene@idevity.com)
 * @author Todd E. Johnson (todd@idevity.com)
 * @author LaChelle Levan (lachelle@idevity.com)
 * 
 * @version $Revision: 235 $
 * 
 *          Changed: $LastChangedDate: 2013-11-07 00:31:22 -0500 (Thu, 07 Nov
 *          2013) $
 *****************************************************************************/
public class SmartCardService extends Service {

	/**
	 * 
	 */
	public SmartCardService() {
		// TODO Auto-generated constructor stub
	}

	/* (non-Javadoc)
	 * @see android.app.Service#onBind(android.content.Intent)
	 */
	@Override
	public IBinder onBind(Intent intent) {
		// TODO Auto-generated method stub
		return null;
	}

}
