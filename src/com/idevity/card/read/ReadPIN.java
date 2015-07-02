package com.idevity.card.read;

import android.app.Activity;
import android.app.AlertDialog;
import android.app.AlertDialog.Builder;
import android.content.DialogInterface;
import android.view.LayoutInflater;
import android.view.View;
import android.widget.Button;
import android.widget.TextView;

public class ReadPIN {
	// flag values
	public static int NOFLAGS = 0;
	public static int HIDE_INPUT = 1;
	public static int HIDE_PROMPT = 2;
	
	static Float amountDue;
	
	static TextView prompt;
	static TextView promptValue;
	
	static Button btn1;
	static Button btn2;
	static Button btn3;
	static Button btn4;
	static Button btn5;
	static Button btn6;
	static Button btn7;
	static Button btn8;
	static Button btn9;
	static Button btn0;
	static Button btnEnter;
	static Button btnBack;
	
	private String value = "";
	private String addl_text = "";
	private ReadPIN me;
	
	private int flag_hideInput = 0;
	private int flag_hidePrompt = 0;
	
	public interface numbPadInterface {
		public String numPadInputValue(String value);
		public String numPadCanceled();
	}
	
	public String getValue() {
		return value;
	}

	public void setAdditionalText(String inTxt) {
		addl_text = inTxt;
	}
	
	public void show(final Activity a, final String promptString, int inFlags, 
	  final numbPadInterface postrun) {
		me = this;
		flag_hideInput = inFlags % 2;
		flag_hidePrompt = (inFlags / 2) % 2;
		
		Builder dlg = new AlertDialog.Builder(a);
		if (flag_hidePrompt == 0) {
			dlg.setTitle(promptString);
		}
		// Inflate the dialog layout
		LayoutInflater inflater = a.getLayoutInflater();
		View iView = inflater.inflate(R.layout.activity_read_pin, null, false);
		
		// create code to handle the change tender
		prompt = (TextView) iView.findViewById(R.id.pininstructions);
		prompt.setText(addl_text);
		if (addl_text.equals("")) {
			prompt.setVisibility(View.GONE);
		}
		promptValue = (TextView) iView.findViewById(R.id.promptValue);
		
		// Defaults
		value = "";
		promptValue.setText("");

		btn1 = (Button) iView.findViewById(R.id.button1);
		btn2 = (Button) iView.findViewById(R.id.button2);
		btn3 = (Button) iView.findViewById(R.id.button3);
		btn4 = (Button) iView.findViewById(R.id.button4);
		btn5 = (Button) iView.findViewById(R.id.button5);
		btn6 = (Button) iView.findViewById(R.id.button6);
		btn7 = (Button) iView.findViewById(R.id.button7);
		btn8 = (Button) iView.findViewById(R.id.button8);
		btn9 = (Button) iView.findViewById(R.id.button9);
		btn0 = (Button) iView.findViewById(R.id.button0);
		btnEnter = (Button) iView.findViewById(R.id.buttonEnter);
		btnBack = (Button) iView.findViewById(R.id.buttonBack);

		btnEnter.setOnClickListener(new Button.OnClickListener() {
			public void onClick(View v) {
				value = "";
				promptValue.setText("");
			}
		});
		btnBack.setOnClickListener(new Button.OnClickListener() {
			public void onClick(View v) {
				value = "";
				promptValue.setText("");
			}
		});
		btn1.setOnClickListener(new Button.OnClickListener() {
			public void onClick(View v) {
				appendNumber("1");
			}
		});
		btn2.setOnClickListener(new Button.OnClickListener() {
			public void onClick(View v) {
				appendNumber("2");
			}
		});
		btn3.setOnClickListener(new Button.OnClickListener() {
			public void onClick(View v) {
				appendNumber("3");
			}
		});
		btn4.setOnClickListener(new Button.OnClickListener() {
			public void onClick(View v) {
				appendNumber("4");
			}
		});
		btn5.setOnClickListener(new Button.OnClickListener() {
			public void onClick(View v) {
				appendNumber("5");
			}
		});
		btn6.setOnClickListener(new Button.OnClickListener() {
			public void onClick(View v) {
				appendNumber("6");
			}
		});
		btn7.setOnClickListener(new Button.OnClickListener() {
			public void onClick(View v) {
				appendNumber("7");
			}
		});
		btn8.setOnClickListener(new Button.OnClickListener() {
			public void onClick(View v) {
				appendNumber("8");
			}
		});
		btn9.setOnClickListener(new Button.OnClickListener() {
			public void onClick(View v) {
				appendNumber("9");
			}
		});
		btn0.setOnClickListener(new Button.OnClickListener() {
			public void onClick(View v) {
				appendNumber("0");
			}
		});

		dlg.setView(iView);
		dlg.setPositiveButton("Enter", new DialogInterface.OnClickListener() {
			public void onClick(DialogInterface dlg, int sumthin) {
				dlg.dismiss();
				postrun.numPadInputValue(me.getValue());
			}
		});
		dlg.setNegativeButton("Back", new DialogInterface.OnClickListener() {
			public void onClick(DialogInterface dlg, int sumthin) {
				dlg.dismiss();
				postrun.numPadCanceled();
			}
		});
		
		/*
		 * TODO:  Known "bug"
		 * 
		 * Hitting the back button while this class's dialog in the foreground yields a dead app.
		 * 
		 * Somewhat annoying, but this code only generates a warning.
		 * 
		 * "Attempted to finish an input event but the input event receiver has already been disposed."
		 * 
		 * This is due to a callback to the postrun.numPadCanceled(), but this object has already
		 * been destroyed if someone touches the back button to escape out of the dialog.  Since this
		 * object is dead, it cannot act on it, hence the warning.  A future iteration of this class
		 * should be a floating fragment, according to LaChelle.
		 */
		dlg.setOnCancelListener(new DialogInterface.OnCancelListener() {
			
			@Override
			public void onCancel(DialogInterface dialog) {
				postrun.numPadCanceled();
			}
			
		});
		dlg.show();
	}
	
	void appendNumber(String inNumb) {
		value = value + inNumb;
		if (flag_hideInput == 1) {
			promptValue.setText(promptValue.getText() + "*");
		} else {
			promptValue.setText(promptValue.getText() + inNumb);
		}
	}
	
}

