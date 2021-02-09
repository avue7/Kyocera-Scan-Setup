#USAGE:
	*** Devoloped and tested on Windows 10 environment. May not work on prior Windows version.

	0. For the beginners: 
		To see and edit source code, right-click file 'SCAN_SETUP_PROMPT_4_PASSWORD.ps1' 
		and select 'edit'. Code should now be opened in default Windows PowerShell ISE.
		Else, open text editor that can edit .ps1 files. 

	   To the Pros: Sorry!!! d^_^b

	1. To add a CONSTANT (hardcoded) password to the script go to line 54 and input the password
		in the string literal. Else, creation of local user will prompt for password at each 
		run. If you hardcode the password please see my disclaimer in the comments for that 
		section. It is safe so long as you take the correct precautions as with any other 
		technology. 

	2. CONSTANTS for local user account name and scans folder name can be specified at line 
		66 and 67. Defaults are: NewUser = 'Zscan', FolderName = 'Scans'.

	3. Double-click the RUN_ME bat file to run the script. Else, right-click the 
		'SCAN_SETUP_PROMPT_4_PASSWORD.ps1' and select 'Run with PowerShell'.

	4. When script finishes, reflect the info results to the Kyocera address book entry. Go to the
		Kyocera printer's WebUI via IP address. Next go to the 'Address Book' menu on the left 
		and choose 'Machine Address Book'. Then click the add button or the entry you would like
		to update and reflect the info on the script to the text box fields of the WebUI. Click 
		the test button on the WebUI after all info is filled. If you see 'Connection OK', you 
		are good to go. Scan a test page to end-user for the final test. 

	*** The three CONSTANTS: CustomPassword, NewUser, and FolderName should be the only 
		CONSTANTS or variables that you would need to modify for customization to your liking.
		If you modify any other code, I cannot guarantee it to work appropriately.

		However, if you have any suggestions, comments, or questions don't hesitate to call me
		at the Avanced Document Concepts Service number: (530) 893-8714. Please report any bugs
		to me at: athit@adcyes.com