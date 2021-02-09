## 
# SCAN_SETUP_PROMPT_4_PASSWORD
#
# This is a simple, interactive, PowerShell script that will do the following:
#     1. Creates a new local user if the user defined is not found on the running computer.
#     2. Creates a new folder called 'Scans' in the root C drive if not found. If folder is found,
#        migration to a new specified folder is possible.
#     3. Shares the folder created.
#     4. Checks and sets the permission and ACL rules for the created local user.
#     5. Creates a new shortcut to the 'Scans' folder on the desktop.
#     6. Pins the 'Scans' folder to the 'Quick Access' toolbar in file explorer for easy access.
#     7. Gets current network profile. If current profile is 'Public', switch to 'Private' if not 
#        on a domain, or switch to 'Domain' if on a domain. This method is a mitigation effort for 
#        future network changes that can break scanning, yet not allow for file and folder sharing
#        on the public network profile.
#     8. Enables the 'File and Printer Sharing' firewall rules for the 'Domain' or 'Private' profile.
#     9. Enables the running computer to be discoverable by turning on the 'Turn on Network Discovery'
#        option for the 'Domain' or 'Private' profile.
#    10. Displays the final information needed to be reflected on the Kyocera printer's address book
#        entry.
#
# The current execution policy for the script is display for debugging and awareness purposes. This script
# runs on the 'Bypass' execution policy. What this means is that by running this script, the running computer 
# retains its execution policy for running scripts and this script only runs on an 'on-demand', 'one-time', allowance. 
# 
# If you are reading this, this means you are curious and are taking security precautions. When developing 
# this tool, I had that in mind as well. Here are some steps you can take to ensure that scripts can't be 
# run unintentionally:
#
#     1. Run command 'Get-ExecutionPolicy' in elevated-mode in PowerShell."
#     2. If return is other than 'Restricted', then in elevated-mode in PowerShell"
#        run 'Set-ExecutionPolicy Restricted'.
#
# On the side-note: according to Microsoft, this feature of Windows is not meant to be a security system
# that restricts user actions. Instead it acts to set basic rules so users do not voilate them unintentionally.     
# 
# By: Athit Vue
# Date: 11/06/2020
# Last modified: 12/26/2020


####################### CUSTOM PASSWORD HARDCODED #####################

# Serves as a CONSTANT for password without asking for a password 
# everytime the script runs. If string is empty, script will prompt for 
# password at new local user creation. Enter the password you want to 
# hardcode as plaintext in the "".

# Disclaimer: please use this feature wisely. If you use this feature, please 
# do not store this script in devices you do not trust. I recommend storing 
# this script in a flash drive and only run it locally on the flash drive if 
# you hardcode the password here. 

$CustomPassword = ""

######################### DEFAULT CONSTANTS ###########################

# You can change these defaults to your preferred string literals. 

# - NewUser:    referrenced throughout code as the default local user we want to give
#               shared folder access to.
# - FolderName: referrenced throughout code as the default shared 'Scans' folder that we 
#               want the scans from the Kyocera to go to. Code is hardcoded to find and 
#               create this folder in the root path of the C drive.

$NewUser = "Zscan"
$FolderName = "Scans"

######################### SET-UP: ELEVATED ############################

# Sets up the script to run in elevated mode if not. This is to allow the batch script that is calling 
# this file to be able to run without it being in elevated mode. 

if (!([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] "Administrator")) { 
    Start-Process powershell.exe "-NoProfile -ExecutionPolicy Bypass -File `"$PSCommandPath`"" -Verb RunAs; 
    exit 
}

######################### FUNCTION DEFINITIONS GOES HERE ################################

##
# ConfirmPassword
#
# Confirms if password is incorrect. 
#
# @param <string> UserName The username to be created.
# @return <string> Password The confirmed password.
function ConfirmPassword($UserName) {
	$Password = Read-Host "	Enter $($UserName)'s password to create the account" -AsSecureString
	$ConfirmedPassword = Read-Host "	Confirm password" -AsSecureString
	
	$Password_text = [Runtime.InteropServices.Marshal]::PtrToStringAuto([Runtime.InteropServices.Marshal]::SecureStringToBSTR($Password))
	$ConfirmedPassword_text = [Runtime.InteropServices.Marshal]::PtrToStringAuto([Runtime.InteropServices.Marshal]::SecureStringToBSTR($ConfirmedPassword))
	
	while ($Password_text -ne $ConfirmedPassword_text) {
		Write-Host "	Error: passwords do not match!" -fore red
		$Password = Read-Host "	Enter $($UserName)'s password to create the account" -AsSecureString
		$ConfirmedPassword = Read-Host "	Confirm password" -AsSecureString

		$Password_text = [Runtime.InteropServices.Marshal]::PtrToStringAuto([Runtime.InteropServices.Marshal]::SecureStringToBSTR($Password))
		$ConfirmedPassword_text = [Runtime.InteropServices.Marshal]::PtrToStringAuto([Runtime.InteropServices.Marshal]::SecureStringToBSTR($ConfirmedPassword))

		if ($Password_text -eq $ConfirmedPassword_text) {
			break
		}	
	}

	return $Password
}

##
# PinToQuickAccess
#
# Pins the folder to the quick access toolbar.
#
# @param <string> FolderName the folder name of the folder to pin to the quick access toolbar. 
# @return <string> True or false if successful or not. 
function PinToQuickAccess($FolderName) {
  Try
  {
    Write-Host "        Pinning <$($FolderName)> folder to the 'Quick Access' toolbar..."
    $QA = New-Object -com Shell.Application -ErrorAction Stop
    $QA.Namespace("C:\$($FolderName)").Self.InvokeVerb("pintohome")
    Write-Host "        Successfully pinned <$($FolderName)> folder to the 'Quick Access' toolbar!" -fore Green
    Write-Host ""
  }
  Catch
  {
    Write-Host "        Error: cannot pin <$($FolderName)> folder to 'Quick Access' toolbar:" -fore Red
    Write-Host "        ==> $($_.Exception.Message)" -fore Red
    Write-Host ""
  }
}

##
# CreateNewLocalUser
#
# Creates a new local user to the local user group. First attempt will be hardcoded as Zscan. 
# If first attempt fails, user can then specify which user name. 
# 
# @param <string> UserName String name of the username.
# @param <boolean> CustomUserFlag True or false flag if custom name or not.
# @return <string> True or false if success or not
function CreateNewLocalUser($UserName, $CustomUserFlag) {
  Try
  {
    $Password = $Null

    if ($CustomPassword -ne "") {
        if ($CustomUserFlag) {
            $Password = ConfirmPassword $UserName
        } else {
            $Password = ConvertTo-SecureString $CustomPassword -AsPlainText -Force        
        }
    } else {
        $Password = ConfirmPassword $UserName
    }

	New-LocalUser $UserName -Password $Password -FullName "Kyocera Scanner" -Description "Local user account for Kyocera scanner." -ErrorAction Stop
	Write-Host " "
	return "true"
  }
  Catch
  {
	Write-Host "	Error: cannot create user <$($UserName)>: $($_.Exception.Message)" -fore red
	Write-Host " "
	return "false"
  }
}

##
# GetZscanLocalUser
#
# Check and see if Zscan exists, if not automatically create him. 
# If account already exists need to return false to prompt what user would like to do.
# 
# @return <string> True or false True if zscan was created false if zscan already exists. 
function GetZscanLocalUser() {
  Try
  {
    $RetVal = Get-LocalUser -Name $NewUser -ErrorAction Stop
    
    Write-Host "        <$($NewUser)> user already exists!" -fore green
    return "false" 
  }
  Catch
  {
    Write-Host "        $($_.Exception.Message) Creating new <$($NewUser)> user..." -fore red

    $RetVal = CreateNewLocalUser $NewUser $False

    if ($RetVal -eq "true") {
        Write-Host "        New <$($NewUser)> user created successfully!" -fore green
        return "true"
    } else {
        return "false"
    }
  }
}

##
# DeleteLocalUser
# 
# Deletes the local user account.
# 
# @param <string> UserName The string name of the local user account to delete.
# @return <string> True or false if deletion was successful or not.
function DeleteLocalUser($UserName) {
  Try
  {
	Remove-LocalUser -Name $UserName -ErrorAction Stop
	Write-Host "	Deleted local user account <$($UserName)> successfully!" -fore green
    Write-Host ""
	return "true"
  }
  Catch
  {
	Write-Host "	Error: $($_.Exception.Message)" -fore red
    Write-Host ""
	return "false"	
  }
}

##
# CreateNewFolderInCDrive
# 
# Creates a new folder on the C drive. Argument first defaults to 'Scans' as folder name, then will 
# allow end-user to specify if 'Scans' folder already exist. 
# 
# @param <string> FolderName The name of the folder to be created
# @return <string> Returns string true or false if success or not
function CreateNewFolderInCDrive($FolderName) {
  Try
  {
	New-Item -ItemType Directory -Path C:\$FolderName -ErrorAction Stop
	Write-Host "	New folder, <C:\$($FolderName)>, created successfully!" -fore green 
	return "true"
  }
  Catch 
  {
	Write-Host "	Error: $($_.Exception.Message)" -fore red

	$FolderItems = (Get-ChildItem C:\$FolderName | Measure-Object).Count 

	if($FolderItems -gt 0)
	{
		Write-Host "	==> The folder contains <$($FolderItems)> items." -fore red
	} elseif ($FolderItems -eq 0) {
		Write-Host "	==> The folder is empty." -fore red
	}
	
	Write-Host " "
	return "false"
  }
}

##
# CopyOverItemsToNewFolder
# 
# Copies over the items from Scans folder to new folder.
# @param <string> DestFolder The destination folder name
# @return <string> True or false if successful or not. 
function CopyOverItemsToNewFolder($OriginFolder, $DestFolder) {
  Try
  {
  	Copy-Item -Force -Recurse "C:\$($OriginFolder)\*" -Destination "C:\$($DestFolder)" -ErrorAction Stop
	Write-Host "	Successfully copied items from <C:\$($OriginFolder)> to <C:\$($DestFolder)>" -fore green
	return "true"	  
  }
  Catch
  {
	Write-Host "	Error:$($_.Exception.Message)" -fore red
	Write-Host " "
	return "false"
  }
}

##
# DeleteScansFolderInCDrive
#
# Deletes the Scans folder in root of C drive.
#
# @return <string> True or false if successful or not.
function DeleteScansFolderInCDrive($FolderName) {
  Try
  {
	Remove-Item "C:\$($FolderName)" -Recurse -ErrorAction Stop
    	Write-Host "	Successfully deleted the <C:\$($FolderName)> folder!" -fore Green
    	return "true"
  }
  Catch 
  {
    	Write-Host "	Error:$($_.Exception.Message)" -fore Red
    	Write-Host ""
    	return "false"
  }
}

##
# ShareFolder
# 
# Shares the folder passed in the arugment as a new SMB shared folder.
#
# @param <string> FolderName The new folder to be shared.
# @param <string> True or False if sharing the folder was success or not.
function ShareFolder($FolderName) {
   Try
   {
        Write-Host "        Setting <$FolderName> folder as shared folder..."
        New-SmbShare -Name $FolderName -Path "C:\$($FolderName)" -ErrorAction Stop
        Write-Host "        Successfully set <$FolderName> folder as shared folder!" -fore Green
        Write-Host ""
        return "true"
   }
   Catch
   {
        Write-Host "        Error setting up <$($FolderName)> folder as a shared folder: $($_.Exception.Message)" -fore Red
        Write-Host ""
        return "false"
   }
}
##
# AddSecurityToSharedFolder
# 
# Adds the user to the shared folder in ACL.
#
# @param <string> FolderName The folder we need to add security allowance for.
# @param <string> NewUser The user to be added to the security allowance.
# @return <string> True or false if succeeded or not.
function AddSecurityToSharedFolder($FolderName, $NewUser) {
   Try
   {
        Write-Host "        Setting ACL Rules to <$($FolderName)> folder..."

        $ACL = Get-Acl "C:\$($FolderName)" -ErrorAction Stop
        $AR = New-Object System.Security.AccessControl.FileSystemAccessRule($($NewUser), "FullControl", "ContainerInherit,ObjectInherit", "None", "Allow") -ErrorAction Stop
        $ACL.SetAccessRule($AR)
        Set-Acl "C:\$($FolderName)" $ACL -ErrorAction Stop

        Write-Host "        Successfully added ACL rules to the <$($FolderName)> folder!" -fore Green
        Write-Host ""
        return "true"
   }
   Catch 
   {
        Write-Host "        Error setting ACL security: $($_.Exception.Message)" -fore Red
        Write-Host ""
        return "false"
   }
}

##
# AddPermissionToShareFolder
#
# Adds permission to the shared folder.
#
# @param <string> FolderName The name of the folder being shared.
# @param <string> NewUser The user we want to give permissions to.
# @return <string> True or false if successfully set or not.
function AddPermissionToShareFolder($FolderName, $NewUser) {
   Try
   {
        Write-Host "        Setting permissions in shared folder <$($FolderName)> for user <$($NewUser)>..."
        Grant-SmbShareAccess -Name $FolderName -AccountName "$($env:COMPUTERNAME)\$($NewUser)" -AccessRight Full -Force -ErrorAction Stop
        Write-Host "        Successfully added permissions to the <$($FolderName)> folder for <$($NewUser)>!" -fore Green
        Write-Host " "

        $AddSecurityResponse = AddSecurityToSharedFolder $FolderName $NewUser

        if ($AddSecurityResponse -eq "true") {
            return "true"    
        } else {
            return "false"
        }
   }
   Catch 
   {
        Write-Host "        Error setting permissions to the <$($FolderName)> folder for user <$($NewUser)>!" -fore red
        Write-Host ""
        return "false"
   }
}

## 
# CheckForScansFolder
#
# Checks to see if a folder named 'Scans' already exist on the root path in C drive.
#
# BIG TODO: Allow the user to specify a folder name other than 'Scans', grab the full path, 
#           return it, and use it as the scans folder. A few select of our clients scans
#           to other locations other than 'Scans' in the c drive. 
#
# @return <string> Returns true or false if scans folder already exist
function CheckForScansFolder() {
   Try
   {
        Test-Path C:\Scans -PathType Container -ErrorAction Stop
        Write-Host "        Scans folder already exists!" -fore green
        
        $FolderItems = (Get-ChildItem C:\Scans | Measure-Object).Count 

	    if($FolderItems -gt 0)
	    {
		    Write-Host "	==> The folder contains <$($FolderItems)> items." -fore green
	    } elseif ($FolderItems -eq 0) {
		    Write-Host "	==> The folder is empty." -fore green
    	}

        Write-Host ""
        return "true"
   }
   Catch
   {
        Write-Host "        Error: $($_.Exception.Message)" -fore red
        Write-Host ""
        return "false"
   }
}

##
# CreateScansShortCutOnDesktop
#
# Creates the Scans or foldername shortcut for scanning 
# on the desktop.
#
# @param <string> FolderName The foldername of the folder to create the shortcut for.
function CreateScansShortCutOnDesktop($FolderName) {
  Try 
  {
        Write-Host "        Creating shortcut on Desktop for the <$($FolderName)> folder..."
        $WshShell = New-Object -ComObject WScript.Shell -ErrorAction Stop
        $Desktop = [System.Environment]::GetFolderPath('Desktop')
        $Lnk = $WshShell.CreateShortCut($Desktop+"\$($FolderName) - Shortcut.lnk")
        $Lnk.TargetPath = "C:\$($FolderName)"
        $Lnk.Save()

        Write-Host "        Successfully created shortcut for the <$($FolderName)> folder!" -fore Green
        Write-Host ""
  }
  Catch
  {
        Write-Host "        Error: Something happened can't create shortcut: $($_.Exception.Message)" -fore Red
        Write-Host ""
  }
}

##
# GetNetworkConnectionProfile
#
# Gets the current connection profile for the running computer.
# 
# @return <string> NetworkProfile Returns the connection profile that the computer is connected on. 
# @return <string> False if running computer is not connected to the network.
function GetNetworkConnectionProfile() {
  Try 
  {
        Write-Host "        Getting current network profile..."
        $NetworkProfile = Get-NetConnectionProfile | Select -ExpandProperty NetworkCategory -ErrorAction Stop
        return $NetworkProfile
  }
  Catch
  {
        Write-Host "        Error: Could not get connection profile: $($_.Exception.Message)" -fore Red
        Write-Host ""
        return "false"
  }
}

##
# ChangeNetworkProfileFromPublicToPrivate
#
# Changes the current network profile from public to private.
#
# @param <string> CurrentNetProfile The current network profile obtained.
# @return <string> CurrentNetProfile The current network profile after switching.
# @return <string> False if could not set from public to private.
function ChangeNetworkProfileFromPublicToPrivate($CurrentNetProfile) {
  Try
  {
        $CurrentNetProfile = Set-NetConnectionProfile -NetworkCategory Private -PassThru | Select -ExpandProperty NetworkCategory -ErrorAction Stop 
        return $CurrentNetProfile     
  }
  Catch
  {
        Write-Host "        Error: Could not set network profile from PUBLIC to PRIVATE: $($_.Exception.Message)" -fore Red
        return "false"
  }
}

##
# SetFireWallRulesForFileAndPrinterSharing
#
# Enables the file and printer sharing at the firewall.
#
# @param <string> CurrentNetProfile The net profile(s) we want to turn on file
#                 and printer sharing for. 
# @param <string> ErrorCounter The counter for errors for final display.
# @return <string> True or false if enabled successfully or not. 
function SetFireWallRulesForFileAndPrinterSharing($CurrentNetProfile, $ErrorCounter) {
  Try
  {
        Write-Host "        Enabling 'File and Printer Sharing' for the <$($CurrentNetProfile)> profile(s)..."
        $EnableStatus = Set-NetFirewallRule -DisplayGroup "File And Printer Sharing" -Enabled True -Profile $CurrentNetProfile -PassThru -ErrorAction Stop | Select -ExpandProperty Enabled
        Write-Host "        Successfully enabled 'File and Printer Sharing' for the <$($CurrentNetProfile)> profile(s)!" -fore Green
        Write-Host ""
        return $EnableStatus
  }
  Catch
  {
        Write-Host "        Error: enabling 'File and Printer Sharing' for <$($CurrentNetProfile)> profile(s) failed: $($_.Exception.Message)"
        $ErrorCounter = $ErrorCounter + 1
        Write-Host ""
        return "false"
  }
}

##
# TurnOnNetworkDiscovery
# 
# Turns on the network discovery for selected network profiles.
#
# @param <string> Profiles The profile or profiles that network discovery 
#                 should be turned on for.
# @param <string> ErrorCounter The counter for errors for final display.
# @return <string> True or false depending on if it was a success or not.
function TurnOnNetworkDiscovery($Profiles, $ErrorCounter) {
  Try 
  {
        Write-Host "        Enabling 'Turn on Network Discovery' for the <$($Profiles)> profile(s)..."
        $EnableStatus = Set-NetFireWallRule -DisplayGroup "Network Discovery" -Enabled True -Profile $Profiles -PassThru -ErrorAction Stop | Select -ExpandProperty Enabled 
        Write-Host "        Successfully enabled 'Turn on Network Discovery' for the <$($Profiles)> profile(s)!" -fore Green
        Write-Host ""
        return $EnableStatus
  }
  Catch
  {
        Write-Host "        Error: enabling 'Turn on Network Discovery' for <$($Profiles)> profile(s) failed: $($_.Exception.Message)"
        $ErrorCounter = $ErrorCounter + 1
        Write-Host ""
        return "false"  
  }
}

##########################################################################################

Write-Host ""
Write-Host "        #### Welcome! We will be adding Zscan as a local account on this computer." -fore green
Write-Host "        #### Next, we will create a Scans folder and set the appropriate permissions for " -fore green
Write-Host "        #### Zscan to this folder. We'll then create a shorcut of the scans folder on the " -fore Green
Write-Host "        #### desktop and attempt to apply the appropriate network settings to mitigate future" -fore Green
Write-Host "        #### issues with our setup. Good luck and have fun!" -fore Green
Write-Host "        #### " -fore Green
Write-Host "        #### Hint.Hint: you may use me to re-apply settings and help with troubleshooting" -fore Green
Write-Host "        #### scanning issues on the client side." -fore Green
Write-Output ""

Read-Host -Prompt "	Press <Enter> to continue..."

$ErrorCounter = 0

# CREATE THE LOCAL USER 

$Counter = 0
$RetVal = ""

Write-Host "        ########################### ZSCAN CREATION #############################" -fore DarkCyan
Write-Host ""

# This while loop terminates at the creation of a new user, recreation of Zscan, or user descretion.
while ($Counter -ge 0) {
  If ($Counter -eq 0) {
    $RetVal = GetZscanLocalUser
  }

  $Counter = $Counter + 1

  if ($RetVal -eq "false") {
    Write-Host ""
	Write-Host "	Would you like to create a new user or delete Zscan?"
	Write-Host "	==> Options:"
	Write-Host "		(1) - create new user"
	Write-Host "		(2) - delete <$($NewUser)>"
	Write-Host " 		(3) - delete and recreate <$($NewUser)>"
	Write-Host "		(4) - move on to <$($FolderName)> folder creation"
	$NewUserPrompt = Read-Host -Prompt "	"
	if ($NewUserPrompt -eq "1") {
        Write-Host ""
		$NewUser = Read-Host -Prompt "	Enter new user name"
		$RetVal = CreateNewLocalUser $NewUser $True
    } elseif ($NewUserPrompt -eq "2") {
        Write-Host ""
        $DeletedUser = DeleteLocalUser $NewUser
        if ($DeletedUser -eq "true") {
           $NewUser = Read-Host -Prompt "	Enter new user name"
           $RetVal = CreateNewLocalUser $NewUser $True
        }
	} elseif ($NewUserPrompt -eq "3") {
        Write-Host ""
		$ZscanDeleteRetVal = DeleteLocalUser $NewUser
		if ($ZscanDeleteRetVal -eq "true") {
			$RetVal = CreateNewLocalUser $NewUser $False
		}	
	} elseif ($NewUserPrompt -eq "4") {
		Write-Host " "
		break;
	} else {
        continue;
    }
  } 
  if ($RetVal -eq "true") {
	Write-Host "	Local user $($NewUser) was created successfully!" -fore green
	
	# Ensure user password never expires. 
	try 
	{
		Set-LocalUser -Name $NewUser -PasswordNeverExpires $true -ErrorAction Stop
		Write-Host "	--> Successfully set PasswordNeverExpires to true" -fore green
	}
	Catch
	{
		Write-Host "	Error: $($_.Exception.Message)" -fore red
	}
	# Ensure user cannot change password
	try
	{
		Set-LocalUser -Name $NewUser -UserMayChangePassword $false -ErrorAction Stop
		Write-Host "	--> Successfully set UserMayChangePassword to false" -fore green
	}
	Catch
	{
		Write-Host "	Error: $($_.Exception.Message)" -fore red
	}
	# Ensure account never expires
	try
	{
		Set-LocalUser -Name $NewUser -AccountNeverExpires -ErrorAction Stop
		Write-Host "	--> Successfully set AccountNeverExpires" -fore green
	}
	Catch
	{
		Write-Host "	Error: $($_.Exception.Message)" -fore red
	}
	
    Write-Host ""
    break
  }
}

Write-Host "        ############################ SCANS FOLDER ##############################" -fore DarkCyan
Write-Host " "

# CREATE THE SCANS FOLDER
$CreateNewFolderRetVal = CreateNewFolderInCDrive $FolderName

if ($CreateNewFolderRetVal -eq "true") {
    write-Host " " 
    $CreateNewFolderRetVal = ShareFolder $FolderName

    # If share folder success we can then set permissions
    if ($CreateNewFolderRetVal -eq "true") {
        $CreateNewFolderRetVal = AddPermissionToShareFolder $FolderName $NewUser
    } 
} 

while ($CreateNewFolderRetVal -eq "false") {
	Write-Host "	Would you like to create a new folder in <C:\> drive?"
	Write-Host "	==> Options:"
	Write-Host "		(1) - create new folder in <C:\>"
	Write-Host " 		(2) - move files to temp folder, recreate <$($FolderName)> folder in <C:\>, and restore"
	Write-Host "		(3) - move on to <$($FolderName)> folder permissions"		    
    $CreateCustomFolderResponse = Read-Host -Prompt "	"

	Write-Host " "		

	if ($CreateCustomFolderResponse -eq "1") {
        $OldFolderName = $FolderName

		$FolderName = Read-Host -Prompt "	Enter the folder name"

        Write-Host " "

		$CreateNewFolderRetVal = CreateNewFolderInCDrive $FolderName

		# Copy items from Scans folder to new folder?
		while ($true) {
			$CopyOverResponse = Read-Host -Prompt "	Copy items from <C:\$($OldFolderName)> to new scans location <C:\$($FolderName)>? (y/n)"
			Write-Host " "

			if ($CopyOverResponse -eq "y" -Or $CopyOverResponse -eq "Y") {
				$CopyOverRetVal = CopyOverItemsToNewFolder $OldFolderName $FolderName
					
				Write-Host " "
				break;
			}
			elseif ($CopyOverResponse -eq "n" -Or $CopyOverResponse -eq "N") {
				Write-Host " "
				break;
			}
		}
	    
        Write-Host "        ########################## FOLDER PERMISSIONS ##########################" -fore DarkCyan
        Write-Host ""
        
        # Share the folder
        $ShareFolderResponse = ShareFolder $FolderName

        # If share folder success we can then set permissions
        if ($ShareFolderResponse -eq "true") {
            $AddPermResponse = AddPermissionToShareFolder $FolderName $NewUser

            if ($AddPermResponse -eq "true") {
                break;
            } else {
                continue;
            }
        } else {
            Write-Host "        Attempting to re-apply the correct permission settings for the <$($FolderName)> folder..."
            Write-Host ""

            $AddPermResponse = AddPermissionToShareFolder $FolderName $NewUser
 
            if ($AddPermResponse -eq "true") {
                break;
            } else {
                continue;
            }
        }    
	} elseif ($CreateCustomFolderResponse -eq "2") {
		# Make a new folder call temp on c drive
		$TempFolderName = "temp1234"
		Write-Host "	Creating <temp1234> folder..."
		$CreateNewFolderRetVal = CreateNewFolderInCDrive $TempFolderName
			
		##Copy scans items to temp folder
        Write-Host "        Copying items from Scans to Temp1234 folder..."
		$CopyResponse = CopyOverItemsToNewFolder $FolderName $TempFolderName 
			
		if ($CopyResponse -eq "true") {
            Write-Host "        Deleting old Scans folder..."
			$DeleteFolderResponse = DeleteScansFolderInCDrive $FolderName
			if ($DeleteFolderResponse -eq "true") {
                Write-Host "        Creating new Scans folder..."
				$CreateNewFolderRetVal = CreateNewFolderInCDrive $FolderName
				if ($CreateNewFolderRetVal -eq "true") {
                    Write-Host "        Copying items from Temp1234 folder to new Scans folder..."
					$CopyResponse = CopyOverItemsToNewFolder $TempFolderName $FolderName
					if ($CopyResponse -eq "true") {
                        Write-Host "        Deleting Tem1234 folder..."
						$DeleteResponse = DeleteScansFolderInCDrive $TempFolderName
                        if ($DeleteResponse -eq "true") {
                            Write-Host ""
                            Write-Host "        Created new Scans folder and moved files from old Scans folder successfully!" -fore Green
                        }
					}
				}
			}
		} else {
            Write-Host "    Error: Could not copy over items from 'Scans' folder to the 'Temp1234' folder!"
        }
         
        Write " "
        Write-Host "        ########################## FOLDER PERMISSIONS ##########################" -fore DarkCyan
        Write-Host ""    
        
        # Share the folder
        $ShareFolderResponse = ShareFolder $FolderName

        # If share folder success we can then set permissions
        if ($ShareFolderResponse -eq "true") {
            $AddPermResponse = AddPermissionToShareFolder $FolderName $NewUser
            if ($AddPermResponse -eq "true") {
                break;
            } else {
                continue;
            }
        } else {
            Write-Host "        Attempting to re-apply the correct permission settings for the <$($FolderName)> folder..."
            Write-Host ""

            $AddPermResponse = AddPermissionToShareFolder $FolderName $NewUser
            if ($AddPermResponse -eq "true") {
                break;
            } else {
                continue;
            }
        }
	} elseif ($CreateCustomFolderResponse -eq "3") {
        Write-Host "        ########################## FOLDER PERMISSIONS ##########################" -fore DarkCyan
        Write-Host ""
        
        Write-Host "        Attempting to re-apply the correct permission settings for the <$($FolderName)> folder..."
        Write-Host ""

        $AddPermResponse = AddPermissionToShareFolder $FolderName $NewUser
        if ($AddPermResponse -eq "true") {
            break;
        } else {
            continue;
        }
	}
	Write-Host " "
}


Write-Host "        ########################### SCANS SHORTCUT #############################" -fore DarkCyan
Write-Host ""

# Create shortcut for scans folder
CreateScansShortCutOnDesktop $FolderName

# Pin to quick access toolbar
PinToQuickAccess $FolderName

Write-Host "        ########################## NETWORK SETTINGS ############################" -fore DarkCyan
Write-Host ""

# Grab the computer's ipv4 address
$ComputerIP = Test-Connection ::1 -Cou 1 | select -ExpandProperty IPV4Address

# Get the current profile connection that the printer is connected to
$CurrentNetProfile = GetNetworkConnectionProfile

# Switch network profile to private if on public
if ($CurrentNetProfile -eq "false") {
    $ErrorCounter = $ErrorCounter + 1
} elseif ($CurrentNetProfile -eq "DomainAuthenticated" -Or $CurrentNetProfile -eq "Private") {
    Write-Host "        Current network profile is: <$($CurrentNetProfile)>. No need to switch profile!" -fore Green
} elseif ($CurrentNetProfile -eq "Public") { 
    # if network profile is public we must switch it to private
    Write-Host "        Current network profile is: <$($CurrentNetProfile)>. Switching profile to Private..."
    $CurrentNetProfile = ChangeNetworkProfileFromPublicToPrivate $CurrentNetProfile

    if ($CurrentNetProfile -eq "Private") {
        Write-Host "        Successfully switched network profile from <Public> to <Private>!" -fore Green
    } else {
        $ErrorCounter = $ErrorCounter + 1
        Write-Host "        Error: Could not switched network profile to Private: $($CurrentNetProfile)" -fore Red
    }
}

Write-Host ""

$FileAndPrinterSharingStatus = ""

# Check file and printer sharing for all profiles in the firewall.

$IncludeDomainProfile = $false
$IncludePrivateProfile = $false

# Enable for private and domain profiles if not set. 
if ($CurrentNetProfile -eq "DomainAuthenticated") {
    $IncludeDomainProfile = $true
    $IncludePrivateProfile = $true
} elseif ($CurrentNetProfile -eq "Private") {
    $IncludePrivateProfile = $true
}

if ($IncludeDomainProfile -and $IncludePrivateProfile) {
    $FileAndPrinterSharingStatus = SetFireWallRulesForFileAndPrinterSharing "Domain, Private" $ErrorCounter        
} elseif ($IncludePrivateProfile) {
    $FileAndPrinterSharingStatus = SetFireWallRulesForFileAndPrinterSharing "Private" $ErrorCounter
}

# Enable network discovery

$EnableNetworkDiscoveryStatus = $false

$IncludeDomainProfile = $false
$IncludePrivateProfile = $false
$IncludePublicProfile = $false

if ($CurrentNetProfile -eq "DomainAuthenticated") {
    $IncludeDomainProfile = $true
    $IncludePrivateProfile = $true
} elseif ($CurrentNetProfile -eq "Private") {
    $IncludePrivateProfile = $true
}
    
if ($IncludeDomainProfile -and $IncludePrivateProfile) {
    $EnableNetworkDiscoveryStatus = TurnOnNetworkDiscovery "Domain, Private" $ErrorCounter
} elseif ($IncludePrivateProfile) {
    $EnableNetworkDiscoveryStatus = TurnOnNetworkDiscovery "Private" $ErrorCounter
}

# Add to counter if any status is false
if ($FileAndPrinterSharingStatus -ne "true" -Or $EnableNetworkDiscoveryStatus -ne "true") {
    $ErrorCounter = $ErrorCounter + 1
}

# Add to counter if any status is false
if ($FileAndPrinterSharingStatus -ne "true" -Or $EnableNetworkDiscoveryStatus -ne "true") {
    $ErrorCounter = $ErrorCounter + 1
}

Write-Host "        ########################################################################" -fore DarkCyan

Write-Host ""
Write-Host ""
# Attempted artwork to bring the user's eyes to the prize.......
Write-Host "        ========================================================================" -fore Red           
Write-Host "        ^_^_^_^_^_^_^_^_^_^_^_^_^_^ SCRIPT COMPLETED ^_^_^_^_^_^_^_^_^_^_^_^_^_^" -fore Yellow
Write-Host "        ========================================================================" -fore Red           
Write-Host ""
Write-Host "        Please use the following for the address book entry for this computer:" -fore DarkCyan
Write-Host ""
Write-Host "        SMB:" -fore DarkCyan
Write-Host "        ====> Host Name: " -NoNewLine -fore Green 
Write-Host "$($env:COMPUTERNAME)" -NoNewLine -fore Yellow
Write-Host " or " -NoNewLine -fore Green 
Write-Host "$($ComputerIP)" -fore Yellow
Write-Host "        ====> Port Number: " -NoNewLine -fore Green
Write-Host "445" -NoNewline -fore Yellow
Write-Host " or " -NoNewLine -for Green
Write-Host "139" -fore Yellow
Write-Host "        ====> Path: " -NoNewline -fore Green
Write-Host "$($FolderName)" -fore Yellow
Write-Host "        ====> Login User Name: " -NoNewLine -fore Green
Write-Host "$($NewUser)" -fore Yellow
Write-Host "        ====> Login Password: " -NoNewline -fore Green
Write-Host "(not display for security purpose)" -fore Yellow
Write-Host " "
Write-Host " "

####################### PUT ERRORS THAT REQUIRE MANUAL CHECKING HERE ##########################

if ($ErrorCounter > 0) {
    Write-Host "        ERRORS that need manual checking:" -fore Red
    # For network profile checking and switching.
    if (($CurrentNetProfile -ne "Private") -Or ($CurrentNetProfile -ne "DomainAuthenticated")) {
        Write-Host "        ====> Error: I was unable to help you switch the 'Network Profile' from 'Public' to 'Private'. " -fore Red
        Write-Host "                     You can change the profile to 'Private' by clicking on the Internet Icon near the clock. " -fore Red
        Write-Host "                     Then the network connection (SSID) where it says 'Connected' to change this." -fore Red
    }

    # For unable to enable file and printer sharing 
    if ($FileAndPrinterSharingStatus -eq "false") {
        Write-Host "        ====> Error: I had trouble enabling the 'File and Printer Sharing' allowance for this computer." -fore Red
        Write-Host "                     Please check the 'Advanced Sharing Settings' or 'Firewall' to allow for 'File and Printer Sharing'." -fore Red
    }

    # For unable to enable network discovery
    if ($EnableNetworkDiscoveryStatus -eq "false") {
        Write-Host "        ====> Error: I had trouble enabling the 'Turn on Network Discovery' allowance for this computer." -fore Red
        Write-Host "                     Please check the 'Advanced Sharing Settings" or "Firewall" to allow for "Turn on Network Discovery." -fore Red 
    }

    Write-Host ""
    Write-Host ""
}

# Another attempted artwork to keep the user's eyes on the prize,,,,,
Write-Host "        ========================================================================" -fore Red
Write-Host "        <><><><><><><><><><><><><><><><><><><><><><><><><><><><><><><><><><><><>" -fore Yellow
Write-Host "        ========================================================================" -fore Red          
Write-Host ""
Write-Host ""

Write-Host "        Current execution policy for this script: " -NoNewline

# Set-ExecutionPolicy Restricted

Write-Host "$(Get-ExecutionPolicy)." -fore Yellow
Write-Host "" 

# Make sure script doesn't auto close before user tells it to
$Quit = Read-Host -Prompt "        Press (q) to quit..."
Write-Host ""

while ($Quit -ne "q" -Or $Quit -ne "Q") {
   $Quit = Read-Host -Prompt "        Press (q) to quit..."
   Write-Host ""
}