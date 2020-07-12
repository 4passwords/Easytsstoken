# Easytsstoken an Thycotic Secret Server Get Token wrapper    

script features:
    
A friendly method to get an token from your Secret Server API.
Main method is Rest, the token retrieved can also be used on the Soap api.

When starting the script the only required argument is the secret server url, all other questions will be interactively asked. like a domain, userid and password.
You can skip the TOTP code by leaving it empty. If you do not wish to have the TOTP question at all then use the argument : -donotuseotp $true
The result will be a global variable $tsstokenlocal or $tsstokenremote (if you configure a second url with -urlremote

The script tests if the dns can be resolved, the url syntax is ok and the webserver returns a valid 200 code. 
it times the login when an OTP is supplied. on the whole of half minute. so account locks are prevented
the script aborts if it takes more then 30 seconds to enter the OTP codes
you can use the OTP values but also supply the OTP Secrets to Calculate the TOTP codes in realtime
the script always stores the passwords or totp keys in secure strings and or in a System.Management.Automation.PSCredential object. 
you can supply a secure string as password in an commadn argument and or the TOTP secrets as arguments to get the tokens automaticly in your session

It can fetch a local and a remote secret server session token in one go. for sync scripts  or cloud / on premise syncs
all options can be supplied as parametes to fully automate.

Command options:

-urllocal, supply a valid https url, http is prevented by the script as you post a password to an api! this first argument is required.

        -urllocal https://your.domain/secretserver
        
-urlremote, supply a standby or secondary secret server to fetch a token for

        -urlremote https://your.domain/secretserver

-donotuseotp, will not ask TOTP questions it assumes you do not have TOTP configured for you account. it will disable the timing mechanism to safeguard you for accountlocks if TOTP is required.

        -donotuseotp $false, $true or empty, it defaults to $false 
        
-useotpsecrets, if you want to supply your TOTP Secrets instead of the results, The script will then calculate the TOTP code for you based on the Secret instead of asking you for the results. use with care in how you specify the secret for the script. The related Secrets will then be asked interactive and or can be supplied with secure string object in the arguments PrimaryTSSUserSecureStringOTPSecret and or PrimaryTSSUserSecureStringOTPSecret.

        -useotpsecrets $false, $true or empty, it defaults to $false

-UseSameUseridandPasswordforStandbyTSS, if an urlremote is specified then script will ask you if you want to use the same domain, userid and password for the standby/second secret server

        -UseSameUseridandPasswordforStandbyTSS $true, $false, empty it defaults to $true

-PrimaryTSSDomain, supply the primary secretserver domain

        -PrimaryTSSDomain local, secretserver, empty, it defaults to secretserver

-PrimaryTSSUSer, supply the userid for the primary secretserver.

        -PrimaryTSSUSer USERID

 -PrimaryTSSUSerSecureStringPassword, if you need to interactively run this script with a password, supply a secure string to this script ([Security.SecureString]), it will reject a normal string. also be carefull when you store passwords in scripts, its better to use the SKD kit / client and or integrated windows authentication with a scehduled tasks or service for fully automation. This option together with the -useotpsecrets can fully automate a TOTP login with a stored userid and password. can be helpfull in development sessions to automate.

        -PrimaryTSSUSerSecureStringPassword $securestringobject

 -PrimaryTSSUserSecureStringOTPSecret, this is the TOTP secret to calculate the TOTP code for you while the script is running. supply a secure string to this script ([Security.SecureString]), it will reject a normal string. 
 
        -PrimaryTSSUserSecureStringOTPSecret $securestringobject
 
 -StandbyTSSDomain, supply the standby, secondary secretserver domain, if will not be asked if -UseSameUseridandPasswordforStandbyTSS is set to $true
 
        -StandbyTSSDomain local, secretserver, empty, it defaults to secretserver

-StandbyTSSUSer, supply the standby, secondary secretserver user , if will not be asked if -UseSameUseridandPasswordforStandbyTSS is set to $true

        -StandbyTSSUSer USERID

-StandbyTSSUSerSecureStringPassword, supply a secure string to this script ([Security.SecureString]), it will reject a normal string, further the same applies  as for the PrimaryTSSUSerSecureStringPassword.

        -StandbyTSSUSerSecureStringPassword $securestringobject

-StandbyTSSUserSecureStringOTPSecret, this is the TOTP secret to calculate the TOTP code for you while the script is running. supply a secure string to this script ([Security.SecureString]), it will reject a normal string. 

        -StandbyTSSUserSecureStringOTPSecret $securestringobject

--

example syntax:

    easytsstoken.ps1 -urllocal https://url -useotpsecrets $false -PrimaryTSSDomain local -PrimaryTSSUSer USERID -PrimaryTSSUSerSecureStringPassword $thisneedstobeasecurestring

fully automated syntax:

    easytsstoken.ps1 -urllocal https://url -useotpsecrets $true -PrimaryTSSDomain local -PrimaryTSSUSer USERID -PrimaryTSSUSerSecureStringPassword $thisneedstobeasecurestring -PrimaryTSSUserSecureStringOTPSecret $testotplocalsecure

fully automated with an standby secret server syntax: ( even if accounts are the same on both secret servers with AD logins, you will have two different OTP's if using google authenticators

    easytsstoken.ps1 -urllocal https://url -urlremote https://url -UseSameUseridandPasswordforStandbyTSS $true -useotpsecrets $true -PrimaryTSSDomain local -PrimaryTSSUSer USERID -PrimaryTSSUSerSecureStringPassword $thisneedstobeasecurestring -PrimaryTSSUserSecureStringOTPSecret $testotplocalsecure -StandbyTSSUserSecureStringOTPSecret $testotpremotesecure

fully automated with an standby secret server and have seperated useraccounts and otp's on both secret servers

    easytsstoken.ps1 -urllocal https://url -urlremote https://url -UseSameUseridandPasswordforStandbyTSS $false -useotpsecrets $true -PrimaryTSSDomain local -PrimaryTSSUSer USERID -PrimaryTSSUSerSecureStringPassword $thisneedstobeasecurestring -PrimaryTSSUserSecureStringOTPSecret $testotplocalsecure -StandbyTSSDomain DOMAINREMOTE -StandbyTSSUser USERIDREMOTE -StandbyTSSUSerSecureStringPassword $test1secure -StandbyTSSUserSecureStringOTPSecret $testotpremotesecure

to supply secure strings for the script or command arguments : 

    $test1secure = Read-Host -AsSecureString ; $testotplocalsecure  = Read-Host -AsSecureString ; $testotpremotesecure  = Read-Host -AsSecureString

