# Easytsstoken
# Easytsstoken an Thycotic Secret Server Get Token wrapper    

script features:
    
     A friendly method to get an token from your Secret Server API.
     Main method is Rest, the token retrieved can also be used on the Soap api.
     
     the script tests if the dns can be resolved, the url syntax is ok and the webserver returns a valid 200 code. 
     it times the login when an OTP is supplied. on the whole of half minute. so account locks are prevented
     the script aborts if it takes more then 30 seconds to enter the OTP codes
     you can use the OTP values but also supply the OTP Secrets to Calculate the TOTP codes in realtime
     the script always stores the passwords or totp keys in secure strings and or in a System.Management.Automation.PSCredential object. 
     you can supply a secure string as password in an commadn argument and or the TOTP secrets as arguments to get the tokens automaticly in your session
     
     It can fetch a local and a remote secret server session token in one go. for sync scripts  or cloud / on premise syncs
     all options can be supplied as parametes to fully automate.
     
     example syntax:

     easytsstoken.ps1 -urllocal https://url -useotpsecrets $false -PrimaryTSSDomain local -PrimaryTSSUSer USERID -PrimaryTSSUSerSecureStringPassword $thisneedstobeasecurestring

     fully automated syntax:
     easytsstoken.ps1 -urllocal https://url -useotpsecrets $true -PrimaryTSSDomain local -PrimaryTSSUSer USERID -PrimaryTSSUSerSecureStringPassword $thisneedstobeasecurestring -PrimaryTSSUserSecureStringOTPSecret $testotplocalsecure

     fully automated with an standby secret server syntax: ( even if accounts are the same on both secret servers with AD logins, you will have two different OTP's if using google authenticators
     easytsstoken.ps1 -urllocal https://url -urlremote https://url -UseSameUseridandPasswordforStandbyTSS $true -useotpsecrets $true -PrimaryTSSDomain local -PrimaryTSSUSer USERID -PrimaryTSSUSerSecureStringPassword $thisneedstobeasecurestring -PrimaryTSSUserSecureStringOTPSecret $testotplocalsecure -StandbyTSSUserSecureStringOTPSecret $testotpremotesecure

     fully automated with an standby secret server and have seperated useraccounts and otp's on both secret servers
     easytsstoken.ps1 -urllocal https://url -urlremote https://url -UseSameUseridandPasswordforStandbyTSS $false -useotpsecrets $true -PrimaryTSSDomain local -PrimaryTSSUSer USERID -PrimaryTSSUSerSecureStringPassword $thisneedstobeasecurestring -PrimaryTSSUserSecureStringOTPSecret $testotplocalsecure -StandbyTSSDomain DOMAINREMOTE -StandbyTSSUser USERIDREMOTE -StandbyTSSUSerSecureStringPassword $test1secure -StandbyTSSUserSecureStringOTPSecret $testotpremotesecure

     to supply secure strings for the script or command arguments : $test1secure = Read-Host -AsSecureString ; $testotplocalsecure  = Read-Host -AsSecureString ; $testotpremotesecure  = Read-Host -AsSecureString
    
