    # Easytsstoken an Thycotic Secret Server Get Token wrapper 
    # By jan.dijk@mccs.nl / 4passwords.com
    #
    # script features:
    #
    # A friendly method to get an token from your Secret Server API.
    # Main method is Rest, the token retrieved can also be used on the Soap api.
    # 
    # the script tests if the dns can be resolved, the url syntax is ok and the webserver returns a valid 200 code. 
    # it times the login when an OTP is supplied. on the whole of half minute. so account locks are prevented
    # the script aborts if it takes more then 30 seconds to enter the OTP codes
    # you can use the OTP values but also supply the OTP Secrets to Calculate the TOTP codes in realtime
    # the script always stores the passwords or totp keys in secure strings and or in a System.Management.Automation.PSCredential object. 
    # you can supply a secure string as password in an commadn argument and or the TOTP secrets as arguments to get the tokens automaticly in your session
    # 
    # It can fetch a local and a remote secret server session token in one go. for sync scripts  or cloud / on premise syncs
    # all options can be supplied as parametes to fully automate.
    # 
    # example syntax:
    # easytsstoken.ps1 -urllocal https://url -useotpsecrets $false -PrimaryTSSDomain local -PrimaryTSSUSer USERID -PrimaryTSSUSerSecureStringPassword $thisneedstobeasecurestring
    # fully automated syntax:
    # easytsstoken.ps1 -urllocal https://url -useotpsecrets $true -PrimaryTSSDomain local -PrimaryTSSUSer USERID -PrimaryTSSUSerSecureStringPassword $thisneedstobeasecurestring -PrimaryTSSUserSecureStringOTPSecret $testotplocalsecure
    # fully automated with an standby secret server syntax: ( even if accounts are the same on both secret servers with AD logins, you will have two different OTP's if using google authenticators
    # easytsstoken.ps1 -urllocal https://url -urlremote https://url -UseSameUseridandPasswordforStandbyTSS $true -useotpsecrets $true -PrimaryTSSDomain local -PrimaryTSSUSer USERID -PrimaryTSSUSerSecureStringPassword $thisneedstobeasecurestring -PrimaryTSSUserSecureStringOTPSecret $testotplocalsecure -StandbyTSSUserSecureStringOTPSecret $testotpremotesecure
    # fully automated with an standby secret server and have seperated useraccounts and otp's on both secret servers
    # easytsstoken.ps1 -urllocal https://url -urlremote https://url -UseSameUseridandPasswordforStandbyTSS $false -useotpsecrets $true -PrimaryTSSDomain local -PrimaryTSSUSer USERID -PrimaryTSSUSerSecureStringPassword $thisneedstobeasecurestring -PrimaryTSSUserSecureStringOTPSecret $testotplocalsecure -StandbyTSSDomain DOMAINREMOTE -StandbyTSSUser USERIDREMOTE -StandbyTSSUSerSecureStringPassword $test1secure -StandbyTSSUserSecureStringOTPSecret $testotpremotesecure
    # to supply secure strings for the script or command arguments : $test1secure = Read-Host -AsSecureString ; $testotplocalsecure  = Read-Host -AsSecureString ; $testotpremotesecure  = Read-Host -AsSecureString
    #
    # changelog: 10-07-2020: fixed skipping the otp option 


    param (
        [Parameter(Mandatory=$true, ValueFromPipeline=$false, Position=0)]
        [String[]]$urllocal,
        [Parameter(Mandatory=$false,ValueFromPipeline=$false)]
        [String[]]$urlremote,
        [Parameter(Mandatory=$false,ValueFromPipeline=$false)]
        [bool[]]$useotpsecrets,
        [Parameter(Mandatory=$false,ValueFromPipeline=$false)]
        [bool[]]$donotuseotp,
        [Parameter(Mandatory=$false,ValueFromPipeline=$false)]
        [bool[]]$UseSameUseridandPasswordforStandbyTSS,
        [Parameter(Mandatory=$false,ValueFromPipeline=$false)]
        [String[]]$PrimaryTSSDomain,
        [Parameter(Mandatory=$false,ValueFromPipeline=$false)]
        [String[]]$PrimaryTSSUSer,
        [Parameter(Mandatory=$false,ValueFromPipeline=$false)]
        [Security.SecureString]$PrimaryTSSUSerSecureStringPassword,
        [Parameter(Mandatory=$false,ValueFromPipeline=$false)]
        [Security.SecureString]$PrimaryTSSUserSecureStringOTPSecret,
        [String[]]$StandbyTSSDomain,
        [Parameter(Mandatory=$false,ValueFromPipeline=$false)]
        [String[]]$StandbyTSSUSer,
        [Parameter(Mandatory=$false,ValueFromPipeline=$false)]
        [Security.SecureString]$StandbyTSSUSerSecureStringPassword,
        [Parameter(Mandatory=$false,ValueFromPipeline=$false)]
        [Security.SecureString]$StandbyTSSUserSecureStringOTPSecret
    )

    $tssscriptversion = "1.2.3.1" 

    # show debug messages
    #$DebugPreference = 'Continue'
    # hide debug messages
    $DebugPreference = 'SilentlyContinue'

    # make sure we talk tls12 from powershell to the webservers
    [System.Net.ServicePointManager]::SecurityProtocol = [System.Net.SecurityProtocolType]::Tls12;

    # validate optional parameters in the debug
    write-debug "donotuseotp:$donotuseotp"  
    write-debug "useotpsecrets instead of the otp values:$useotpsecrets"
    write-debug "UseSameUseridandPasswordforStandbyTSS:$UseSameUseridandPasswordforStandbyTSS"
    write-debug "PrimaryTSSDomain:$PrimaryTSSDomain"
    write-debug "PrimaryTSSUSer:$PrimaryTSSUSer"
    write-debug "StandbyTSSDomain:$StandbyTSSDomain"
    write-debug "StandbyTSSUSer:$StandbyTSSUSer"

    if ( $($UseSameUseridandPasswordforStandbyTSS) -eq $false ) {
     if ( $($StandbyTSSDomain) -eq $null ) { write-error "need to specify StandbyTSSDomain if UseSameUseridandPasswordforStandbyTSS is False" ; cleanupvars; exit 1 }
     if ( $($StandbyTSSUSer) -eq $null ) { write-error "need to specify StandbyTSSUSer if UseSameUseridandPasswordforStandbyTSS is False" ; cleanupvars; exit 1 }
    }

    if ( $($useotpsecrets) -as [bool] -eq $true ) {
     if ( $($PrimaryTSSUserSecureStringOTPSecret) -eq $null ) { write-error "need to specify PrimaryTSSUserSecureStringOTPSecret if useotpsecrets is set" ; cleanupvars; exit 1 }
        if ($($urlremote) -eq '') {
            if ( $($StandbyTSSUserSecureStringOTPSecret) -eq $null ) { write-error "need to specify StandbyTSSUserSecureStringOTPSecret if useotpsecrets is set" ; cleanupvars; exit 1 }
        }
     
    }
   

    if ( $PrimaryTSSUSerSecureStringPassword -ne $null ) {
        if ( (($PrimaryTSSUSerSecureStringPassword.GetType()).name) -ne "SecureString" ) { write-error "please give as argument a secure string type for: PrimaryTSSUSerSecureStringPassword"; cleanupvars; exit 1 } else { write-debug "PrimaryTSSUSerSecureStringPassword is set with a secure string" }
    }

    if ( $PrimaryTSSUserSecureStringOTPSecret -ne $null ) {
        if ( (($PrimaryTSSUserSecureStringOTPSecret.GetType()).name) -ne "SecureString" ) { write-error "please give as argument a secure string type for: PrimaryTSSUserSecureStringOTPSecret"; cleanupvars; exit 1 } else { write-debug "PrimaryTSSUserSecureStringOTPSecret is set with a secure string" }
    }

    if ( $StandbyTSSUSerSecureStringPassword -ne $null ) {
        if ( (($StandbyTSSUSerSecureStringPassword.GetType()).name) -ne "SecureString" ) { write-error "please give as argument a secure string type for: StandbyTSSUSerSecureStringPassword"; cleanupvars; exit 1 } else { write-debug "StandbyTSSUSerSecureStringPassword is set with a secure string" }
    }

    if ( $StandbyTSSUserSecureStringOTPSecret -ne $null ) {
        if ( (($StandbyTSSUserSecureStringOTPSecret.GetType()).name) -ne "SecureString" ) { write-error "please give as argument a secure string type for: StandbyTSSUserSecureStringOTPSecret"; cleanupvars; exit 1 } else { write-debug "StandbyTSSUserSecureStringOTPSecret is set with a secure string" }
    }

    ###

    # make sure we have two global variables as endresult in this we will store the tokens.
    Set-Variable -Scope global -Name tssurllocal -value $urllocal
    if ($urlremote -eq '') { $urlremote=$false }
    if ($urlremote -eq $null) { $urlremote=$false }
    Set-Variable -Scope global -Name tssurlremote -value $urlremote
 
    # output the parameter url values.
    write-debug "tssurllocal:$urllocal"
    write-debug "tssurlremote:$urlremote"


#OTP function code by  https://gist.github.com/jonfriesen/234c7471c3e3199f97d5 (jonfriesen & ecspresso )
function Get-Otp(){
    param(
        [Parameter(Mandatory=$true)]$SECRET,
        $LENGTH = 6,
        $WINDOW = 30
    )
    $enc = [System.Text.Encoding]::UTF8
    $hmac = New-Object -TypeName System.Security.Cryptography.HMACSHA1
    $hmac.key = Convert-HexToByteArray(Convert-Base32ToHex(($SECRET.ToUpper())))
    $timeBytes = Get-TimeByteArray $WINDOW
    $randHash = $hmac.ComputeHash($timeBytes)

    $offset = $randhash[($randHash.Length-1)] -band 0xf
    $fullOTP = ($randhash[$offset] -band 0x7f) * [math]::pow(2, 24)
    $fullOTP += ($randHash[$offset + 1] -band 0xff) * [math]::pow(2, 16)
    $fullOTP += ($randHash[$offset + 2] -band 0xff) * [math]::pow(2, 8)
    $fullOTP += ($randHash[$offset + 3] -band 0xff)

    $modNumber = [math]::pow(10, $LENGTH)
    $otp = $fullOTP % $modNumber
    $otp = $otp.ToString("0" * $LENGTH)
    return $otp
}

function Get-TimeByteArray($WINDOW) {
    $span = (New-TimeSpan -Start (Get-Date -Year 1970 -Month 1 -Day 1 -Hour 0 -Minute 0 -Second 0) -End (Get-Date).ToUniversalTime()).TotalSeconds
    $unixTime = [Convert]::ToInt64([Math]::Floor($span/$WINDOW))
    $byteArray = [BitConverter]::GetBytes($unixTime)
    [array]::Reverse($byteArray)
    return $byteArray
}

function Convert-HexToByteArray($hexString) {
    $byteArray = $hexString -replace '^0x', '' -split "(?<=\G\w{2})(?=\w{2})" | %{ [Convert]::ToByte( $_, 16 ) }
    return $byteArray
}

function Convert-Base32ToHex($base32) {
    $base32chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
    $bits = "";
    $hex = "";

    for ($i = 0; $i -lt $base32.Length; $i++) {
        $val = $base32chars.IndexOf($base32.Chars($i));
        $binary = [Convert]::ToString($val, 2)
        $staticLen = 5
        $padder = '0'
            # Write-Host $binary
        $bits += Add-LeftPad $binary.ToString()  $staticLen  $padder
    }


    for ($i = 0; $i+4 -le $bits.Length; $i+=4) {
        $chunk = $bits.Substring($i, 4)
        # Write-Host $chunk
        $intChunk = [Convert]::ToInt32($chunk, 2)
        $hexChunk = Convert-IntToHex($intChunk)
        # Write-Host $hexChunk
        $hex = $hex + $hexChunk
    }
    return $hex;

}

function Convert-IntToHex([int]$num) {
    return ('{0:x}' -f $num)
}

function Add-LeftPad($str, $len, $pad) {
    if(($len + 1) -ge $str.Length) {
        while (($len - 1) -ge $str.Length) {
            $str = ($pad + $str)
        }
    }
    return $str;
}
#OTP function code end


Function Get-TSSToken {

Param
    (
         [Parameter(Mandatory=$true, Position=0)]
         [string] $tssapimethod,
         [Parameter(Mandatory=$true, Position=1)]
         [string] $tssapiurl, 
         [Parameter(Mandatory=$true, Position=2)]
         [string] $tssapidomain, 
         [Parameter(Mandatory=$true, Position=3)]
         [string] $tssapiuserid,
         [Parameter(Mandatory=$true, Position=4)]
         [string] $tssapipassword, 
         [Parameter(Mandatory=$false, Position=5)]
         [string] $tssotp 
    )
 
write-debug "strtssremote:$tssapiurl"
write-debug "strtssdomain:$tssapidomain"
write-debug "strtssuserid:$tssapiuserid"
write-debug "strtsspassword:************"
write-debug "tssotp:$tssotp"


    switch -Exact (($tssapimethod).ToLower())
        {
        'soap' { write-debug "fetching soap token"

                write-error "not implemented yet, use the rest api to get a valid token, this can be used for soap and rest api calls at the same time." 
                cleanupvars
                exit

                }

        'rest' { write-debug "fetching rest token"


                $application = $tssapiurl
                $apidstusername = $tssapiuserid
                $apidstdomain = $tssapidomain
                $apidstpassword = ConvertTo-SecureString $tssapipassword -AsPlainText -force; 
                $headers = $null

                $Credentials = New-Object System.Management.Automation.PSCredential -ArgumentList $apidstusername, $apidstpassword
                if ($apidstpassword -ne $null) { Remove-Variable apidstpassword} 
                [System.GC]::Collect()

                      $creds = @{
                        username = $apidstusername
                        domain = $apidstdomain
                        password = $Credentials.GetNetworkCredential().Password
                        grant_type = "password"
                    };

                    if ($Credentials -ne $null) { 
                            $Credentials.Password.Dispose()
                            Remove-Variable Credentials
                    } 
                [System.GC]::Collect()


                #set otp headers if applicable
          
                If ($tssotp -ne $null) {
                        $headers = @{
                        "OTP" = $tssotp
                    }
                }
    
                    try
                    {
                        write-debug "$application/oauth2/token"
                        $response = Invoke-RestMethod "$application/oauth2/token" -Method Post -Body $creds -Headers $headers;
                        $token = $response.access_token;
                        if ($creds -ne $null) { Remove-Variable creds} 
                        if ($response -ne $null) { Remove-Variable response} 
                        [System.GC]::Collect()
                    }
                    catch
                    {
                        if ( $result -eq $null ) {
                        throw "could not login to remote secret server : $application"
                        }

                        $result = $_.Exception.Response.GetResponseStream();
                        $reader = New-Object System.IO.StreamReader($result);
                        $reader.BaseStream.Position = 0;
                        $reader.DiscardBufferedData();
                        $responseBody = $reader.ReadToEnd() | ConvertFrom-Json
                        Write-Host "ERROR: $($responseBody.error)"
                        if ($creds -ne $null) { Remove-Variable creds} 
                        if ($response -ne $null) { Remove-Variable response} 
                        [System.GC]::Collect()
                        throw "could not login to remote secret server : ERROR: $($responseBody.error)"
                    }

                            #--
                            write-debug "tsstoken:$token"
                            return $token
                        } #end rest

             } # switch

}

function Get-TimeStamp {
   
    return "[{0:MM/dd/yy} {0:HH:mm:ss}]" -f (Get-Date)
   
}

function msglog {

    Param(
        [parameter(position=0)]
        $msg
        )

$tmpdateline=(Get-TimeStamp)
write-host $tmpdateline $msg
}

function cleanupvars {
#cleanup secure objects
if ($localCredentials -ne $null) { Remove-Variable localCredentials }
if ($remoteCredentials -ne $null) { Remove-Variable remoteCredentials }
#if ($PrimaryTSSUserSecureStringOTPSecret -ne $null) { Remove-Variable PrimaryTSSUserSecureStringOTPSecret }
#if ($StandbyTSSUserSecureStringOTPSecret -ne $null) { Remove-Variable StandbyTSSUserSecureStringOTPSecret }

}

function gethalveminutepercent {
 if ($($(date).Second) -gt 00 -and $($(date).Second) -le 29)
  {
 $percent=[math]::Round((($($(date).Second))/30*100))
 }

  if ($($(date).Second) -gt 30 -and $($(date).Second) -le 59)
  {
 $percent=[math]::Round((($($(date).Second))/30*100)-100)
 }
 return $percent
}

function Get-UrlStatusCode([string] $testurl) {

 try
    {
        (Invoke-WebRequest -Uri $testurl -UseBasicParsing -DisableKeepAlive).StatusCode
    }
    catch [Net.WebException]
    {
        [int]$_.Exception.Response.StatusCode
    }

}

function test-dnsname([string] $testdns) {

    try {
    (Resolve-DnsName $testdns -ErrorAction Stop -QuickTimeout).count
    }
    catch {
    return “0”
    }

}

function test-urlsyntax([string] $testurl) {



        $testurlsyntaxresults=([System.Uri]"$testurl")

        #$testurlsyntaxresults
        $tmpdateline=Get-TimeStamp
        if ( ($testurlsyntaxresults.AbsoluteUri).count -eq 0 ) {
        write-host "$tmpdateline urlcheck: Supplied value is not an url : $testurl" -ForegroundColor red
        Return "1"
        } else {
        write-host "$tmpdateline urlcheck: URL syntax ok : $testurl" -ForegroundColor gray
        }

        $tmpdateline=Get-TimeStamp
        if ( (test-dnsname($testurlsyntaxresults.Authority)) -eq 0 ) {
        write-host "$tmpdateline dnscheck: FAILED: DNS resolution failed for " + $testurlsyntaxresults.Authority -ForegroundColor red
        Return "1"
        } else {
        write-host "$tmpdateline dnscheck: PASSED: DNS resolution OK for " + $testurlsyntaxresults.Authority -ForegroundColor gray
        }

        $tmpdateline=Get-TimeStamp
        if ( ($testurlsyntaxresults.Scheme) -ne 'https' ) {
        write-host "$tmpdateline httpscheck: FAILED: url does not use HTTPS" -ForegroundColor red
        Return "1"
        } else {
        write-host "$tmpdateline httpscheck: PASSED" -ForegroundColor gray
        }

        $tmpdateline=Get-TimeStamp
        $checkifonlineresults=(Get-UrlStatusCode($testurl))

        if ($checkifonlineresults -ne '200' ) {
        write-host "$tmpdateline checkifonline: FAILED: the webserver did not returen statuscode 200, but " + $checkifonlineresults -ForegroundColor gray -BackgroundColor red
        Return "1"
        } else {
        write-host "$tmpdateline checkifonline: PASSED" -ForegroundColor gray
        }

}


########################### Main

$tmpdateline=Get-TimeStamp
write-host "$tmpdateline TSS Easy Get Token wrapper v$tssscriptversion by Jan Dijk / 4Passwords.com" -ForegroundColor black -BackgroundColor white

## checks

    if (test-urlsyntax($urllocal) -eq 1 ){
    cleanupvars
    exit 1
    }
     if ( $urlremote -ne $false ) {

        if (test-urlsyntax($urlremote) -eq 1 ){
        cleanupvars
        exit 1
        }

     }

####
#write-debug "useotpsecrets:$useotpsecrets" 

if ( $donotuseotp -as [bool] -ne $true ) {  
    if ( ($useotpsecrets) -eq $null ) { 
    $inputuseotpsecrets = Read-Host "$(Get-TimeStamp) Would you like to use OTP Secrets instead of the OTP values? `n$(Get-TimeStamp) With OTP Secrets we will calculate the OTP values for you, this will grant you more time when filling in the login form.`n$(Get-TimeStamp) Otherwise you will need to enter the OTP results in the login process within 30 seconds from when the first OTP challenge is requested"
    if ($($inputuseotpsecrets) -eq '') { 
        $useotpsecrets = $false 
        } else {
            if ($($inputuseotpsecrets).ToLower() -eq 'y') { $useotpsecrets = $true } else { $useotpsecrets = $true}
        }
        }
    write-warning "make sure your local time and the TSS servers time are in sync, otherwise the OTP results could be off and the login could fail because of it"
    if ($($useotpsecrets) -eq $true) {
    write-warning "$(Get-TimeStamp): Using OTP secrets instead of results, we will calculate the results based on the given OTP secret."
    }
}

if ( $urlremote -ne $false ) {
        
        if ( ($UseSameUseridandPasswordforStandbyTSS) -eq $null ) {  

                $inputseperatestandbyuseridpasswordconfirmation = Read-Host "$(Get-TimeStamp) Use the same credentials for the standby secret server (default=y)?"
                if ( $inputseperatestandbyuseridpasswordconfirmation -eq "" ) { $UseSameUseridandPasswordforStandbyTSS = $true }

                }
        }


$executescript = 0
# get login data

if ( $PrimaryTSSDomain -eq $null ) {
$localdomain = Read-Host -Prompt "$(Get-TimeStamp) Enter your primary TSS domain (local,secretserver etc, default=secretserver)";
	if ( $localdomain -eq "" ) { $localdomain = "SecretServer" }
} else {
$localdomain = $($PrimaryTSSDomain)
}
write-debug "localdomain:$localdomain"

        if ( $PrimaryTSSUSer -eq $null ) { 
        $localusername = Read-Host -Prompt "$(Get-TimeStamp) Enter your primary TSS userid";
        } else {
        $localusername = $($PrimaryTSSUSer)
        }
        write-debug "localusername:$localusername"

        if ( $PrimaryTSSUSerSecureStringPassword -eq $null ) { 
        $localpassword = Read-Host -Prompt "$(Get-TimeStamp) Enter your primary TSS password" -AsSecureString;
        } else {

        write-debug "PrimaryTSSUSerSecureStringPassword:$PrimaryTSSUSerSecureStringPassword"
        $localpassword = $PrimaryTSSUSerSecureStringPassword 
        write-debug "localpassword:$localpassword"
        }


        if ( $urlremote -ne $false ) {
                if ($($UseSameUseridandPasswordforStandbyTSS) -ne $true) {
                    if ( $StandbyTSSDomain -eq $null ) {
                        $remotedomain = Read-Host -Prompt "$(Get-TimeStamp) Enter your standby TSS domain (local,secretserver etc, default=secretserver)";
                        } else {
                        $remotedomain = $($StandbyTSSDomain)
                        }
    	                if ( $remotedomain -eq "" ) { $remotedomain = "SecretServer" }
                        write-debug "remotedomain:$remotedomain"
                        
                        if ( $StandbyTSSUSer -eq $null ) { 
                            $remoteusername = Read-Host -Prompt "$(Get-TimeStamp) Enter your standby TSS userid";
                            } else {
                            $remoteusername = $($StandbyTSSUSer)
                            }
                        if ( $StandbyTSSUSerSecureStringPassword -eq $null ) { 
                            $remotepassword = Read-Host -Prompt "$(Get-TimeStamp) Enter your standby TSS password" -AsSecureString;
                            } else {
                            $remotepassword = $StandbyTSSUSerSecureStringPassword
                           }
                }
        }

write-debug "useotpsecrets:$useotpsecrets" 

if ( $donotuseotp -as [bool] -ne $true ) {

                    if ($($useotpsecrets) -ne $true) {

                    write-debug "useotpsecrets:ok" 

                            do {
                             #write-host "$(Get-TimeStamp) waiting to the seconds to hit 00 or 30, to minimize the login error, you need to complete the form within 30 seconds"
 
                              sleep 1


                            $percent=$(gethalveminutepercent)


                             Write-Progress -Activity "$(Get-TimeStamp) Timing the login on the 00 and 30th second mark to avoid OTP expiration issues. The login form should be completed within 30 seconds, it will be aborted to prevent account locks. Be ready to enter your OTP results, if login errors persist make sure your time is in sync with the server" -PercentComplete $percent

 
                              if ( $($(date).Second) -eq 00 )  {
                               $executescript = 1
                               Write-Progress -Activity "$(Get-TimeStamp) completed." -Completed -PercentComplete 100
                              }

                              if ( $($(date).Second) -eq 30 )  {
                               $executescript = 1
                               Write-Progress -Activity "$(Get-TimeStamp) completed." -Completed -PercentComplete 100
                              }


                             } while ( $executescript -eq 0 )
                    }

                    # get the time to calculate to safely login
                    $fetchtime1=$(date)

        
                        if ($($useotpsecrets) -eq $true) {

                        if ($($PrimaryTSSUserSecureStringOTPSecret) -eq $null ) { 
                                $localotpsecret = Read-Host -Prompt "$(Get-TimeStamp) Enter your primary TSS OTP secret" -AsSecureString;
                                    if ( $localotpsecret -eq '') { 
                                        Write-Error "the otp secret cannot be empty, tryagain"
                                        cleanupvars
                                        exit 1
                                        }
                                } else {
                                $localotpsecret = $PrimaryTSSUserSecureStringOTPSecret
                                }
    
                        } else {
	                        $localotp = Read-Host -Prompt "$(Get-TimeStamp) Enter your primary TSS OTP for 2FA (displayed in your 2FA app) leave empty to skip" -AsSecureString;
                        }

                        if ( $urlremote -ne $false ) {

                                    if ($($UseSameUseridandPasswordforStandbyTSS) -eq $true) {
	                                    $remotedomain = $localdomain
	                                    $remoteusername = $localusername
	                                    $remotepassword = $localpassword

                                       }
  
                                    if ($($useotpsecrets) -eq $true) {
                                     write-debug "StandbyTSSUserSecureStringOTPSecret:$StandbyTSSUserSecureStringOTPSecret"
                                            if ( $StandbyTSSUserSecureStringOTPSecret -eq $null ) {
                                                $remoteotpsecret = Read-Host -Prompt "$(Get-TimeStamp) Enter your standby TSS OTP secret" -AsSecureString;
                                                if ( $remoteotpsecret -eq '') { 
                                                    Write-Error "the otp secret cannot be empty, tryagain"
                                                    cleanupvars
                                                    exit 1
                                                    }
                                                } else {
                                                $remoteotpsecret = $StandbyTSSUserSecureStringOTPSecret
                                                }
                            
                                        } else {
	                                    $remoteotp = Read-Host -Prompt "$(Get-TimeStamp) Enter your standby TSS OTP for 2FA (displayed in your 2FA app) leave empty to skip" -AsSecureString;
                                        }
                                }
} # end use otp

 if ($($useotpsecrets) -eq $true) {


 # make sure we have enough time to generate and submite
 
    
    $percent=$(gethalveminutepercent)
    
    if ( $percent -ge 93 ) {
    write-debug "$(Get-TimeStamp) percent of timeout: $percent, there were $([math]::Round(30-(30/100*$percent))) seconds left"
    write-debug "lets wait until the next time window"
    do {
    sleep 1
    $percent=$(gethalveminutepercent)
        $percent=$(gethalveminutepercent)


         Write-Progress -Activity "$(Get-TimeStamp) Timing the login on the 00 and 30 second mark to avoid OTP expiration issues. please wait" -PercentComplete $percent
    } until ( $percent -ge 0 -and $percent -le 90)

    }


 $objsecretlocalOTP = New-Object System.Management.Automation.PSCredential -ArgumentList $localusername, $localotpsecret
 if ( $urlremote -ne $false ) { $objsecretremoteOTP = New-Object System.Management.Automation.PSCredential -ArgumentList $remoteusername, $remoteotpsecret }
 if ($localotpsecret -ne $null) { Remove-Variable localotpsecret} 
 if ( $urlremote -ne $false ) { if ($remoteotpsecret -ne $null) { Remove-Variable remoteotpsecret} }
 [System.GC]::Collect()

 $localotptmp=Get-Otp($($objsecretlocalOTP.GetNetworkCredential().Password))
 if ( $urlremote -ne $false ) { $remoteotptmp=Get-Otp($($objsecretremoteOTP.GetNetworkCredential().Password)) }
 $localotp = ConvertTo-SecureString $localotptmp -AsPlainText -Force
 if ( $urlremote -ne $false ) { $remoteotp = ConvertTo-SecureString $remoteotptmp -AsPlainText -Force }
 write-debug "Generating OTP for local account: $localotptmp"
 write-debug "Generating OTP for remote account: $remoteotptmp"
 }

# check if vars are empty
if ( $localusername -eq '') { write-error "please supply a value for the requested fields"; cleanupvars ; exit 1 }
if ( $localpassword -eq '' ) { write-error "please supply a value for the requested fields"; cleanupvars ; exit 1  }
if ( $urlremote -ne $false ) {
    if ( $remoteusername -eq '' ) { write-error "please supply a value for the requested fields"; cleanupvars ; exit 1  }
    if ( $remotepassword -eq '' ) { write-error "please supply a value for the requested fields"; cleanupvars ; exit 1  }
}
$objlocalCredentials = New-Object System.Management.Automation.PSCredential -ArgumentList $localusername, $localpassword

if ( $donotuseotp -as [bool] -ne $true ) {
    $objlocalOTP = New-Object System.Management.Automation.PSCredential -ArgumentList $localusername, $localotp
}

if ( $urlremote -ne $false ) {
    $objremoteCredentials = New-Object System.Management.Automation.PSCredential -ArgumentList $remoteusername, $remotepassword

    if ( $donotuseotp -as [bool] -ne $true ) {
        $objremoteOTP = New-Object System.Management.Automation.PSCredential -ArgumentList $remoteusername, $remoteotp
    }
}

# cleanup password vars as they are in the secure objects now
if ($localpassword -ne $null) { Remove-Variable localpassword} 
if ($localotp -ne $null) { Remove-Variable localotp} 
if ( $urlremote -ne $false ) {
    if ($remotepassword -ne $null) { Remove-Variable remotepassword} 
    if ($remoteotp -ne $null) { Remove-Variable remoteotp} 
}
[System.GC]::Collect()


write-debug $(Get-TimeStamp)

#check if we should submit login or not to prevent login locks
$fetchtime2=$(date)

if ( $donotuseotp -as [bool] -ne $true ) {
    $runtimeineconds=[math]::Round(($fetchtime2-$fetchtime1).TotalSeconds)
}
 write-debug "runtimeineconds:$runtimeineconds"

 if ($($useotpsecrets) -ne $true) {
     if ($runtimeineconds -ge 30 ) { 
     write-error "$(Get-TimeStamp) aborting login to prevent account lock, fill in the forms within 30 seconds"
     cleanupvars
     exit 1
            } else {
            $percent=$(gethalveminutepercent) 
    write-debug "$(Get-TimeStamp) percent of timeout: $percent, there were $([math]::Round(30-(30/100*$percent))) seconds left"

    }
} else {
 write-debug "performing login with otp secrets, ignoring runtime in seconds"
}

write-host "$(Get-TimeStamp) Setting tsstokenlocal global variable with the api token."
#Get-TSSToken -tssapimethod rest -tssapiurl $($tssurllocal) -tssapidomain $localdomain -tssapiuserid $($objlocalCredentials.GetNetworkCredential().Username) -tssapipassword $($objlocalCredentials.GetNetworkCredential().Password) -tssotp $($objlocalOTP.GetNetworkCredential().Password)

if ( $donotuseotp -as [bool] -ne $true ) {
Set-Variable -Scope global -Name tsstokenlocal -value (Get-TSSToken -tssapimethod rest -tssapiurl $($tssurllocal) -tssapidomain $localdomain -tssapiuserid $($objlocalCredentials.GetNetworkCredential().Username) -tssapipassword $($objlocalCredentials.GetNetworkCredential().Password) -tssotp $($objlocalOTP.GetNetworkCredential().Password))
} else {
Set-Variable -Scope global -Name tsstokenlocal -value (Get-TSSToken -tssapimethod rest -tssapiurl $($tssurllocal) -tssapidomain $localdomain -tssapiuserid $($objlocalCredentials.GetNetworkCredential().Username) -tssapipassword $($objlocalCredentials.GetNetworkCredential().Password) -tssotp '')
}

if ( $urlremote -ne $false ) {
    
    write-host "$(Get-TimeStamp) Setting tsstokenremote global variable with the api token."    
    #Get-TSSToken -tssapimethod rest -tssapiurl $($tssurlremote) -tssapidomain $remotedomain -tssapiuserid $($objremoteCredentials.GetNetworkCredential().Username) -tssapipassword $($objremoteCredentials.GetNetworkCredential().Password) -tssotp $($objremoteOTP.GetNetworkCredential().Password)
    if ( $donotuseotp -as [bool] -ne $true ) {
    Set-Variable -Scope global -Name tsstokenremote -value (Get-TSSToken -tssapimethod rest -tssapiurl $($tssurlremote) -tssapidomain $remotedomain -tssapiuserid $($objremoteCredentials.GetNetworkCredential().Username) -tssapipassword $($objremoteCredentials.GetNetworkCredential().Password) -tssotp $($objremoteOTP.GetNetworkCredential().Password))
    } else {
    Set-Variable -Scope global -Name tsstokenremote -value (Get-TSSToken -tssapimethod rest -tssapiurl $($tssurlremote) -tssapidomain $remotedomain -tssapiuserid $($objremoteCredentials.GetNetworkCredential().Username) -tssapipassword $($objremoteCredentials.GetNetworkCredential().Password) -tssotp '')
    }
}

#cleanup secure objects
cleanupvars

