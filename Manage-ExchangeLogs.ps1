#region Author-Info
########################################################################################################################## 
# Author: Zewwy (Aemilianus Kehler)
# Date:   Feb 19, 2019
# Script: Manage-ExchangeLogs
# This script allows to clear the Exchange server logs.
# 
# Required parameters: 
#   Permissions on the folders and files of the Exchange Front End which holds the log files 
##########################################################################################################################
#endregion
#region Variables
##########################################################################################################################
#   Variables
##########################################################################################################################
#MyLogoArray
$MylogoArray = @(
    ("              This script is brought to you by:              "),
    ("      ___         ___         ___         ___                "),
    ("     /  /\       /  /\       /__/\       /__/\        ___    "),
    ("    /  /::|     /  /:/_     _\_ \:\     _\_ \:\      /__/|   "),
    ("   /  /:/:|    /  /:/ /\   /__/\ \:\   /__/\ \:\    |  |:|   "),
    ("  /  /:/|:|__ /  /:/ /:/_ _\_ \:\ \:\ _\_ \:\ \:\   |  |:|   "),
    (" /__/:/ |:| //__/:/ /:/ //__/\ \:\ \:/__/\ \:\ \:\__|__|:|   "),
    (" \__\/  |:|/:\  \:\/:/ /:\  \:\ \:\/:\  \:\ \:\/:/__/::::\   "),
    ("     |  |:/:/ \  \::/ /:/ \  \:\ \::/ \  \:\ \::/\__\\~~\:\  "),
    ("     |  |::/   \  \:\/:/   \  \:\/:/   \  \:\/:/      \  \:\ "),
    ("     |  |:/     \  \::/     \  \::/     \  \::/        \__\/ "),
    ("     |__|/       \__\/       \__\/       \__\/               "),
    (" ")
)
#Script Definition
$ScriptName = "Manage-ExchangeLogs; cause sometimes; Logs."
$LogScript = @(
("   _________________________________________                "),
("  /                                         \               "),
(" | What?! Logs have taken up all your hard   |              "),
(" | drive space on your server?!?!?!!!!!!     |              "),
("  \_________________________________________/               "),
("         \                                                  "),
(" ")
)

#Script Variables, known log locations of Exhange Server
#Unfortunetly I couldn't find the reg key for IIS Logs:
#HKLM\SOFTWARE\Microsoft\WebManagement\Server\LoggingDirectory
#But I couldn't find it on my server
$IISLogPath="$env:SystemDrive\inetpub\logs\LogFiles"
#OI, I can't seem to find a reg key for this path either, hardcoded it remains
$ExchangeLoggingPath="C:\Program Files\Microsoft\Exchange Server\V15\Logging\"

$ETLRegKeyPath = 'HKLM:\SOFTWARE\Microsoft\Office Server\16.0\Search\Diagnostics\Tracing'
$ETLLogKey2 = 'HKLM:\SOFTWARE\Microsoft\Search Foundation for Exchange\Diagnostics'

#------------------------------------------------------------------------------------------------------------------------
#Static Variables
#------------------------------------------------------------------------------------------------------------------------
#console info Static Variables
$pswheight = (get-host).UI.RawUI.MaxWindowSize.Height
$pswwidth = (get-host).UI.RawUI.MaxWindowSize.Width
#Exhcnage Log Static Variables
$PSRegObj2 = Get-ItemProperty -Path $ETLLogKey2
$PSRegObj = Get-ItemProperty -Path $ETLRegKeyPath
$ETLTotalSize = ($PSRegObj.MaxTraceFileCount*$PSRegObj.MaxTraceFileSize) / 1000
$ETLLoggingPath = $PSRegObj.TracingPath
$ETLLoggingPath2 = $PSRegObj2.LogDir
#User Context Static Variables
$currentPrincipal = New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())
$IsAdmin=$currentPrincipal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
#endregion
#region Functions
##########################################################################################################################
#   Functions
##########################################################################################################################

#function takes in a name to alert confirmation of an action
function confirm()
{
  param(
  [Parameter(Position=0,Mandatory=$true)]
  [string]$name,
  [Parameter(Position=1,Mandatory=$false,ParameterSetName="color")]
  [string]$C
  )
    Centeralize "$name" "$C" -NoNewLine;$answer = Read-Host;Write-Host " "
    Switch($answer)
    {
        yes{$result=0}
        ye{$result=0}
        y{$result=0}
        no{$result=1}
        n{$result=1}
        default{confirm $name $C}
    }
    Switch ($result)
        {
              0 { Return $true }
              1 { Return $false }
        }
}

#Function to Centeralize Write-Host Output, Just take string variable parameter and pads it
function Centeralize()
{
  param(
  [Parameter(Position=0,Mandatory=$true)]
  [string]$S,
  [Parameter(Position=1,Mandatory=$false,ParameterSetName="color")]
  [string]$C,
  [Parameter(Mandatory=$false)]
  [switch]$NoNewLine = $false
  )
    $sLength = $S.Length
    $padamt =  "{0:N0}" -f (($pswwidth-$sLength)/2)
    $PadNum = $padamt/1 + $sLength #the divide by one is a quick dirty trick to covert string to int
    $CS = $S.PadLeft($PadNum," ").PadRight($PadNum," ") #Pad that shit
    if (!$NoNewLine)
    {
        if ($C) #if variable for color exists run below
        {    
            Write-Host $CS -ForegroundColor $C #write that shit to host with color
        }
        else #need this to prevent output twice if color is provided
        {
            $CS #write that shit without color
        }
    }
    else
    {
        if ($C) #if variable for color exists run below
        {    
            Write-Host $CS -ForegroundColor $C -NoNewLine #write that shit to host with color
        }
        else #need this to prevent output twice if color is provided
        {
            Write-Host $CS -NoNewLine #write that shit without color
        }
    }
}

function ValidateNum()
{
    Param( 
        [ValidateRange(1,100)] 
        [Int] 
        $Numbero
  )
}

#Get a number from the user, and ensure it is between 1 and 100, catch terminating errors from bad inputs, and repeat till valid
function GetNum()
{
    try{Write-host "Enter A Number(1,100): " -NoNewline; [Uint16]$Number = Read-Host;try{ValidateNum $Number;return $Number}catch{GetNum}}catch{GetNum}
}

#Check and Configure the ETL logs
function CCETL()
{
    $TheNote = "Your Server is configured to have "+$PSRegObj.MaxTraceFileCount+" ETL Log Files each with a size of "+$PSRegObj.MaxTraceFileSize+"MB which equals a total of "+$ETLTotalSize+"GB`n"
    Centeralize "$TheNote"
    
    if(confirm "Would you like to change these settings? " "Magenta")
    {
        Centeralize "What would you like the Max file Count to be?"
        $GoodNumber = GetNum
        $Question = "You Sure you want to set the new Max ETL file Count to "+$GoodNumber+"? "
        if(confirm $Question "Yellow")
        {
            Try{Set-ItemProperty -Path $ETLRegKeyPath -Name MaxTraceFileCount -Value $GoodNumber -ErrorAction Stop}
            Catch
            {
                $ErrorMessage = $_.Exception.Message
                Centeralize "Message is: $ErrorMessage `n" "red"
                Centeralize "Please Check your permissions! Maybe run Exchange mgmt shell as an admin? `n" "Yellow"
            }
        }
    }
}

Function CleanLogFiles($TargetFolder)
{
    if(Test-Path $TargetFolder)
    {
        try
        {
            $Files = Get-ChildItem $TargetFolder -Recurse -ErrorAction Stop 
            $FolderSize = "{0:N2} GB" -f (($Files | measure Length -s).sum / 1Gb)
            Write-Host $TargetFolder " has a file size of " $FolderSize "`n"
        }
        catch [System.UnauthorizedAccessException]
        {
            $ErrorMessage = $_.Exception.Message
            Centeralize "Message is: $ErrorMessage `n" "red"
            Centeralize "Please Check your permissions! Maybe run Exchange mgmt shell as an admin? `n" "Yellow"
        }
        if (confirm "Delete $TargetFolder`? " "red")
        {

            Remove-item -Recurse $TargetFolder -ErrorAction SilentlyContinue
         }
    }
    Else 
    {
        Write-Host "The folder $TargetFolder doesn't exist! Check the folder path!" -ForegroundColor "red"
    }
}
#endregion
#region Run

#region DisplayLogo
#Start actual script by posting and asking user for responses
foreach($L in $MylogoArray){Centeralize $L "green"}
Centeralize $ScriptName "White"
foreach($L in $LogScript){Centeralize $L "white"}
#endregion

if($IsAdmin)
{
    Centeralize "Congrats you're running elevated, script should run fine. :P`n" "Green"
}
else
{
    Centeralize "Well you're not elevated, good luck...`n" "Yellow"
}

#GO
CCETL

CleanLogfiles($IISLogPath)
CleanLogfiles($ExchangeLoggingPath)
CleanLogfiles($ETLLoggingPath)
CleanLogfiles($ETLLoggingPath2)
#endregion
