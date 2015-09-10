# PowerShell Profile with generous borrowing from 
# https://cyber-defense.sans.org/blog/2010/02/11/powershell-byte-array-hex-convert

###############################################################################
#
# " Changing colors and testing for -Verbose switch..."
#
###############################################################################

if ($host.Name -like "*ISE*")
{
    $psISE.Options.ConsolePaneBackgroundColor = "black"
    $psISE.Options.ConsolePaneTextBackgroundColor = "black"
    $psISE.Options.ConsolePaneForegroundColor = "white"
    $psISE.Options.FontName = "Lucida Console"
    $psISE.Options.FontSize = 12
}
else
{
    [system.console]::set_foregroundcolor("green") 
    [system.console]::set_backgroundcolor("black")
}


function Get-TimestampUTC {
    Get-Date (Get-Date).ToUniversalTime() -Format "yyyy-MM-ddTHH:mm:ssZ"
}

function Get-Timestamp {
    Get-Date -Format "yyyy-MM-dd HH:mm:ss"
}

function Get-Local2Utc {
Param(
    [Parameter(Mandatory=$True)]
        [string]$time
)
    [datetime]::parse($time).ToUniversalTime().ToString("o")
}

function GetByteArray {
Param(
    [Parameter(Mandatory=$True,Position=0,ValueFromPipeLine=$True)]
        [String]$string
)
    ([System.Text.Encoding]::Default.GetBytes($string) | ForEach-Object {
        $Byte = [String]::Format("{0:d}",$_)
        $Byte.PadLeft(3,"0")
    })
}



function rot13 {
# Returns a Rot13 string of the input $value
# May not be the most efficient way to do this
Param(
[Parameter(Mandatory=$True,Position=0)]
    [string]$value
)
    $newvalue = @()
    for ($i = 0; $i -lt $value.length; $i++) {
        $charnum = [int]$value[$i]
        if ($charnum -ge [int][char]'a' -and $charnum -le [int][char]'z') {
            if ($charnum -gt [int][char]'m') {
                $charnum -= 13
            } else {
                $charnum += 13
            }
        } elseif ($charnum -ge [int][char]'A' -and $charnum -le [int][char]'Z') {
            if ($charnum -gt [int][char]'M') {
                $charnum -= 13
            } else {
                $charnum += 13
            }
        }
        $newvalue += [char]$charnum
    }
    $newvalue -join ""
}


function Get-FileHex 
{

##############################################################################
#.Synopsis
#    Display the hex dump of a file.
#
#.Parameter Path
#    Path to file as a string or as a System.IO.FileInfo object;
#    object can be piped into the function, string cannot.
#
#.Parameter Width
#    Number of hex bytes shown per line (default = 16).
#
#.Parameter Count
#    Number of bytes in the file to process (default = all).
#
#.Parameter PlaceHolder
#    What to print when byte is not a character (default = '.' ).
#
#.Parameter NoOffset
#    Switch to suppress offset line numbers in output (left side).
#
#.Parameter NoText
#    Switch to suppress text mapping of bytes in output (right side).
#
#.Notes
#    Date: 1.Jul.2014
# Version: 1.3
#  Author: Jason Fossen, Enclave Consulting LLC (http://www.sans.org/sec505)
#   Legal: Script provided "AS IS" without warranties or guarantees of any
#          kind.  USE AT YOUR OWN RISK.  Public domain.  No rights reserved.
##############################################################################
    [CmdletBinding()] Param 
    (
        [Parameter(Mandatory = $True, ValueFromPipelineByPropertyName = $True)]
        [Alias("FullName","FilePath")] $Path,
        [Int] $Width = 16,
        [Int] $Count = -1,
        [String] $PlaceHolder = ".",
        [Switch] $NoOffset,
        [Switch] $NoText
    )

    $linecounter = 0      # Offset from beginning of file in hex.
    #$placeholder = "."    # What to print when byte is not a letter or digit.


    get-content $path -encoding byte -readcount $width -totalcount $count |
    foreach-object `
    {
         $paddedhex = $text = $null
         $bytes = $_  # Array of [Byte] objects that is $width items in length.


         foreach ($byte in $bytes)`
         {
            $byteinhex = [String]::Format("{0:X}", $byte)   # Convert byte to hex.
            $paddedhex += $byteinhex.PadLeft(2,"0") + " "   # Pad with two zeros.
         } 


         # Total bytes unlikely to be evenly divisible by $width, so fix last line.
         # Hex output width is '$width * 3' because of the extra spaces.
         if ($paddedhex.length -lt $width * 3)
         { $paddedhex = $paddedhex.PadRight($width * 3," ") }


         foreach ($byte in $bytes)`
         {
             if ( [Char]::IsLetterOrDigit($byte) -or
                  [Char]::IsPunctuation($byte) -or
                  [Char]::IsSymbol($byte) )
             { $text += [Char] $byte }
             else
             { $text += $placeholder }
         }


         $offsettext = [String]::Format("{0:X}", $linecounter)  # Linecounter in hex too.
         $offsettext = $offsettext.PadLeft(8,"0") + "h:"        # Pad linecounter with left zeros.
         $linecounter += $width                                 # Increment linecounter.


         if (-not $NoOffset) { $paddedhex = "$offsettext $paddedhex" }
         if (-not $NoText) { $paddedhex = $paddedhex + $text }
         $paddedhex
    }
}


####################################################################################################
#  A couple of functions for coverting to/from Base64 and US-ASCII, as defined in RFC4648.
#  Both functions can accept piped input.
#  Legal: Public Domain, No Warranties or Guarantees of Any Kind, USE AT YOUR OWN RISK.
#####################################################################################################

function Convert-Base64ToAscii 
{ 
    [CmdletBinding()] 
    Param( [Parameter(Mandatory = $True, Position = 0, ValueFromPipeline = $True)] $String )

    [System.Text.Encoding]::ASCII.GetString([System.Convert]::FromBase64String($String)) 

} 



function Convert-AsciiToBase64
{ 
    [CmdletBinding()] 
    Param( [Parameter(Mandatory = $True, Position = 0, ValueFromPipeline = $True)] $String )

    [System.Convert]::ToBase64String([System.Text.Encoding]::ASCII.GetBytes($String)) 
} 




#####################################################################################################
#  The same functions as above, but for Unicode (UTF16-LE) instead of US-ASCII.
#####################################################################################################

function Convert-Base64ToUnicode 
{ 
    [CmdletBinding()] 
    Param( [Parameter(Mandatory = $True, Position = 0, ValueFromPipeline = $True)] $String )

    [System.Text.Encoding]::UNICODE.GetString([System.Convert]::FromBase64String($String)) 
} 


function Convert-UnicodeToBase64
{ 
    [CmdletBinding()] 
    Param( [Parameter(Mandatory = $True, Position = 0, ValueFromPipeline = $True)] $String )

    [System.Convert]::ToBase64String([System.Text.Encoding]::UNICODE.GetBytes($String)) 
} 

#####################################################################################################
#  Convert an array of bytes to/from Base64 when read from a binary file.
#  File does not have to be binary, but it will be read/written as raw bytes.
#  Example: dir file.exe | Convert-FromFileBytesToBase64 | Convert-FromBase64ToFile -Path file2.exe
#####################################################################################################

function Convert-BinaryFileToBase64 
{ 
    [CmdletBinding()] 
    Param( [Parameter(Mandatory = $True, Position = 0, ValueFromPipeline = $True)] $Path )

    [System.Convert]::ToBase64String( $(Get-Content -ReadCount 0 -Encoding Byte -Path $Path) )
} 

function Convert-Base64ToBinaryFile 
{ 
    [CmdletBinding()] 
    Param( [Parameter(Mandatory = $True, Position = 0, ValueFromPipeline = $True)]  $String , 
           [Parameter(Mandatory = $True, Position = 1, ValueFromPipeline = $False)] $Path )

    [System.Convert]::FromBase64String( $String ) | Set-Content -Path $Path -Encoding Byte 

}

function Convert-IntToBits ([UInt32] $Integer, [Switch] $NoLeadingZeros) 
{ 
    if ($NoLeadingZeros) { [System.Convert]::ToString($Integer,2) } 
    else { ([System.Convert]::ToString($Integer,2)).PadLeft(8,"0") } 
}

function Touch ($file) {
    "" | Set-Content -Encoding Ascii $file
}

function prompt
{
    $global:LINE=$global:LINE + 1
    'PS ' + $(Get-Location) + ' ' + '(' + $($global:LINE) + ')' + $(if ($nestedpromptlevel -ge 1) { '>>' }) + ' > '
}

Clear-Host
$VerbosePreference = "Continue"