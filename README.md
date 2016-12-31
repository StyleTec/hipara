# Hipara

Source code for the Hipara endpoint client. Hipara is a modular endpoint agent that scans (very quickly!) files being accessed in realtime with the industry standard Yara framework. If a Yara signature matches a malicious file, an alert is generated and sent to the Hipara Server (https://github.com/jbc22/hipara-server).


## How to Install the Endpoint Client

You may either ask me for a signed MSI package by emailing brett@hipara.org or compiling on your own. If you would like a ready-to-use MSI package, send along the domain name or IP address of your Hipara Server. Instructions to compile are provided in the rest of this document.


## Compilation

Instructions were created using a VirtualBox instance running Windows 7 Professional x64. Some people say to install the Windows Driver Kit (WDK) before Visual Studio. The official documentation says otherwise. I installed WDK first, then VS. It takes too long to install both products, so I did not test to see if this makes a difference.

Software needed:
- Microsoft Visual Studio 2013 Professional. Only optional feature installed was "Microsoft Foundation Classes for C++", presented during VS2013 installation.
- Download and install Window's Driver Kit (WDK) 8.1: https://www.microsoft.com/en-us/download/details.aspx?id=42273

Optional software:
- Git for Windows: https://git-scm.com/download/win

Copy the source code by either performing a 'git clone https://github.com/jbc22/hipara.git' or downloading the .zip package from Github (https://github.com/jbc22/hipara/archive/master.zip).

Open hipara\scanner\C++\scanner.sln with Visual Studio 2013 Pro. Then you may build the project.


## After compilation - file output

These instructions are for x64 compilation. 

After building (compilation), the necessary files will all be located at hipara\scanner\HiparaInstaller\files\64\.


## Generate cat file

If scanner.cat does not exist, you will need to use Inf2Cat.exe from WDK 8.1.

Open cmd.exe and navigate to hipara\scanner\HiparaInstaller\files\64. 

Type the following example: "C:\Program Files (x86)\Windows Kits\8.1\bin\x86\Inf2Cat.exe" /os:7_X64 /driver:.


## Signing necessary files

Allsum, LLC (the company behind Hipara) purchased a code signing certificate from DigiCert. To sign the drivers, you will need the Windows Driver Kit (WDK) 8.1 installed as instructed in the "Compilation" section and a pfx certificate file that can perform code signing.

Files to be signed:
 - scanner.sys
 - hiparamemscan.sys
 - scanner.cat
 - hiparamemscan.cat
 
Use signtool.exe from WDK to sign. Example: "C:\Program Files (x86)\Windows Kits\8.1\bin\x64\signtool.exe" sign /v /s my /n "Allsum, LLC" /t http://timestamp.digicert.com <file to sign>


## Creating a MSI package

WiX Toolset is a required download. Currently we support WiX v3.10.2, which can be downloaded here: https://wix.codeplex.com/releases/view/619491

Double-click the hipara\scanner\HiparaInstaller\build.bat file. If there were no errors and the build was successful, your output should be located at hipara\scanner\HiparaInstaller\MSI\Hipara Mini-Filter Driver Setup (x64).msi.

You will want to sign the MSI file with your certificate. Example: "C:\Program Files (x86)\Windows Kits\8.1\bin\x64\signtool.exe" sign /v /s my /n "Allsum, LLC" /t http://timestamp.digicert.com "Hipara Mini-Filter Driver Setup (x64).msi"


## Modules

cmd logging - This module captures every command typed on a box, even if issued from a backdoor. It does so by continually monitoring conhost.exe spawning a cmd.exe process. From there, Hipara will explore the memory pages assigned to those processes looking for the data structure "COMMAND_HISTORY". Inspiration comes from Volatility's "cmd scan" plugin (https://github.com/volatilityfoundation/volatility/wiki/Command%20Reference#cmdscan).


## File Types Scanned

The types of files to be scanned are currently defined in ____.inf. This needs some re-evaluation. Hipara can scan any file type; therefore, work needs to be done to compare actor TTPs of file types used, including fake file extensions (think webshells, text files).


## Roadmap

Anti-Ransomware module: Done!

HUNT module: This module will generate metadata from files on the endpoint using the popular exiftool library. Output will be sent to the Hipara Server, which acts as a relay to send the logs to a SIEM. Incident Responders can hunt for evil by looking for mispellings of common technology vendors like Microsoft, alert on well-known weaponization tools (Trey De Lah), and other hunting techniques Incident Responders can come up with!

Pick and choose block/alert: Hipara currently can do 100% blocking or 100% alerting. In the future, security professionals will be able to pick and choose which Yara signatures they want to block, which you only want to alert on.

GRR (Google Rapid Response) integration: Done in Hipara-Server!
