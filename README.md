# Hipara

Source code for the Hipara endpoint client. Hipara is a modular endpoint agent that scans (very quickly!) files being accessed in realtime with the industry standard Yara framework. If a Yara signature matches a malicious file, an alert is generated and sent to the Hipara Server (https://github.com/jbc22/hipara-server).


## How to Install

You may either ask me for a signed MSI package by emailing brett@hipara.org or compiling on your own. If you would like a ready-to-use MSI package, send along the domain name or IP address of your Hipara Server. Instructions to compile are provided in the next section.

## Compilation

Instructions were created using a VirtualBox instance running Windows 7 Professional x64. Some people say to install the Windows Driver Kit (WDK) before Visual Studio. The official documentation says otherwise. I installed WDK first, then VS. It takes too long to install both products, so I did not test to see if this makes a difference.

Software needed:
- Microsoft Visual Studio 2013 Professional. Only optional feature installed was "Microsoft Foundation Classes for C++", presented during VS2013 installation.
- Download and install Window's Driver Kit (WDK) 8.1: https://www.microsoft.com/en-us/download/details.aspx?id=42273

Optional software:
- Git for Windows: https://git-scm.com/download/win

Copy the source code by either performing a 'git clone https://github.com/jbc22/hipara.git' or downloading the .zip package from Github (https://github.com/jbc22/hipara/archive/master.zip).

Open hipara\scanner\C++\scanner.sln with Visual Studio 2013 Pro. Then you may build the project.


## Modules

cmd logging - This module captures every command typed on a box, even if issued from a backdoor. It does so by continually monitoring conhost.exe spawning a cmd.exe process. From there, Hipara will explore the memory pages assigned to those processes looking for the data structure "COMMAND_HISTORY". Inspiration comes from Volatility's "cmd scan" plugin (https://github.com/volatilityfoundation/volatility/wiki/Command%20Reference#cmdscan).


## File Types Scanned

The types of files to be scanned are currently defined in ____.inf. This needs some re-evaluation. Hipara can scan any file type; therefore, work needs to be done to compare actor TTPs of file types used, including fake file extensions (think webshells).

## Roadmap

Anti-Ransomware module - measures the entropy of a file when it is opened and closed. If the difference in entropy is great, a process may be attempting to encrypt files without the user's knowledge. This module will check to see if the process is trusted, as defined by System Admins and/or Incident Responders. If it is not a trusted process, Hipara will suspend the process, prompt the user and generate an alert for Incident Responders.

HUNT module - This module will generate metadata from files on the endpoint using the popular exiftool library. Output will be sent to the Hipara Server, which acts as a relay to send the logs to a SIEM. Incident Responders can hunt for evil by looking for mispellings of common technology vendors like Microsoft, alert on well-known weaponization tools (Trey De Lah), and other hunting techniques Incident Responders can come up with!

Hipara currently can do 100% blocking or 100% alerting. In the future, security professionals will be able to pick and choose which Yara signatures they want to block, which you only want to alert on.

GRR (Google Rapid Response) integration - Hipara is currently focused on detection of evil. By integrating the world-class GRR package, security teams will have a single product that performs both detection and response.
