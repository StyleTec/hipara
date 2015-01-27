hipara
======

Host intrusion prevention with the power of Yara

To Install
======
Right-click and install the scanner.inf file. <br>
Open the command line as administrator and go to the 'compiled' directory. Type "fltmc load scanner". 

To Run
======
While still running as administrator, run "scanuser.exe C:\yarasigs\\[SignatureFile].yar". Example: scanuser.exe  C:\Samples\test.yar

Results
======
If a match is found, it will log to C:\yaraLog.txt. Currently it will only log the message "Virus Signature found".

To Do/Roadmap
======
Add 64-bit support <br>
More detailed logging: file name/patch, Yara rule that matched
