hipara
======

Host intrusion prevention with the power of Yara

To Install
======
Open the command line as administrator. Type "fltmc load scanner.sys". 

To Run
======
Run "scanuser.exe C:\yarasigs\[SignatureFile].yar". Example: scanuser.exe  C:\Samples\test.yar

Results
======
If a match is found, it will log to C:\yaraLog.txt. Currently it will only log the message "Virus Signature found".

To Do/Roadmap
======
Add 64-bit support
More detailed logging: file name/patch, Yara rule that matched