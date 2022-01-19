# SharpGhosting
x64 Process Ghosting in C#

https://www.elastic.co/blog/process-ghosting-a-new-executable-image-tampering-attack  

## Compile options:
1. Build the solution  
2. `PS C:\> C:\Windows\Microsoft.NET\Framework64\v3.5\csc.exe /out:SharpGhost.exe /unsafe C:\Path\to\SharpGhosting\*.cs`  

## Usage:
-real: the exe you want executed [Required]  
-fake: path to a file that doesn't exist (parent directory must exist though) [Optional]  

`PS C:\> .\Path\to\SharpGhosting.exe -real C:\windows\system32\cmd.exe`  
`PS C:\> .\Path\to\SharpGhosting.exe -real C:\windows\system32\cmd.exe -fake C:\windows\temp\`  

![Alt text](/images/demo.png)

## Super helpful projects:
- https://github.com/hasherezade/process_ghosting  
- https://github.com/aaaddress1/PR0CESS/tree/main/miniGhosting  
- https://github.com/FuzzySecurity/Sharp-Suite/tree/master/SwampThing  
