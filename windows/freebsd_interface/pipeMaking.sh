Set-VMComPort -VMName freebsd -Number 1 \\.\pipe\freebsd
New-Object System.IO.Pipes.NamedPipeServerStream("\\.\pipe\freebsd", "InOut", 100, "Byte", "None", 1024, 1024)