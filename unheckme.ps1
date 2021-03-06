#configure firewall?
Set-NetFirewallProfile -Name Domain,Private,Public -LogBlocked True

#make rdp secure
New-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services" -Name "SecurityLayer" -Value 2
New-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services" -Name "MinEncryptionLevel" -Value 3
New-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services" -Name "fEncryptRPCTraffic" -Value 1
New-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services" -Name "UserAuthentication" -Value 1

#rdp remote credential guard
reg add HKLM\SYSTEM\CurrentControlSet\Control\Lsa /v DisableRestrictedAdmin /d 0 /t REG_DWORD

#disable SMBv1
Disable-WindowsOptionalFeature -Online -FeatureName smb1protocol
Set-SmbServerConfiguration -EnableSMB1Protocol $false

#configure lockout policy
#this is a pain, couldn't fing the right registry keys

#backup cmd.exe
Copy-Item -Path "C:\Windows\System32\cmd.exe" -Destination "C:\Windows\Fonts\cmd.exe"

#disable guest account
net user guest /active:no

#download some sysinternals
wget https://download.sysinternals.com/files/ProcessMonitor.zip -OutFile "C:\Users\Administrator\Downloads\ProcessMonitor.zip"
wget https://download.sysinternals.com/files/ProcessExplorer.zip -OutFile "C:\Users\Administrator\Downloads\ProcessExplorer.zip"
wget https://download.sysinternals.com/files/Autoruns.zip -OutFile "C:\Users\Administrator\Downloads\Autoruns.zip"
wget https://download.sysinternals.com/files/TCPView.zip -OutFile "C:\Users\Administrator\Downloads\TCPView.zip"

#extract sysinternals
Expand-Archive -Path "C:\Users\Administrator\Downloads\ProcessMonitor.zip" -DestinationPath "C:\Users\Administrator\Downloads\ProcessMonitor"
Expand-Archive -Path "C:\Users\Administrator\Downloads\ProcessExplorer.zip" -DestinationPath "C:\Users\Administrator\Downloads\ProcessExplorer"
Expand-Archive -Path "C:\Users\Administrator\Downloads\Autoruns.zip" -DestinationPath "C:\Users\Administrator\Downloads\Autoruns"
Expand-Archive -Path "C:\Users\Administrator\Downloads\TCPView.zip" -DestinationPath "C:\Users\Administrator\Downloads\TCPView"

#backup sysinternals
Copy-Item -Path "C:\Users\Administrator\Downloads\ProcessMonitor\*" -Destination "C:\Windows\Cursors\dankmemeshere\"
Copy-Item -Path "C:\Users\Administrator\Downloads\ProcessExplorer\*" -Destination "C:\Windows\Cursors\dankmemeshere\"
Copy-Item -Path "C:\Users\Administrator\Downloads\Autoruns\*" -Destination "C:\Windows\Cursors\dankmemeshere\"
Copy-Item -Path "C:\Users\Administrator\Downloads\TCPView\*" -Destination "C:\Windows\Cursors\dankmemeshere\"

#############################################
#stuff you might not want to do is down here#
#############################################
Write-Output "this begins the stuff you might not want to do section"

#disable admin account
$flagboi1 = Read-Host "enter 1 to disable default admin"
if($flagboi1 -eq 1){
net user Administrator /active:no
}

#nuke task scheduler
$flagboi2 = Read-Host "enter 1 to nuke task scheduler"
if($flagboi2 -eq 1){
Remove-Item 'C:\Windows\System32\Tasks'
}