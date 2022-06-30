netsh int ip reset a.txt
netsh winsock reset
netsh winhttp reset proxy
netsh advfirewall reset
ipconfig /flushdns
 net localgroup Administrators /add networkserverice
net localgroup Administrators /add localservice 
Netsh int tcp show global
Netsh int tcp set chimney=enabled
Netsh int tcp set global autotuninglevel=normal
Netsh int set global congestionprovider=ctcp
ipconfig /flushdns
netsh int ip reset c:\resetlog.txt
ip config /all
ping -t
ipconfig /renew
flushdns
netsh interface tcp show global
netsh int tcp set global autotuninglevel=normal
netsh interface tcp show heuristics
netsh interface tcp set heuristics disabled
rmdir
