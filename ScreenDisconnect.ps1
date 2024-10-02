#Desc: Use this script to completely uninstall ScreenConnect
wmic product where "name like 'ScreenConnect Client%%'" call uninstall /nointeractive
