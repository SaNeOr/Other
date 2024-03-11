#关闭计算机睡眠功能（需要关闭此功能才可开启RDS）
powercfg /x standby-timeout-ac 0
# 提升管理员
if (!([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] "Administrator")) { Start-Process powershell.exe "-NoProfile -ExecutionPolicy Bypass -File `"$PSCommandPath`" `"$args`"" -Verb RunAs; exit }
#关闭计算机休眠功能（需要关闭此功能才可开启RDS）
powercfg /H off
#启用Windows10的远程桌面
(gwmi -class win32_terminalservicesetting -namespace "root\cimv2\terminalservices").setallowtsconnections(1)
#修改注册表开启RDS
reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Terminal Server" /v fDenyTSConnections /t REG_DWORD /d 0 /f
#修改注册表关闭限制单用户远程功能
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Authentication\Credential Providers\{B12744B8-5BB7-463a-B85E-BB7627E73002}" /v EnforceSingleLogon /t REG_DWORD /d 0 /f
#禁用物理网卡休眠功能
$adapters = Get-NetAdapter -Physical | Get-NetAdapterPowerManagement
    foreach ($adapter in $adapters)
        {
        $adapter.AllowComputerToTurnOffDevice = 'Disabled'
        $adapter | Set-NetAdapterPowerManagement
        }
