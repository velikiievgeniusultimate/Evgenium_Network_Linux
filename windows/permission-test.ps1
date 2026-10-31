param([string]$Output)
$ErrorActionPreference='Stop'
if($env:GITHUB_ACTIONS -ne 'true' -or $env:RUNNER_ENVIRONMENT -ne 'github-hosted'){throw 'Disposable hosted runner only'}
$version=(Get-Content (Join-Path $PSScriptRoot 'VERSION') -Raw -Encoding UTF8).Trim()
$testRoot=Join-Path $env:SystemDrive ('evg-permission-'+[Guid]::NewGuid().ToString('N'))
$user='evgAclTest';$plain='EvG!'+[Guid]::NewGuid().ToString('N')+'a7';$password=ConvertTo-SecureString $plain -AsPlainText -Force
try{
 $null=New-LocalUser -Name $user -Password $password -AccountNeverExpires -PasswordNeverExpires
 $null=New-Item -ItemType Directory $testRoot
 Copy-Item (Join-Path $Output ('Evgenium-Windows-'+$version+'-x64')) (Join-Path $testRoot 'package') -Recurse
 Copy-Item (Join-Path $PSScriptRoot 'Evgenium.ps1') $testRoot
 Copy-Item (Join-Path $PSScriptRoot 'Policy.ps1') $testRoot
 # The account has a real non-administrator logon token. This reproduces what
 # the original runner-admin-only tests missed, without granting privileges.
 & icacls.exe $testRoot /grant ($user+':(OI)(CI)M') | Out-Null
 $script=@'
param([string]$Root)
$ErrorActionPreference='Stop'
try {
 [Reflection.Assembly]::LoadFile((Join-Path $Root 'package/Evgenium.exe')) | Out-Null
 . (Join-Path $Root 'Evgenium.ps1') -Command selftest -ExecutableDirectory (Join-Path $Root 'package')
 . (Join-Path $Root 'Policy.ps1')
 if(Is-Admin){throw 'Test unexpectedly elevated'}
 Protect-Directory $script:Data
 foreach($i in 1..3){$s=Read-State;$s.name='Обычный пользователь';$s.token=Seal 'test-only-not-a-real-token';Save-State $s;Save-PrivateJSON $script:PolicyPath (Read-Policy);Save-PrivateJSON $script:OptionsPath (Read-Options)}
 if((Unseal (Read-State).token) -ne 'test-only-not-a-real-token'){throw 'DPAPI/state persistence failed'}
 if((Read-State).name -ne 'Обычный пользователь'){throw 'Unicode state persistence failed'}
 $acl=[IO.Directory]::GetAccessControl($script:Data,[Security.AccessControl.AccessControlSections]::Access)
 if(!$acl.AreAccessRulesProtected){throw 'Private directory inherits access'}
 $allowed=@($script:Sid,'S-1-5-18','S-1-5-32-544')
 foreach($rule in $acl.Access){if($rule.IdentityReference.Translate([Security.Principal.SecurityIdentifier]).Value -notin $allowed){throw 'Unexpected access rule'}}
 [IO.File]::WriteAllText((Join-Path $Root 'result.txt'),'PASS: real standard-user token; private ACL/state/policy/options/DPAPI without SeSecurityPrivilege.')
 exit 0
}catch{[IO.File]::WriteAllText((Join-Path $Root 'result.txt'),($_.Exception.ToString()+"`n"+$_.ScriptStackTrace));exit 1}
'@
 [IO.File]::WriteAllText((Join-Path $testRoot 'normal-user.ps1'),$script,[Text.Encoding]::UTF8)
 $cred=New-Object Management.Automation.PSCredential(($env:COMPUTERNAME+'\'+$user),$password)
 $p=Start-Process (Join-Path $env:SystemRoot 'System32/WindowsPowerShell/v1.0/powershell.exe') -Credential $cred -LoadUserProfile -WorkingDirectory $testRoot -ArgumentList '-NoProfile','-ExecutionPolicy','Bypass','-File',('"'+(Join-Path $testRoot 'normal-user.ps1')+'"'),'-Root',('"'+$testRoot+'"') -PassThru
 if(!$p.WaitForExit(60000)){$p.Kill();throw 'Standard-user test timed out'}
 $result=Get-Content (Join-Path $testRoot 'result.txt') -Raw -Encoding UTF8
 [IO.File]::WriteAllText((Join-Path $Output 'standard-user.log'),$result,[Text.Encoding]::UTF8)
 if($p.ExitCode -ne 0){throw $result};Write-Output $result
}finally{
 $plain=$null;$password=$null
 Remove-LocalUser -Name $user -ErrorAction SilentlyContinue
 if(Test-Path $testRoot){Remove-Item $testRoot -Recurse -Force}
}
