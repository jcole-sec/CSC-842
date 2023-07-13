from rich.progress import track
from rich import print

# Attribution: Detection logic and descriptions are ported from 'Find Evil - Know Normal' graphic by Rob Lee and Mike Pilkington of the SANS Institute, ref: https://www.sans.org/posters/hunt-evil/

def check_system_process(pdata :dict):

    """ Validates System process attributes and returns associated flags if anomalies are present. """

    """ Description: \
        The System process is responsible for most kernel-mode threads. \
        Modules run under System are primarily drivers (.sys files), but also include several important DLLs as well as the kernel executable, ntoskrnl.exe."""

    flags = []

    # Verify no image path exists (the system process is not generated from an executable image)
    if len(pdata['ppath']) > 1:
        print(f'[bold red][!] WARNING: System process should not have a path: {pdata["ppath"]}[/bold red]')
        flags.append('process_path')

    # Verify no parent process exists
    if pdata['ppid'] != 0:
        print(f'[bold red][!] WARNING: System process should not have a parent process: {pdata["ppid_name"]}[/bold red]')
        flags.append('parent_process')

    # Instance_Count = 1
    # Start_Time = ''

    return flags


def check_smss_process(pdata :dict):
    
    """ Validates SMSS process attributes and returns associated flags if anomalies are present. """

    """ Description: \
        The Session Manager process is responsible for creating new sessions. \
        The first instance creates a child instance for each new session. \
        Once the child instance initializes the new session by starting the Windows subsystem (csrss.exe) and wininit.exe for Session 0 or winlogon.exe for Session 1 and higher, the child instance exits."""

    flags = []
    # Verify parent is system (PID 4)
    if pdata['ppid'] != 4:
        print(f'[bold red][!] WARNING: SMSS process should have a parent process of System (PID 4); Parent is : {pdata["ppid_name"]}[/bold red]')
        flags.append('parent_process')

    # Verify image path is %SystemRoot%\System32\smss.exe
    if pdata['ppath'] != 'C:\\Windows\\System32\\smss.exe':
        print(f'[bold red][!] WARNING: Incorrect path for SMSS: {pdata["ppath"]}[/bold red]')
        flags.append('process_path')
    
    # Verify user account is Local System
    if pdata['puser'] != 'NT AUTHORITY\SYSTEM':
        print(f'[bold red][!] WARNING: SMSS should be running as the local system user: {pdata["puser"]}[/bold red]')
        flags.append('process_user')

    return flags


def check_wininit_process(pdata :dict):

    """ Validates WinInit process attributes and returns associated flags if anomalies are present. """

    """ Description: \
        Wininit.exe starts key background processes within Session 0. \
        It starts the Service Control Manager (services.exe), the Local Security Authority process (lsass.exe), and lsaiso.exe for systems with Credential Guard enabled. \
        Note that prior to Windows 10, the Local Session Manager process (lsm.exe) was also started by wininit.exe. \
        As of Windows 10, that functionality has moved to a service DLL (lsm.dll) hosted by svchost.exe."""

    flags = []

    # Verify parent is null; Created by an instance of smss.exe that exits, so tools usually do not provide the parent process name.
    if pdata['ppid_name'] != '-':
        print(f'[bold red][!] WARNING: WinInit process should not have an active parent: {pdata["ppid_name"]}[/bold red]')
        flags.append('parent_process')
    
    # Verify image path is %SystemRoot%\System32\wininit.exe
    if pdata['ppath'] != 'C:\\Windows\\System32\\wininit.exe':
        print(f'[bold red][!] WARNING: Incorrect path for WinInit: {pdata["ppath"]}[/bold red]')
        flags.append('process_path')

    # Verify user account is Local System
    if pdata['puser'] != 'NT AUTHORITY\SYSTEM':
        print(f'[bold red][!] WARNING: WinInit should be running as the local system user: {pdata["puser"]}[/bold red]')
        flags.append('process_user')

    return flags


def check_runtimebroker_process(pdata :dict):

    """ Validates RuntimeBroker process attributes and returns associated flags if anomalies are present. """

    """ Description: \
        RuntimeBroker.exe acts as a proxy between the constrained Universal Windows Platform (UWP) apps (formerly called Metro apps) and the full Windows API. \
        UWP apps have limited capability to interface with hardware and the file system. \
        Broker processes such as RuntimeBroker.exe are therefore used to provide the necessary level of access for UWP apps. \
        Generally, there will be one RuntimeBroker.exe for each UWP app. \
        For example, starting Calculator.exe will cause a corresponding RuntimeBroker.exe process to initiate."""

    flags = []

    # Verify parent is svchost.exe 
    if pdata['ppid_name'] != 'svchost.exe':
        print(f'[bold red][!] WARNING: RunTimeBroker process should have a parent process of svchost; Parent is path: {pdata["ppid_name"]}[/bold red]')
        flags.append('parent_process')

    # Verify image path is %SystemRoot%\System32\RuntimeBroker.exe
    if pdata['ppath'] != 'C:\\Windows\\System32\\RuntimeBroker.exe':
        print(f'[bold red][!] WARNING: Incorrect path for RunTimeBroker: {pdata["ppath"]}[/bold red]')
        flags.append('process_path')

    # Verify user account is variable (typically logged on user)

    return flags


def check_taskhostw_process(pdata :dict):

    """ Validates TaskHostW process attributes and returns associated flags if anomalies are present. """

    """ Description: \
        The generic host process for Windows Tasks. Upon initialization, taskhostw.exe runs a continuous loop listening for trigger events. \
        Example trigger events that can initiate a task include a defi ned schedule, user logon, system startup, idle CPU time, a Windows log event, workstation lock, or workstation unlock. \
        There are more than 160 tasks preconfi gured on a default installation of Windows 10 Enterprise (though many are disabled). \
        All executable files (DLLs & EXEs) used by the default Windows 10 scheduled tasks are signed by Microsoft."""

    flags = []

    # Verify image path is %SystemRoot%\System32\taskhostw.exe
    if pdata['ppath'] != 'C:\\Windows\\System32\\taskhostw.exe':
        print(f'[bold red][!] WARNING: Incorrect path for TaskHostW: {pdata["ppath"]}[/bold red]')
        flags.append('process_path')

    # Verify parent is svchost.exe 
    if pdata['ppid_name'] != 'svchost.exe':
        print(f'[bold red][!] WARNING: TaskHostW process should have a parent process of svchost; Parent is path: {pdata["ppid_name"]}[/bold red]')
        flags.append('parent_process')

    # User Account: variable (may be owned by logged-on users and/or by local service accounts.)

    return flags


def check_winlogon_process(pdata :dict):

    """ Validates TaskHostW process attributes and returns associated flags if anomalies are present. """

    """ Description: \
        Winlogon handles interactive user logons and logoffs. \
        It launches LogonUI.exe, which uses a credential provider to gather credentials from the user, and then passes the credentials to lsass.exe for validation. \
        Once the user is authenticated, Winlogon loads the user’s NTUSER.DAT into HKCU and starts the user’s shell (usually explorer.exe) via userinit.exe."""

    flags = []

    # Verify image path is %SystemRoot%\System32\winlogon.exe
    if pdata['ppath'] != 'C:\\Windows\\System32\\winlogon.exe':
        print(f'[bold red][!] WARNING: Incorrect path for WinLogon: {pdata["ppath"]}[/bold red]')
        flags.append('process_path')

    # Verify parent is null; Created by an instance of smss.exe that exits, so tools usually do not provide the parent process name.
    if pdata['ppid_name'] != '-':
        print(f'[bold red][!] WARNING: WinLogon process should not have an active parent: {pdata["ppid_name"]}[/bold red]')
        flags.append('parent_process')

    # Verify user account is Local System
    if pdata['puser'] != 'NT AUTHORITY\SYSTEM':
        print(f'[bold red][!] WARNING: WinLogon should be running as the local system user: {pdata["puser"]}[/bold red]')
        flags.append('process_user')

    return flags


def check_csrss_process(pdata :dict):

    """ Validates CSRSS process attributes and returns associated flags if anomalies are present. """

    """ Description: \
        The Client/Server Run-Time Subsystem is the user-mode process for the Windows subsystem. \
        Its duties include managing processes and threads, importing many of the DLLs that provide the Windows API, and facilitating shutdown of the GUI during system shutdown. \
        An instance of csrss.exe will run for each session. \
        Session 0 is for services and Session 1 for the local console session. \
        Additional sessions are created through the use of Remote Desktop and/or Fast User Switching. \
        Each new session results in a new instance of csrss.exe."""

    flags = []

    # Verify image path is %SystemRoot%\System32\csrss.exe
    if pdata['ppath'] != 'C:\\Windows\\System32\\csrss.exe':
        print(f'[bold red][!] WARNING: Incorrect path for CSRSS: {pdata["ppath"]}[/bold red]')
        flags.append('process_path')

    # Verify parent is null; Created by an instance of smss.exe that exits, so tools usually do not provide the parent process name.
    if pdata['ppid_name'] != '-':
        print(f'[bold red][!] WARNING: CSRSS process should not have an active parent: {pdata["ppid_name"]}[/bold red]')
        flags.append('parent_process')

    # Verify user account in Local System
    if pdata['puser'] != 'NT AUTHORITY\SYSTEM':
        print(f'[bold red][!] WARNING: CSRSS should be running as the local system user: {pdata["puser"]}[/bold red]')
        flags.append('process_user')

    return flags


def check_services_process(pdata :dict):

    """ Validates Services process attributes and returns associated flags if anomalies are present. """

    """ Description: \
        Implements the Unified Background Process Manager (UBPM), which is responsible for background activities such as services and scheduled tasks. \
        Services.exe also implements the Service Control Manager (SCM), which specifi cally handles the loading of services and device drivers marked for auto-start. \
        In addition, once a user has successfully logged on interactively, the SCM (services.exe) considers the boot successful and sets the Last Known Good control set \
        (HKLM\SYSTEM\Select\LastKnownGood) to the value of the CurrentControlSet."""

    flags = []

    # Verify image path is %SystemRoot%\System32\services.exe
    if pdata['ppath'] != 'C:\\Windows\\System32\\services.exe':
        print(f'[bold red][!] WARNING: Incorrect path for Services: {pdata["ppath"]}[/bold red]')
        flags.append('process_path')

    # Verify parent is wininit
    if pdata['ppid_name'] != 'wininit.exe':
        print(f'[bold red][!] WARNING: Services process should have WinInit as parent: {pdata["ppid_name"]}[/bold red]')
        flags.append('parent_process')

    # Verify user account in Local System
    if pdata['puser'] != 'NT AUTHORITY\SYSTEM':
        print(f'[bold red][!] WARNING: Services should be running as the local system user: {pdata["puser"]}[/bold red]')
        flags.append('process_user')

    return flags


def check_svchost_process(pdata :dict):
    """ Validates SvcHost process attributes and returns associated flags if anomalies are present. """

    """ Description: \
        Generic host process for Windows services. It is used for running service DLLs. \
        Windows will run multiple instances of svchost.exe, each using a unique “-k” parameter for grouping similar services. \
        Typical “-k” parameters include DcomLaunch, RPCSS, LocalServiceNetworkRestricted, LocalServiceNoNetwork, LocalServiceAndNoImpersonation, netsvcs, NetworkService, and more. \
        Malware authors often take advantage of the ubiquitous nature of svchost.exe and use it either to host a malicious DLL as a service, or run a malicious process named svchost.exe or similar spelling. \
        Beginning in Windows 10 version 1703, Microsoft changed the default grouping of similar services if the system has more than 3.5 GB of RAM. \
        In such cases, most services will run under their own instance of svchost.exe. \
        On systems with more than 3.5 GB RAM, expect to see more than 50 instances of svchost.exe (the screenshot in the poster is a Windows 10 VM with 3 GB RAM)."""

    flags = []

    # Verify image path is %SystemRoot%\System32\svchost.exe
    if pdata['ppath'] != 'C:\\Windows\\System32\\svchost.exe':
        print(f'[bold red][!] WARNING: Incorrect path for SvcHost: {pdata["ppath"]}[/bold red]')
        flags.append('process_path')

    # Verify parent is services.exe
    if pdata['ppid_name'] != 'services.exe':
        print(f'[bold red][!] WARNING: SvcHost process should have Services as parent: {pdata["ppid_name"]}[/bold red]')
        flags.append('parent_process')
    
    # User account: Varies depending on svchost instance, though it typically will be Local System, Network Service, or Local Service accounts; Windows 10 also has some instances running as logged-on users. 

    return flags


def check_lsaiso_process(pdata :dict):

    """ Validates LSAISO process attributes and returns associated flags if anomalies are present. """

    """ Description: \
        When Credential Guard is enabled, the functionality of lsass.exe is split between two processes – itself and lsaiso.exe. \
        Most of the functionality stays within lsass.exe, but the important role of safely storing account credentials moves to lsaiso.exe. \
        It provides safe storage by running in a context that is isolated from other processes through hardware virtualization technology. \
        When remote authentication is required, lsass.exe proxies the requests using an RPC channel with lsaiso.exe in order to authenticate the user to the remote service. \
        Note that if Credential Guard is not enabled, lsaiso.exe should not be running on the system."""

    flags = []

    # Verify image path is %SystemRoot%\System32\lsaiso.exe
    if pdata['ppath'] != 'C:\\Windows\\System32\\lsaiso.exe':
        print(f'[bold red][!] WARNING: Incorrect path for LSAISO: {pdata["ppath"]}[/bold red]')
        flags.append('process_path')

    # Verify parent is wininit
    if pdata['ppid_name'] != 'wininit.exe':
        print(f'[bold red][!] WARNING: LSAISO process should have WinInit as parent: {pdata["ppid_name"]}[/bold red]')
        flags.append('parent_process')

    # Verify user account in Local System
    if pdata['puser'] != 'NT AUTHORITY\SYSTEM':
        print(f'[bold red][!] WARNING: LSAISO should be running as the local system user: {pdata["puser"]}[/bold red]')
        flags.append('process_user')

    return flags


def check_lsass_process(pdata :dict):

    """ Validates LSASS process attributes and returns associated flags if anomalies are present. """

    """ Description: \
        The Local Security Authentication Subsystem Service process is responsible for authenticating users by calling an appropriate authentication package specified in HKLM\SYSTEM\CurrentControlSet\Control\Lsa. \
        Typically, this will be Kerberos for domain accounts or MSV1_0 for local accounts. \
        In addition to authenticating users, lsass.exe is also responsible for implementing the local security policy (such as password policies and audit policies) and for writing events to the security event log. \
        Only one instance of this process should occur and it should rarely have child processes (EFS is a known exception)."""

    flags = []

    # Verify image path is %SystemRoot%\System32\lsass.exe
    if pdata['ppath'] != 'C:\\Windows\\System32\\lsass.exe':
        print(f'[bold red][!] WARNING: Incorrect path for LSASS: {pdata["ppath"]}[/bold red]')
        flags.append('process_path')

    # Verify parent is wininit
    if pdata['ppid_name'] != 'wininit.exe':
        print(f'[bold red][!] WARNING: LSASS process should have WinInit as parent: {pdata["ppid_name"]}[/bold red]')
        flags.append('parent_process')

    # Verify user account in Local System
    if pdata['puser'] != 'NT AUTHORITY\SYSTEM':
        print(f'[bold red][!] WARNING: LSASS should be running as the local system user: {pdata["puser"]}[/bold red]')
        flags.append('process_user')

    return flags


def check_explorer_process(pdata :dict):

    """ Validates Explorer process attributes and returns associated flags if anomalies are present. """

    """ Description: \
        At its core, Explorer provides users access to files. \
        Functionally, though, it is both a file browser via Windows Explorer (though still explorer.exe) and a user interface providing features such as the user’s Desktop, the Start Menu, the Taskbar, the Control Panel, \
        and application launching via file extension associations and shortcut files. \
        Explorer.exe is the default user interface specified in the Registry value HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon\Shell, though Windows can alternatively function with another interface such as cmd.exe or powershell.exe. \
        Notice that the legitimate explorer.exe resides in the %SystemRoot% directory rather than %SystemRoot%\System32. \
        Multiple instances per user can occur, such as when the option "Launch folder windows in a separate process" is enabled."""

    flags = []

    # Verify image path is %SystemRoot%\explorer.exe
    if pdata['ppath'] != 'C:\\Windows\\explorer.exe':
        print(f'[bold red][!] WARNING: Incorrect path for Explorer: {pdata["ppath"]}[/bold red]')
        flags.append('process_path')

    # Verify parent is null; Created by an instance of userinit.exe that exits, so analysis tools usually do not provide the parent process name.
    if pdata['ppid'] != '-':
        print(f'[bold red][!] WARNING: Explorer process should not have an active parent: {pdata["ppid_name"]}[/bold red]')
        flags.append('parent_process')

    # Verify user account is logged-on user(s)

    return flags


def run_huntevil_checks(process_list :list):

    """ Checks input process data againsts checks defined in huntvil.py for anomalies """

    hunted_list = []
    
    print('[*] Process anomaly enumeration initiated')

    for process_data in track(process_list):

        process_data['hunt_flags'] = ''

        # System Process
        if process_data['pname'].lower() == 'system':
            process_data['hunt_flags'] = ','.join(check_system_process(process_data))
        
        # SMSS Process
        if process_data['pname'].lower() == 'smss.exe':
           process_data['hunt_flags'] = ','.join(check_smss_process(process_data))
        
        # WinInit Process
        if process_data['pname'].lower() == 'wininit.exe':
            process_data['hunt_flags'] = ','.join(check_wininit_process(process_data))

        # RuntimeBroker Process
        if process_data['pname'].lower() == 'runtimebroker.exe':
            process_data['hunt_flags'] = ','.join(check_runtimebroker_process(process_data))

        # TaskHostW Process
        if process_data['pname'].lower() == 'taskhostw.exe':
            process_data['hunt_flags'] = ','.join(check_taskhostw_process(process_data))
        
        # WinLogon Process
        if process_data['pname'].lower() == 'winlogon.exe':
            process_data[flags] = ','.join(check_winlogon_process(process_data))
        
        # CSRSS Process
        if process_data['pname'].lower() == 'csrss.exe':
            process_data['hunt_flags'] = ','.join(check_csrss_process(process_data))

        # Services Process
        if process_data['pname'].lower() == 'services.exe':
            process_data['hunt_flags'] = ','.join(check_services_process(process_data))

        # SvcHost Process
        if process_data['pname'].lower() == 'taskhostw.exe':
            process_data['hunt_flags'] = ','.join(check_taskhostw_process(process_data))
        
        # LSAISO Process
        if process_data['pname'].lower() == 'lsaiso.exe':
            process_data['hunt_flags'] = ','.join(check_lsaiso_process(process_data))
        
        # LSASS Process
        if process_data['pname'].lower() == 'lsass.exe':
            process_data['hunt_flags'] = ','.join(check_lsass_process(process_data))

        # Explorer Process
        if process_data['pname'].lower() == 'explorer.exe':
            process_data['hunt_flags'] = ','.join(check_explorer_process(process_data))
        
        hunted_list.append(process_data)

    print('[*] Process anomaly enumeration complete\n')
    
    return hunted_list