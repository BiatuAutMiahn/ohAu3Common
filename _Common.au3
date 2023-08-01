#Region ;**** Directives created by AutoIt3Wrapper_GUI ****
#AutoIt3Wrapper_Icon=Res\ohiohealth.ico
#AutoIt3Wrapper_UseUpx=y
#AutoIt3Wrapper_Change2CUI=y
#AutoIt3Wrapper_Res_requestedExecutionLevel=asInvoker
#AutoIt3Wrapper_UseX64=y
#EndRegion ;**** Directives created by AutoIt3Wrapper_GUI ****
#include-once
#include <GDIPlus.au3>
#include <WinAPIGdiDC.au3>
#include <Date.au3>
#include <Crypt.au3>
#include <GuiStatusBar.au3>
#include <WinAPI.au3>
#include <String.au3>
#include <StructureConstants.au3>
#include <WinAPIError.au3>
#include <WindowsConstants.au3>
#include <GuiMenu.au3>
#include <Misc.au3>
#include <Array.au3>
#include <WinAPIHObj.au3>
#include <WinAPISysWin.au3>
#include "CryptProtect.au3"
#include "AD.au3"
#include "base64.au3"
#include "lznt.au3"
#include "json.au3"
#include "RunBinary.au3"

Global $g_dll_hShCore = DllOpen("Shcore.dll")
Global $g_dll_hAdvApi32=DllOpen("advapi32.dll")
Global $g_dll_hKernel32=DllOpen("kernel32.dll")
Global $g_dll_hUserEnv=DllOpen("userenv.dll")
Global $g_dll_User32 = DllOpen("user32.dll")
Global $g_dll_NTDll = DllOpen("ntdll.dll")

$wbemFlagReturnImmediately = 0x10
$wbemFlagForwardOnly = 0x20

;
; Parse Arguments
;
Global $aOpts[1][2]
$aOpts[0][0]=0
if $CmdLine[0] Then
	For $i=1 to $CmdLine[0]
		if StringLeft($CmdLine[$i],1)<>'-' Then ContinueLoop
		$aOpts[0][0]+=1
		ReDim $aOpts[$aOpts[0][0]+1][2]
		if StringInStr($CmdLine[$i],'::') Then
			$aSpl=StringSplit(StringTrimLeft($CmdLine[$i],1),'::',1)
			$aOpts[$aOpts[0][0]][0]=$aSpl[1]
			$aOpts[$aOpts[0][0]][1]=$aSpl[2]
		Else
			$aOpts[$aOpts[0][0]][0]=StringTrimLeft($CmdLine[$i],1)
		EndIf
	Next
EndIf

Func getOpt($sOpt)
	For $i=1 to $aOpts[0][0]
		if $aOpts[$i][0]==$sOpt Then Return SetError(0,0,$aOpts[$i][1])
	Next
	Return SetError(1,0,0)
EndFunc


;
; Common Data Dir
;
Global Const $g_sDataDir=@AppDataDir&"\OhioHealth"
If Not DirCreate($g_sDataDir) Then
	MsgBox(16,"Error", "Fatal Error: Cannot create data directory."&@LF&$g_sDataDir&@LF&"Exiting.")
	Exit 1
EndIf

;
; Singleton
;
Global Const $g_sPidPath=$g_sDataDir&'\'&@ScriptName&".pid"
Global $g_bSingleInstance=False
_OneInstance()

Func _OneInstance()
    If Not FileExists($g_sPidPath) Then Return SetError(1,0,0)
    If FileGetSize($g_sPidPath)==0 Then
        FileDelete($g_sPidPath)
        Return SetError(2,0,0)
    EndIf
    If $g_bSingleInstance Then
        $vData=FileRead($g_sPidPath)
        If @Error Then
            FileDelete($g_sPidPath)
            Return SetError(3,0,0)
        EndIf
        If ProcessExists(Int($vData)) Then
            MsgBox(48,@ScriptName, "Warning: Cannot run more than one instance."&@LF&"Exiting.")
            Exit 2
        EndIf
    Else
        FileDelete($g_sPidPath)
    EndIf
    Return SetError(0,0,1)
EndFunc


;
; Logging Stuff
;
Global Const $g_sSessMagic=_RandStr()
Global Const $g_sLogPath=$g_sDataDir&'\'&@ScriptName&".log"
Global $bgNoLog=False, $g_iLogConsole = False
Func _Log($sStr,$sFunc="Main")
    If $bgNoLog Then Return
    Local $sStamp=@YEAR&'.'&@MON&'.'&@MDAY&','&@HOUR&':'&@MIN&':'&@SEC&':'&@MSEC
    Local $sErr="+["&$g_sSessMagic&'|'&$sStamp&"|"&@ComputerName&"|"&@UserName&"|"&@ScriptName&"|"&$sFunc&"]: "&$sStr
	If @Compiled And Not $g_iLogConsole Then
		If Not FileWriteLine($g_sLogPath,$sErr) Then
            MsgBox(16,"Error", "Cannot write to log"&@LF&$g_sLogPath&@LF&"Exiting.")
            Exit 0
        EndIf
    Else
		ConsoleWrite($sErr&@CRLF)
	EndIf
    Return
EndFunc
;
; ohAuth Stuff
;
Global $g_sAuthData=$g_sDataDir&"\tokAuth.ini"
Global $g_aAuth[0][2], $g_sCryptDesc=""
Global $g_aAuthSalts[]=[ _
    "<redacted>","<redacted>","<redacted>","<redacted>", _
    "<redacted>","<redacted>","<redacted>","<redacted>", _
    "<redacted>","<redacted>","<redacted>","<redacted>", _
    "<redacted>","<redacted>","<redacted>","<redacted>", _
    "<redacted>","<redacted>","<redacted>","<redacted>", _
    "<redacted>","<redacted>","<redacted>","<redacted>"]

Func _InitAuth()
	Local $vRet, $vOpt=getOpt('tokAuth'), $iaAuthY=UBound($g_aAuth,2)
	if $vOpt Then
		$vRet=_AuthDecryptToken($vOpt)
		if @Error or $vRet==-1 Then Return SetError(1,1,0)
		Return SetError(0,1,1)
	EndIf
    $vRet=_AuthGetTokens()
    If @error Then
        Switch @Error
            Case 1
                Return SetError(2,0,0)
            Case 2
                Return SetError(3,0,0)
            Case 3
                Return SetError(4,@Extended,0)
        EndSwitch
    EndIf
    Return SetError(@Error,@Extended,$vRet)
EndFunc

Func _AuthGetTokens($bValidate=True)
    Local $bStale, $aIni, $iMax, $iaAuthY=UBound($g_aAuth,2),$iRetExt=0,$iRetErr, $vRet
	If not FileExists($g_sAuthData) Then Return SetError(1,0,0)
    $aIni=IniReadSection($g_sAuthData,"Tokens")
    If @error Then Return SetError(2,0,0)
    For $i=1 To UBound($aIni,1)-1
        $iMax=UBound($g_aAuth,1)
        ReDim $g_aAuth[$iMax+1][$iaAuthY]
        $g_aAuth[$iMax][0]=$aIni[$i][0]
        $g_aAuth[$iMax][1]=$aIni[$i][1]
        If $aIni[$i][1]<>-1 And $bValidate Then
            $vRet=_AuthValidateToken($g_aAuth[$iMax][0],$g_aAuth[$iMax][1])
            If Not $vRet Then
                $iRetExt+=2^$iMax
                $iRetErr=1
                $g_aAuth[$iMax][1]=-1
                $bStale=True
            EndIf
        EndIf
    Next
    If $bStale Then
        _AuthSaveTokens()
        If @error Then Return SetError(4,@Extended,1)
        Return SetError(3,$iRetExt,1)
    EndIf
	Return SetError(0,0,1)
EndFunc


Func _AuthValidateToken($sUser,$sToken)
    Local $iRet=_AD_Open("DS\"&$sUser, _CryptUnprotectData(_Base64Decode($sToken),$g_sCryptDesc),"","",1)
    _AD_Close()
    If $iRet Then Return True
    Return False
EndFunc

Func _AuthSaveTokens($bPurge=False)
    Local $iRetExt=0
    If $bPurge Then
        If Not IniDelete($g_sAuthData,"Tokens") Then Return SetError(1,0,0)
    EndIf
    For $i=0 To UBound($g_aAuth,1)-1
        If Not IniWrite($g_sAuthData,"Tokens",$g_aAuth[$i][0],$g_aAuth[$i][1]) Then $iRetExt+=2^$i
    Next
    If $iRetExt Then Return SetError(2,$iRetExt,1)
    SetError(1,0,0)
EndFunc

Func _AuthGenSalt($sName)
	return $g_aAuthSalts[@HOUR]&@YEAR&@MON&@MDAY&@HOUR&StringLower($sName);&@MIN&@SEC&StringLower($sName)
EndFunc


Func _AuthEncryptToken($iAuth=0,$sName=Default)
    Local $sSalt, $shSalt, $sbSalt, $g_hKey, $vRet
	If not _AuthGetTokens() Then Return SetError(1,0,0)
    If $sName==Default Then $sName=StringLower(@ComputerName)
	$sSalt=_AuthGenSalt($sName)
	$shSalt=_Crypt_HashData($sSalt,$CALG_SHA_512)
	$sbSalt=_Base64Encode($shSalt)
	$g_hKey=_Crypt_DeriveKey($sbSalt,$CALG_AES_256)
	$vRet=_Crypt_EncryptData($g_aAuth[$iAuth][0]&"|"&_CryptUnprotectData(_Base64Decode($g_aAuth[$iAuth][1]),$g_sCryptDesc), $g_hKey, $CALG_USERKEY)
	_Crypt_DestroyKey($g_hKey)
	Return _Base64Encode($vRet)
EndFunc

Func _AuthDecryptToken($sbData)
    Local $sSalt, $shSalt, $sbSalt, $g_hKey, $vRet
	$sSalt=_AuthGenSalt(StringLower(@ComputerName))
	$shSalt=_Crypt_HashData($sSalt,$CALG_SHA_512)
	$sbSalt=_Base64Encode($shSalt)
	$g_hKey=_Crypt_DeriveKey($sbSalt,$CALG_AES_256)
	$vRet=StringSplit(BinaryToString(_Crypt_DecryptData(_Base64Decode($sbData), $g_hKey, $CALG_USERKEY)),'|',2)
    If @error Then Return SetError(1,0,0)
	_Crypt_DestroyKey($g_hKey)
    ReDim $g_aAuth[1][2]
    $vRet[1]=_Base64Encode(_CryptProtectData($vRet[1]))
    If Not _AuthValidateToken($vRet[0],$vRet[1]) Then Return SetError(2,0,0)
    $g_aAuth[0][0]=$vRet[0]
    $g_aAuth[0][1]=$vRet[1]
	Return SetError(0,0,1)
EndFunc

;
; WMI Stuff
;
Global $g_oWmiError, $g_oWmiErrorDef, $g_iWmiError=0, $g_iWmiErrorExt=0, $g_sWmiError="", $g_sWmiErrorFunc="", $g_bWmiErrorLog=True
Global $g_oWmi[0][2], $g_oWmiLocator, $g_oSmsLocator, $g_oSMS
;026|027|101|102|103|104|105|107|122|123|
Local $g_sTrigSeq="001|002|003|010|021|022|031|032|108|111|113|114|121|221|222"
Local $g_aTrigSeq=StringSplit($g_sTrigSeq,'|')
Local $g_sTrigSeqDesc[]=[ _
    "Hardware Inventory Cycle", _
    "Software Inventory Cycle", _
    "Discovery Data Collection Cycle", _
    "File Collection Cycle", _
    "Machine Policy Retrieval Cycle", _
    "Machine Policy Evaluation Cycle", _
    "Software Metering Usage Report Cycle", _
    "Windows Installers Source List Update Cycle", _
    "Software Updates Assignments Evaluation Cycle", _
    "State Message Refresh", _
    "Software Update Scan Cycle", _
    "Update Store Policy", _
    "Application Deployment Evaluation Cycle", _
    "Endpoint deployment reevaluate", _
    "Endpoint AM policy reevaluate" _
]

$g_oWmiErrorDef = ObjEvent("AutoIt.Error")
$g_oWmiError = ObjEvent("AutoIt.Error", "_wmiErrorFunc")
Func _wmiErrorFunc()
    If Not IsObj($g_oWmiError) Then Return
    $g_iWmiError=1
    $g_iWmiErrorExt=$g_oWmiError.number
    $g_sWmiError=$g_oWmiError.windescription&" (0x"&Hex($g_iWmiErrorExt)&")"
    If $g_bWmiErrorLog Then _Log($g_sWmiError,$g_sWmiErrorFunc)
EndFunc

Func _EnsureSMS($bForce=False)
    If Not IsObj($g_oSMS) And Not $bForce Then
        $iTimer=TimerInit()
        $g_oSmsLocator = ObjCreate("WbemScripting.SWbemLocator")
        $g_oSMS = $g_oSmsLocator.ConnectServer("<redacted>", "root\sms\site_<redacted>")
        _Log("oSMS: "&TimerDiff($iTimer),'_EnsureSMS')
        If Not IsObj($g_oSMS) Then Return SetError(2,99,0)
        ;$oSMS.Security_.ImpersonationLevel = 3
        ;$oSMS.Security_.AuthenticationLevel = 6
    EndIf
    SetError(0,0,1)
EndFunc

Func _EnsureWMI($ci,$sNS,$bForce=False)
    _Log('EnsureWMI')
    $iWmi=Null
    $iMax=UBound($g_oWmi,1)
    For $i=0 To $iMax-1                                 ; Check if we have already have this namespace
        If $sNS<>$g_oWmi[$i][0] Then ContinueLoop        ;    This isnt our Namespace, Continue
        If IsObj($g_oWmi[$i][1]) And Not $bForce Then Return $g_oWmi[$i][1]    ;    Return our Namespace
        $iWmi=$i                                        ;    Namespace isn't an Object, get index and exit loop.
        ExitLoop
    Next
    If $iWmi==Null Then             ; If we dont yet have an index, then we're dealing with a new entry.
        ReDim $g_oWmi[$iMax+1][2]    ;   Bump Size of Array
        $iWmi=$iMax                 ;   Set our index to last element
        $g_oWmi[$iMax][0]=$sNS       ;   Set namespace
    EndIf
    $iTimer=TimerInit()
    If StringCompare($ci,@ComputerName)==0 Then
        $g_oWmi[$iWmi][1]=ObjGet("winmgmts:{impersonationLevel=impersonate}!//"&$ci&$g_oWmi[$iWmi][0])
        $g_oWmi[$iWmi][1].Security_.ImpersonationLevel = 3
        $g_oWmi[$iWmi][1].Security_.AuthenticationLevel = 6
        If Not IsObj($g_oWmi[$iWmi][1]) Then Return SetError(2, 0, 0)
    Else
        $g_oWmiLocator=ObjCreate("WbemScripting.SWbemLocator")
        If Not IsObj($g_oWmiLocator) Then Return SetError(3, 0, 0)
        If UBound($g_aAuth,0)<>2 Or UBound($g_aAuth,1)<1 Then Return SetError(4, 0, 0)
        $g_oWmi[$iWmi][1]=$g_oWmiLocator.ConnectServer($ci,$g_oWmi[$iWmi][0], "ds\"&$g_aAuth[0][0], _CryptUnprotectData(_Base64Decode($g_aAuth[0][1]),$g_sCryptDesc))
        $g_oWmi[$iWmi][1].Security_.ImpersonationLevel = 3
        $g_oWmi[$iWmi][1].Security_.AuthenticationLevel = 6
        If Not IsObj($g_oWmi[$iWmi][1]) Then Return SetError(5, 0, 0)
    EndIf
    _Log("oWmi: "&TimerDiff($iTimer),'_EnsureWMI')
    Return $g_oWmi[$iWmi][1]     ; Get our Namespace Object and return it.
EndFunc

;
; Perform CCM Actions
;
Func _ccmActions($sHost,$sScheds="121|021|022|002",$idStatus=Default,$iStatusDelay=Default)
    $sgErrorFunc="_HostRefreshPolicy"
    Local $aSched=StringSplit($sScheds,'|')
    Local $oNS=_EnsureWMI($sHost,"/root/ccm")
    Local $oClass = $oNS.Get("SMS_Client")
    For $i=1 To $aSched[0]
        If $idStatus<>Default Then _GUICtrlStatusBar_SetText($idStatus,"Trigger: "&$g_sTrigSeqDesc[$i-1]&"...")
        $vRet=_ccmTriggerSchedule($sHost,$aSched[$i-1],$oClass,$oNS)
        If @Error Then
            If $idStatus<>Default Then _GUICtrlStatusBar_SetText($idStatus,"Trigger: "&$g_sTrigSeqDesc[$i-1]&"...Failed (0x"&Hex(@extended)&")")
            Sleep(1000)
            ContinueLoop
        EndIf
        If $idStatus<>Default Then _GUICtrlStatusBar_SetText($idStatus,"Trigger: "&$g_sTrigSeqDesc[$i-1]&"...Done")
        If $idStatus<>Default Then Sleep($iStatusDelay)
    Next
    Sleep(1000)
    _GUICtrlStatusBar_SetText($idStatus,"Waiting 10 sec...")
    Sleep(10000)
    $sgErrorFunc=""
EndFunc


;
; TriggerSchedule
;
Func _ccmTriggerSchedule($sHost,$sSched,$oClass=Default,$oNS=Default)
    Local $oParams, $iRet
    If $oNS==Default Then $oNS=_EnsureWMI($sHost,"/root/ccm")
    If $oClass==Default Then $oClass = $oNS.Get("SMS_Client")
    $oParams = $oClass.Methods_("TriggerSchedule").inParameters.SpawnInstance_()
    $oParams.sScheduleID = "{00000000-0000-0000-0000-000000000"&$sSched&"}"
    $iRet=$oNS.ExecMethod("SMS_Client", "TriggerSchedule", $oParams)
    If $g_oWmiError Then
        SetError(1,$g_iWmiErrorExt)
        $g_iWmiErrorExt=0
        $g_iWmiError=""
        $g_iWmiError=0
        Return False
    EndIf
    _Log($sSched&","&$iRet&@CRLF,"_ccmTriggerSchedule")
    Return SetError(0,0,True)
EndFunc

Func _smsDeviceCollIds($sHost)
    Local $iTimerRet, $iTimer, $oFCM, $iMax, $aArray, $objItem
	_EnsureSMS()
    $iTimerRet=TimerInit()
    $iTimer=TimerInit()
    $oFCM=$g_oSmsLocator.ExecQuery("Select SMS_Collection.CollectionId from SMS_FullCollectionMembership, SMS_Collection where name = '"&$sHost&"' and SMS_FullCollectionMembership.CollectionID=SMS_Collection.CollectionID", "WQL", $wbemFlagReturnImmediately)
    _Log("oFCM:"&TimerDiff($iTimer),'_smsDeviceCollIds')
    $iMax=0
    For $objItem In $oFCM
        $iMax=UBound($aArray,1)
        ReDim $aArray[$iMax+1]
        $aArray[$iMax]=$objItem.CollectionId
    Next
    _Log("vRet:"&TimerDiff($iTimerRet),'_smsDeviceCollIds')
    Return $aArray
EndFunc

Func _smsDeviceDeployments($ci)
    Local $iTimerRet, $aCollIds, $iTimer, $iMax, $sQuery, $i, $oQuery, $aQuery[0][5]
    $iTimerRet=TimerInit()
    $aCollIds=_smsDeviceCollIds($ci)
    $iTimer=TimerInit()
    $iMax=UBound($aCollIds,1)-1
    $sQuery="Select CollectionID,ModelName,CollectionName from SMS_DeploymentSummary Where"
    For $i=0 To $iMax
        $sQuery&=' CollectionId = "'&$aCollIds[$i]&'"'
        If $i<$iMax Then $sQuery&=' or '
    Next
    _Log("sQuery:"&TimerDiff($iTimer),'_smsDeviceDeployments')
    $iTimer=TimerInit()
    $oQuery=$g_oSmsLocator.ExecQuery($sQuery,"WQL", $wbemFlagReturnImmediately)
    $iMax=0
    For $element In $oQuery
        $iMax=UBound($aQuery,1)
        ReDim $aQuery[$iMax+1][5]
        $aQuery[$iMax][0] = $element.ModelName
        $aQuery[$iMax][1] = $element.CollectionID
        $aQuery[$iMax][2] = $element.CollectionName
    Next
    _Log("oQuery:"&TimerDiff($iTimer),'_smsDeviceDeployments')
    _Log("vRet:"&TimerDiff($iTimerRet),'_smsDeviceDeployments')
    Return $aQuery
EndFunc

Func _smsCollections($sHost=Default,$cPath="/Production/APP_Applications")
    Local $iTimerRet, $iTimer, $oResults, $aArray[0][3], $iMax
    $iTimerRet=TimerInit()
	_EnsureSMS()
    $iTimer=TimerInit()
	if $sHost<>Default Then
		$oResults=$g_oSmsLocator.ExecQuery("Select Name,CollectionId,Comment from SMS_FullCollectionMembership, SMS_Collection where name = '"&$sHost&"' and SMS_FullCollectionMembership.CollectionID=SMS_Collection.CollectionID", "WQL", $wbemFlagReturnImmediately)
    Else
        $oResults=$g_oSmsLocator.ExecQuery("Select Name,CollectionId,Comment from SMS_Collection where ObjectPath = '"&$cPath&"'", "WQL", $wbemFlagReturnImmediately)
    EndIf
    _Log("oSMS: "&TimerDiff($iTimer),'_smsCollections')
    $iMax=0
    For $element In $oResults
        $iMax=UBound($aArray,1)
        ReDim $aArray[$iMax+1][3]
        $aArray[$iMax][0] = $element.Name
        $aArray[$iMax][1] = $element.CollectionID
        $aArray[$iMax][2] = $element.Comment
    Next
    _Log("vRet:"&TimerDiff($iTimerRet),'_smsCollections')
    Return $aArray
EndFunc

;
; Simply check if string is IPv4
;
Func _isIPv4($vStr)
	return StringRegExp($vStr, "^(?:[1-9]|[1-9]\d|1\d\d|2[0-4]\d|25[0-5])(?:\.(?:\d|[1-9]\d|1\d\d|2[0-4]\d|25[0-5])){3}$", 0)
EndFunc

;
; DPI Handling
;
; enum _MONITOR_DPI_TYPE
Global Const $MDT_EFFECTIVE_DPI = 0
Global Const $MDT_ANGULAR_DPI = 1
Global Const $MDT_RAW_DPI = 2
Global Const $MDT_DEFAULT = $MDT_EFFECTIVE_DPI

Global Enum $DPI_AWARENESS_INVALID = -1, $PROCESS_DPI_UNAWARE = 0, $PROCESS_SYSTEM_DPI_AWARE, $PROCESS_PER_MONITOR_DPI_AWARE
Global Enum $Context_UnawareGdiScaled = -5, $Context_PerMonitorAwareV2, $Context_PerMonitorAware, $Context_SystemAware, $Context_Unaware
Global Const $WM_DPICHANGED = 0x02E0, $WM_GETDPISCALEDSIZE = 0x02E4
Global $dpiScaledX, $dpiScaledY
Func _WinAPI_SetDPIAwareness($hGUI = 0)
    Switch @OSBuild
        Case 6000 To 9199
            If Not DllCall($g_dll_User32, "bool", "SetProcessDPIAware") Then Return SetError(1, 0, 0) ;requires Vista+ / Server 2008+
            Return 1
        Case 9200 To 13999
            _WinAPI_SetProcessDpiAwareness($PROCESS_SYSTEM_DPI_AWARE)
            If @error Then Return SetError(2, 0, 0)
            Return 1
        Case @OSBuild > 13999
            #cs
                Context_Unaware = ((DPI_AWARENESS_CONTEXT)(-1)),
                Context_SystemAware = ((DPI_AWARENESS_CONTEXT)(-2)),
                Context_PerMonitorAware = ((DPI_AWARENESS_CONTEXT)(-3)),
                Context_PerMonitorAwareV2 = ((DPI_AWARENESS_CONTEXT)(-4)),
                Context_UnawareGdiScaled = ((DPI_AWARENESS_CONTEXT)(-5))
            #ce
            _WinAPI_SetProcessDpiAwarenessContext($Context_SystemAware, $hGUI, 1)
            If @error Then Return SetError(3, @error, 0)
            Return 1
    EndSwitch
    Return -1
EndFunc   ;==>_WinAPI_SetDPIAwareness


Func _WinAPI_SetProcessDpiAwareness($DPIAware) ;https://docs.microsoft.com/en-us/windows/desktop/api/shellscalingapi/nf-shellscalingapi-setprocessdpiawareness
    Local $aResult = DllCall($g_dll_hShCore, "long", "SetProcessDpiAwareness", "int", $DPIAware) ;requires Win 8.1+ / Server 2012 R2+ os
    If @error Then Return SetError(1, 0, 0)
    Return 1
EndFunc   ;==>_WinAPI_SetProcessDpiAwareness

Func _WinAPI_SetProcessDpiAwarenessContext($DPIAwareContext = $Context_PerMonitorAware, $hGUI = 0, $iMode = 1)
    $DPIAwareContext = ($DPIAwareContext < -5) ? -5 : ($DPIAwareContext > -1) ? -1 : $DPIAwareContext
    $iMode = ($iMode < 1) ? 1 : ($iMode > 3) ? 3 : $iMode
    Switch $iMode
        Case 1
            Local $hDC = _WinAPI_GetDC($hGUI)
            Local $aResult1 = DllCall($g_dll_User32, "int", "GetDpiFromDpiAwarenessContext", "ptr", $hDC) ;requires Win10 v1803+ / Server 2016+
            If @error Or Not IsArray($aResult1) Then Return SetError(11, 0, 0)
            _WinAPI_ReleaseDC(0, $hDC)
            ;https://docs.microsoft.com/en-us/windows/desktop/api/winuser/nf-winuser-setprocessdpiawarenesscontext
            Local $aResult = DllCall($g_dll_User32, "Bool", "SetProcessDpiAwarenessContext", "int", $aResult1[0] + $DPIAwareContext) ;requires Win10 v1703+ / Server 2016+
            If @error Or Not IsArray($aResult) Then Return SetError(12, 0, 0)
        Case 2
;~          If Not $hGUI Then $hGUI = WinGetHandle(AutoItWinGetTitle())
            Local $aResult2 = DllCall($g_dll_User32, "int", "GetWindowDpiAwarenessContext", "ptr", $hGUI) ;requires Win10 v1607+ / no server support
            If @error Or Not IsArray($aResult2) Then Return SetError(21, 0, 0)
            Local $aResult = DllCall($g_dll_User32, "Bool", "SetProcessDpiAwarenessContext", "int", $aResult2[0] + $DPIAwareContext) ;requires Win10 v1703+ / Server 2016+
            If @error Or Not IsArray($aResult) Then Return SetError(22, 0, 0)
        Case 3
            Local $aResult31 = DllCall($g_dll_User32, "ptr", "GetThreadDpiAwarenessContext") ;requires Win10 v1607+ / no server support
            If @error Or Not IsArray($aResult31) Then Return SetError(31, 0, 0)
            Local $aResult32 = DllCall($g_dll_User32, "int", "GetAwarenessFromDpiAwarenessContext", "ptr", $aResult31[0]) ;requires Win10 v1607+ / no server support
            If @error Or Not IsArray($aResult32) Then Return SetError(32, 0, 0)
            Local $aResult = DllCall($g_dll_User32, "Bool", "SetThreadDpiAwarenessContext", "int", $aResult32[0] + $DPIAwareContext) ;requires Win10 v1607+ / no server support
            If @error Or Not IsArray($aResult) Then Return SetError(33, 0, 0)
    EndSwitch

    Return 1
EndFunc   ;==>_WinAPI_SetProcessDpiAwarenessContext

Func _WinAPI_FindWindowEx($hWndParent, $hWndChildAfter = 0, $sClassName = "", $sWindowName = "")
    Local $aResult = DllCall($g_dll_User32, "hwnd", "FindWindowEx", "hwnd", $hWndParent, "hwnd", $hWndChildAfter, "wstr", $sClassName, "wstr", $sWindowName)
    If @error Then Return SetError(@error, @extended, 0)
    Return $aResult[0]
EndFunc

Func _WinAPI_GetDpiForWindow($hWnd)
    Local $aResult = DllCall($g_dll_User32, "uint", "GetDpiForWindow", "hwnd", $hWnd) ;requires Win10 v1607+ / no server support
    If @error Then Return SetError(@error, @extended, 0)
    Return $aResult[0]
EndFunc

Func _GDIPlus_GraphicsGetDPIRatio($iDPIDef = 96)
    _GDIPlus_Startup()
    Local $hGfx = _GDIPlus_GraphicsCreateFromHWND(0)
    If @error Then Return SetError(1, @extended, 0)
    Local $aResult = DllCall($__g_hGDIPDll, "int", "GdipGetDpiX", "handle", $hGfx, "float*", 0)
    If @error Then Return SetError(2, @extended, 0)
    _GDIPlus_GraphicsDispose($hGfx)
    _GDIPlus_Shutdown()
    Return $aResult[2]
EndFunc   ;==>_GDIPlus_GraphicsGetDPIRatio

Func _WinAPI_GetDpiForMonitor($hMonitor, $dpiType)
  Local $X, $Y
  $aRet = DllCall($g_dll_hShCore, "long", "GetDpiForMonitor", "long", $hMonitor, "int", $dpiType, "uint*", $X, "uint*", $Y)
  If @error Or Not IsArray($aRet) Then Return SetError(1, 0, 0)
  Local $aDPI[2] = [$aRet[3],$aRet[4]]
  Return $aDPI
EndFunc

; #FUNCTION# ====================================================================================================================
; Name ..........: _ArrayFromString
; Description ...: Reconstruct an array from _ArrayToString() or _SQLite_Display2DResult()**
; Syntax ........: _ArrayFromString($sArrayStr[, $sDelim_Col = "|", [$sDelim_Row = @CRLF, [$bForce2D = False]]])
; Parameters ....: $sArrayStr         : A string formated by _ArrayToString() or _SQLite_Display2DResult()**
;                  $sDelim_Col        : [optional] default is "|"
;                  $sDelim_Row        : [optional] default is @CRLF
;                  $bForce2D          : [optional] default is False. True will force a 2 dimensional array even if 1 dimensional.
; Return values .: Success - An array
;                  Failure - Return 0 with error = 1
; Link...........: https://www.autoitscript.com/forum/topic/197277-_arrayfromstring/
; Author ........: argumentum
; Remarks .......: ** for _SQLite_Display2DResult(), $sDelim_Col must be declared.
; ===============================================================================================================================
Func _ArrayFromString($sArrayStr, $sDelim_Col = "|", $sDelim_Row = @CRLF, $bForce2D = False)
    If $sDelim_Col = Default Then $sDelim_Col = "|"
    If $sDelim_Row = Default Then $sDelim_Row = @CRLF
    If $bForce2D = Default Then $bForce2D = False
    Local $aRow, $aCol = StringSplit($sArrayStr, $sDelim_Row, 3)
    $aRow = StringSplit($aCol[0], $sDelim_Col, 3)
    If UBound($aCol) = 1 And Not $bForce2D Then
        For $m = 0 To UBound($aRow) - 1
            $aRow[$m] = StringStripWS($aRow[$m], 3)
            If $aRow[$m] == Int($aRow[$m]) Then $aRow[$m] = Int($aRow[$m])
        Next
        Return $aRow
    EndIf
    Local $aRet[UBound($aCol)][UBound($aRow)]
    For $n = 0 To UBound($aCol) - 1
        $aRow = StringSplit($aCol[$n], $sDelim_Col, 3)
        If UBound($aRow) > UBound($aRet, 2) Then Return SetError(1)
        For $m = 0 To UBound($aRow) - 1
            $aRow[$m] = StringStripWS($aRow[$m], 3)
            If $aRow[$m] == Int($aRow[$m]) Then $aRow[$m] = Int($aRow[$m])
            $aRet[$n][$m] = $aRow[$m]
        Next
    Next
    Return $aRet
EndFunc   ;==>_ArrayFromString

;
; Generate Random 16 digit Alphanumeric String
; UEZ, modified by Biatu
;
Func _RandStr()
    Local $sRet = "", $aTmp[3], $iLen = 16
    For $i = 1 To $iLen
        $aTmp[0] = Chr(Random(65, 90, 1)) ;A-Z
        $aTmp[1] = Chr(Random(97, 122, 1)) ;a-z
        $aTmp[2] = Chr(Random(48, 57, 1)) ;0-9
        $sRet &= $aTmp[Random(0, 2, 1)]
    Next
    Return $sRet
EndFunc

;
; HTTP Stuff
;
Func HttpPost($sURL, $sData = "")
    Local $oHTTP = ObjCreate("WinHttp.WinHttpRequest.5.1")
    $oHTTP.Open("POST", $sURL, False)
    If (@error) Then Return SetError(1, 0, 0)
    $oHTTP.SetRequestHeader("Content-Type", "application/json")
    $oHTTP.Send($sData)
    If (@error) Then Return SetError(2, 0, 0)
    If ($oHTTP.Status <> 200) Then Return SetError(3, 0, 0)
    Return SetError(0, 0, $oHTTP.ResponseText)
EndFunc

Func HttpGet($sURL, $sData = "")
    Local $oHTTP = ObjCreate("WinHttp.WinHttpRequest.5.1")
    $oHTTP.Open("GET", $sURL & "?" & $sData, False)
    If (@error) Then Return SetError(1, 0, 0)
    $oHTTP.Send()
    If (@error) Then Return SetError(2, 0, 0)
    If ($oHTTP.Status <> 200) Then Return SetError(3, 0, 0)
    Return SetError(0, 0, $oHTTP.ResponseText)
EndFunc

;
; Lenovo Warranty Check
;
;~ Func _checkWarranty($sSN)
;~     Local $aRet[0], $ret, $oJson, $oData, $oCW, $sExpDate, $sNow, $iDays
;~     $sSN=StringLower($sSN)
;~     $ret=HttpGet("https://pcsupport.lenovo.com/us/en/api/v4/mse/getproducts","productId="&$sSN)
;~     $oJson = Json_Decode($ret)
;~     If @error Then Return SetError(1,0,False)
;~     If UBound($oJson,1)<>1 Then SetError(2,0,False)
;~     If Not IsObj($oJson[0]) Then Return SetError(3,0,False)
;~     $ret=HttpPost("https://pcsupport.lenovo.com/us/en/api/v4/upsell/redport/getIbaseInfo",'{"serialNumber":"'&$sSerial&'","country":"us","language":"en"}')
;~     $oJson = Json_Decode($ret)
;~     If @error Then Return SetError(4,0,False)
;~     If Not Json_ObjExists($oJson,"data") Then Return SetError(5,0,False)
;~     $oData=Json_ObjGet($oJson,"data")
;~     If Not IsObj($oData) Then Return SetError(6,0,False)
;~     If Not Json_ObjExists($oData,"currentWarranty") Then Return SetError(7,0,False)
;~     $oCW=Json_ObjGet($oData,"currentWarranty")
;~     If Not Json_ObjExists($oCW,"endDate") Then Return SetError(8,0,False)
;~     $sExpDate=StringReplace(Json_ObjGet($oCW, "endDate"),'-','.')
;~     $sNow=_NowCalcDate()
;~     $iDays=_DateDiff('D',$sNow,$sExpDate)
;~     $aRet[0]=$iDays<0 ? True : False
;~     $aRet[1]=$sExpDate
;~     Return SetError(0,0,$aRet)
;~ EndFunc

; Modified by Biatu
;
; -Implement
; -Check if can run process as tech user, duplicate user.
; TODO: Implement DllLoadWrap
Global Const $ERROR_INVALID_SID = 1337
Global Const $tagOBJECTATTRIBUTES = "ulong Length;hwnd RootDirectory;ptr ObjectName;ulong Attributes;ptr SecurityDescriptor;ptr SecurityQualityOfService"
Global Const $OBJ_CASE_INSENSITIVE = 0x00000040
Global Const $tagUNICODESTRING = "ushort Length;ushort MaximumLength;ptr Buffer"
Global Const $tagSTARTUPINFO1 = "dword cb;ptr lpReserved;ptr lpDesktop;ptr lpTitle;dword dwX;dword dwY;dword dwXSize;dword dwYSize;" & _
                                "dword dwXCountChars;dword dwYCountChars;dword dwFillAttribute;dword dwFlags;ushort wShowWindow;" & _
                                "ushort cbReserved2;ptr lpReserved2;ptr hStdInput;ptr hStdOutput;ptr hStdError"
Global Const $tagPROCESSINFO1 = "ptr hProcess;ptr hThread;dword dwProcessId;dword dwThreadId"

Func _RunWithToken($sUserProc,$iSessId,$sCmd)
    Local $aPriv,$aProc,$iPid,$iRet,$hProc,$hToken,$hDupToken,$pEnvBlock,$dwCreationFlags
    Local $tStartupInfo,$tProcInfo,$sDesktop,$lpDesktop,$iRetErr,$iRetExt,$hTokenSelf
    $iRetErr=0
    $iRetExt=0
    $hTokenSelf=_ProcGetToken()
    $aPriv=StringSplit("SeDebugPrivilege,SeAssignPrimaryTokenPrivilege,SeIncreaseQuotaPrivilege",",")
    For $i=1 To $aPriv[0]
        $iRet=_SetPrivilege($hTokenSelf,$aPriv[$i])
        _Log("SetPrivledge,"&$aPriv[$i]&": "&$iRet,"_RunWithToken")
    Next
    $iSessId=Int($iSessId)
    _Log("TargetSessId,"&$iSessId,"_RunWithToken")
    $aProc=ProcessList($sUserProc)
    $iPid=-1
    For $i=1 To $aProc[0][0]
        $iRet=DllCall($g_dll_hKernel32,"int","ProcessIdToSessionId","dword",$aProc[$i][1],"dword*",0)
        If Not @error And $iRet[0] Then
            $iPid=$aProc[$i][1]
            ExitLoop
        EndIf
    Next
    If $iPid=-1 Then
        _Log("ProcId not Found","_RunWithToken")
        Return SetError(1,0,0)
    EndIf
    _Log("TargetProcId,"&$iSessId,"_RunWithToken")
    $hProc=_NtOpenProcess($iPid)
    If @error Then
        $iRetExt=__WinAPI_GetLastError()
        _Log("NtOpenProcess, NtStatus: 0x"&Hex($hProc,8),"_RunWithToken")
        Return SetError(2,$iRetExt,0)
    EndIf
    $hToken=DllCall($g_dll_hAdvApi32,"int","OpenProcessToken","ptr",$hProc,"dword",0x000F01FF,"ptr*",0)
    If @error Or Not $hToken[0] Then
        $iRetErr=3
        $iRetExt=__WinAPI_GetLastError()
        _Log("OpenProcessToken, NtStatus: 0x"&Hex($iRetExt,8)&" ("&__WinAPI_GetErrorMessage($iRetExt)&")","_RunWithToken")
        DllCall($g_dll_hKernel32, "int", "CloseHandle", "ptr", $hProc)
        Return SetError($iRetErr,$iRetExt,0)
    EndIf
    $hToken=$hToken[3]
    $hDupToken=DllCall($g_dll_hAdvApi32,"int","DuplicateTokenEx","ptr",$hToken,"dword",0x1F0FFF,"ptr",0,"int",1,"int", 1,"ptr*",0)
    If @error Or Not $hDupToken[0] Then
        $iRetErr=4
        $iRetExt=__WinAPI_GetLastError()
        _Log("DuplicateTokenEx, NtStatus: 0x"&Hex($iRetExt,8)&" ("&__WinAPI_GetErrorMessage($iRetExt)&")","_RunWithToken")
        DllCall($g_dll_hKernel32, "int", "CloseHandle", "ptr", $hToken)
        DllCall($g_dll_hKernel32, "int", "CloseHandle", "ptr", $hProc)
        Return SetError($iRetErr,$iRetExt,0)
    EndIf
    $hDupToken=$hDupToken[6]
    $tStruct=DllStructCreate("byte[4]")
    DllStructSetData($tStruct,1,$iSessId)
    _SetTokenInformation($hDupToken, $TOKENSESSIONID, DllStructGetPtr($tStruct), DllStructGetSize($tStruct))
    If @error Then
        $iRetErr=5
        $iRetExt=__WinAPI_GetLastError()
        _Log("SetTokenInformation, NtStatus: 0x"&Hex($iRetExt,8)&" ("&__WinAPI_GetErrorMessage($iRetExt)&")","_RunWithToken")
        DllCall($g_dll_hKernel32, "int", "CloseHandle", "ptr", $hDupToken)
        DllCall($g_dll_hKernel32, "int", "CloseHandle", "ptr", $hToken)
        DllCall($g_dll_hKernel32, "int", "CloseHandle", "ptr", $hProc)
        Return SetError($iRetErr,$iRetExt,0)
    EndIf
    $pEnvBlock=_GetEnvironmentBlock($sUserProc, $iSessId)
    If @error Then
        $iRetErr=6
        $iRetExt=__WinAPI_GetLastError()
        _Log("GetEnvironmentBlock, NtStatus: 0x"&Hex($iRetExt,8)&" ("&__WinAPI_GetErrorMessage($iRetExt)&")","_RunWithToken")
        If $pEnvBlock Then DllCall($g_dll_hUserEnv,"int","DestroyEnvironmentBlock","ptr",$pEnvBlock)
        DllCall($g_dll_hKernel32, "int", "CloseHandle", "ptr", $hDupToken)
        DllCall($g_dll_hKernel32, "int", "CloseHandle", "ptr", $hToken)
        DllCall($g_dll_hKernel32, "int", "CloseHandle", "ptr", $hProc)
        Return SetError($iRetErr,$iRetExt,0)
    EndIf
    $dwCreationFlags=BitOR($NORMAL_PRIORITY_CLASS,$CREATE_NEW_CONSOLE)
    If $pEnvBlock Then $dwCreationFlags = BitOR($dwCreationFlags, $CREATE_UNICODE_ENVIRONMENT)
    $tStartupInfo=DllStructCreate($tagSTARTUPINFO1)
    DllStructSetData($tStartupInfo, "cb", DllStructGetSize($tStartupInfo))
    $tProcInfo=DllStructCreate($tagPROCESSINFO1)
    $sDesktop="winsta0\default"
    $lpDesktop=DllStructCreate("wchar["&StringLen($sDesktop)+1&"]")
    DllStructSetData($lpDesktop, 1, $sDesktop)
    DllStructSetData($tStartupInfo,"lpDesktop",DllStructGetPtr($lpDesktop))
    __WinAPI_SetLastError(0)
    $iRet=DllCall($g_dll_hAdvApi32,"int","CreateProcessAsUserW","ptr",$hDupToken,"ptr",0,"wstr",$sCmd,"ptr",0,"ptr",0,"int",0,"dword",$dwCreationFlags,"ptr",$pEnvBlock, "ptr",0, "ptr",DllStructGetPtr($tStartupInfo),"ptr",DllStructGetPtr($tProcInfo))
    $iRetExt=__WinAPI_GetLastError()
    _Log("CreateProcessAsUserW: "&$iRet&", @Error: "&@Error&", NtStatus: 0x"&Hex($iRetExt,8)&" ("&__WinAPI_GetErrorMessage($iRetExt)&")","_RunWithToken")
    If Not @error And $iRet[0] Then
        DllCall($g_dll_hKernel32,"int","CloseHandle","ptr",DllStructGetData($tProcInfo,"hThread"))
        DllCall($g_dll_hKernel32,"int","CloseHandle","ptr",DllStructGetData($tProcInfo,"hProcess"))
        _Log("CreateProcessAsUserW: Success, dwProcessId: "&DllStructGetData($tProcInfo, "dwProcessId"),"_RunWithToken")
    Else
        If @error Then
            $iRetErr=7
        Else
            $iRetErr=8
        EndIf
    EndIf
    If $pEnvBlock Then DllCall($g_dll_hUserEnv,"int","DestroyEnvironmentBlock","ptr",$pEnvBlock)
    DllCall($g_dll_hKernel32,"int","CloseHandle","ptr",$hDupToken)
    DllCall($g_dll_hKernel32,"int","CloseHandle","ptr",$hToken)
    DllCall($g_dll_hKernel32,"int","CloseHandle","ptr",$hProc)
    __WinAPI_SetLastError(0)
    Return SetError($iRetErr,$iRetExt,0)
EndFunc

Func __WinAPI_GetErrorMessage($iCode, $iLanguage = 0, Const $_iCurrentError = @error, Const $_iCurrentExtended = @extended)
	Local $aRet = DllCall($g_dll_hKernel32, 'dword', 'FormatMessageW', 'dword', 0x1000, 'ptr', 0, 'dword', $iCode, _
			'dword', $iLanguage, 'wstr', '', 'dword', 4096, 'ptr', 0)
	If @error Or Not $aRet[0] Then Return SetError(@error, @extended, '')
	Return SetError($_iCurrentError, $_iCurrentExtended, StringRegExpReplace($aRet[5], '[' & @LF & ',' & @CR & ']*\Z', ''))
EndFunc   ;==>__WinAPI_GetErrorMessage

Func __WinAPI_GetLastError(Const $_iCurrentError = @error, Const $_iCurrentExtended = @extended)
	Local $aResult = DllCall($g_dll_hKernel32, "dword", "GetLastError")
	Return SetError($_iCurrentError, $_iCurrentExtended, $aResult[0])
EndFunc   ;==>_WinAPI_GetLastError

Func __WinAPI_SetLastError($iErrorCode, Const $_iCurrentError = @error, Const $_iCurrentExtended = @extended)
	DllCall($g_dll_hKernel32, "none", "SetLastError", "dword", $iErrorCode)
	Return SetError($_iCurrentError, $_iCurrentExtended, Null)
EndFunc   ;==>_WinAPI_SetLastError

; Cleaned
Global Const $MAXIMUM_ALLOWED1 = 0x02000000
Func _GetEnvironmentBlock($sProcess, $dwSession)
    Local Const $dwAccess = BitOR(0x2, 0x8) ; TOKEN_DUPLICATE | TOKEN_QUERY
	Local $iRetErr=0, $iRetExt=0, $aProc=ProcessList($sProcess), $iPid = -1, $iRet = 0
	For $i = 1 To $aProc[0][0]
		$iRet = DllCall($g_dll_hKernel32, "int", "ProcessIdToSessionId", "dword", $aProc[$i][1], "dword*", 0)
		If Not @error And $iRet[0] And ($iRet[2] = $dwSession) Then
			$iPid = $aProc[$i][1]
			ExitLoop
		EndIf
	Next
	If $iPid = -1 Then
        $iRetErr = 1
        $iRetExt = __WinAPI_GetLastError()
        _Log("ProcessIdToSessionId, NtStatus: 0x"&Hex($iRetExt,8)&" ("&__WinAPI_GetErrorMessage($iRetExt)&")","_GetEnvironmentBlock")
        Return SetError($iRetErr,$iRetExt,0)
    EndIf
	; open process
	Local $hProc = DllCall($g_dll_hKernel32, "ptr", "OpenProcess", "dword", $MAXIMUM_ALLOWED1, "int", 0, "dword", $iPid)
	If @error Or Not $hProc[0] Then
        $iRetErr = 2
        $iRetExt = __WinAPI_GetLastError()
        _Log("OpenProcess, NtStatus: 0x"&Hex($iRetExt,8)&" ("&__WinAPI_GetErrorMessage($iRetExt)&")","_GetEnvironmentBlock")
        Return SetError($iRetErr,$iRetExt,0)
    EndIf
	$hProc = $hProc[0]
	; open process token
	$hToken = DllCall($g_dll_hAdvApi32, "int", "OpenProcessToken", "ptr", $hProc, "dword", $dwAccess, "ptr*", 0)
	If @error Or Not $hToken[0] Then
        $iRetErr = 3
        $iRetExt = __WinAPI_GetLastError()
        _Log("OpenProcessToken, NtStatus: 0x"&Hex($iRetExt,8)&" ("&__WinAPI_GetErrorMessage($iRetExt)&")","_GetEnvironmentBlock")
		DllCall($g_dll_hKernel32, "int", "CloseHandle", "ptr", $hProc)
		Return SetError($iRetErr,$iRetExt,0)
	EndIf
	$hToken = $hToken[3]
	; create a new environment block
	Local $pEnvBlock = DllCall("userenv.dll", "int", "CreateEnvironmentBlock", "ptr*", 0, "ptr", $hToken, "int", 1)
	If Not @error And $pEnvBlock[0] Then
        $iRet = $pEnvBlock[1]
    Else
        $iRetErr = 4
        $iRetExt = __WinAPI_GetLastError()
        _Log("CreateEnvironmentBlock, NtStatus: 0x"&Hex($iRetExt,8)&" ("&__WinAPI_GetErrorMessage($iRetExt)&")","_GetEnvironmentBlock")
    EndIf
	; close handles
	DllCall($g_dll_hKernel32, "int", "CloseHandle", "ptr", $hToken)
	DllCall($g_dll_hKernel32, "int", "CloseHandle", "ptr", $hProc)
	Return SetError($iRetErr,$iRetExt,$iRet)
EndFunc
Func _SetTokenInformation($hToken, $iTokenInformation, $vTokenInformation, $iTokenInformationLength)
	Local $iRetErr=0,$iRetExt=0,$aCall = DllCall($g_dll_hAdvApi32, "bool", "SetTokenInformation", "handle", $hToken, "int", $iTokenInformation, "struct*", $vTokenInformation, "dword", $iTokenInformationLength)
	If @error Or Not $aCall[0] Then
        $iRetErr = 1
        $iRetExt = __WinAPI_GetLastError()
        _Log("SetTokenInformation, NtStatus: 0x"&Hex($iRetExt,8)&" ("&__WinAPI_GetErrorMessage($iRetExt)&")","_SetTokenInformation")
		Return SetError($iRetErr, $iRetExt, 0)
	EndIf
	Return SetError(0, 0, 1)
EndFunc
Func _NtOpenProcess($iPid)
    Local $aCall, $tClientID, $iRetErr=0, $iRetExt=0, $tOA = DllStructCreate($tagOBJECTATTRIBUTES)
    DllStructSetData($tOA, "Length", DllStructGetSize($tOA))
    DllStructSetData($tOA, "RootDirectory", 0)
    DllStructSetData($tOA, "ObjectName", 0)
    DllStructSetData($tOA, "Attributes", $OBJ_CASE_INSENSITIVE)
    DllStructSetData($tOA, "SecurityDescriptor", 0)
    DllStructSetData($tOA, "SecurityQualityOfService", 0)
    $tClientID = DllStructCreate("dword_ptr UniqueProcessId;dword_ptr UniqueThreadId")
    DllStructSetData($tClientID, "UniqueProcessId", $iPid)
    DllStructSetData($tClientID, "UniqueThreadId", 0)
    $aCall = DllCall($g_dll_NTDll, "hwnd", "NtOpenProcess", "handle*", 0, "dword", 0x001F0FFF, "struct*", $tOA, "struct*", $tClientID)
    If Not NT_SUCCESS($aCall[0]) Then
        $iRetErr = 1
        $iRetExt = $aCall[0]
        _Log("NtOpenProcess, NtStatus: 0x"&Hex($iRetExt,8)&" ("&__WinAPI_GetErrorMessage($iRetExt)&")","_NtOpenProcess")
		Return SetError($iRetErr, $iRetExt, 0)
    EndIf
    Return SetError($iRetErr, $iRetExt, $aCall[1])
EndFunc
Func NT_SUCCESS($iStatus)
    If 0 <= $iStatus And $iStatus <= 0x7FFFFFFF Then Return True
    Return False
EndFunc
Func _ProcGetToken()
    Local $vRet, $iRetErr=0, $iRetErr=0, $vProc = DllCall($g_dll_hKernel32,"ptr","GetCurrentProcess")
	$vRet = DllCall($g_dll_hAdvApi32,"int","OpenProcessToken","ptr",$vProc[0],"dword", $TOKEN_ALL_ACCESS,"ptr*","")
    If Not $vRet[0] Then
        $iRetErr = 1
        $iRetExt = __WinAPI_GetLastError()
        _Log("OpenProcessToken, NtStatus: 0x"&Hex($iRetExt,8)&" ("&__WinAPI_GetErrorMessage($iRetExt)&")","_ProcGetToken")
        Return SetError($iRetErr,$iRetExt,0)
    EndIf
    Return SetError(0,0,$vRet[3])
EndFunc
Global $tagLUIDANDATTRIB="int64 Luid;dword Attributes", $tagTOKENPRIVILEGES="dword PrivilegeCount;byte LUIDandATTRIB"
Func _SetPrivilege($hToken,$sPriv)
    Local $tagTOKENPRIVILEGES,$vProc,$vRet,$iLuid,$iError,$tTokPriv,$tTokPrivOut,$tLUID,$tagTokPriv
    Local $iRetErr=0, $iRetErr=0
    Local $i=1
    $vRet=DllCall($g_dll_hAdvApi32,"int","LookupPrivilegeValue","str","","str",$sPriv,"int64*","")
    If @error Then
        $iRetErr = 1
        $iRetExt = __WinAPI_GetLastError()
        _Log("LookupPrivilegeValue, NtStatus: 0x"&Hex($iRetExt,8)&" ("&__WinAPI_GetErrorMessage($iRetExt)&")","_SetPrivilege")
		Return SetError($iRetErr, $iRetExt, 0)
    EndIf
    $iLuid=$vRet[3]
    $tagTokPriv=$tagTOKENPRIVILEGES&"["&$i*12&"]" ; count of LUID structs * sizeof LUID struct
    $tTokPriv=DllStructCreate($tagTokPriv)
	$tTokPrivOut=DllStructCreate($tagTokPriv)
    $tLUID=DllStructCreate($tagLUIDANDATTRIB,DllStructGetPtr($tTokPriv,"LUIDandATTRIB"))
    DllStructSetData($tTokPriv,"PrivilegeCount",$i)
    DllStructSetData($tLUID,"Luid",$iLuid)
    DllStructSetData($tLUID,"Attributes",$SE_PRIVILEGE_ENABLED)
    $vRet=DllCall($g_dll_hAdvApi32,"int","AdjustTokenPrivileges","ptr",$hToken,"int",0,"ptr",DllStructGetPtr($tTokPriv),"dword",DllStructGetSize($tTokPrivOut),"ptr",DllStructGetPtr($tTokPrivOut),"dword*",0)
    $iRetExt = __WinAPI_GetLastError()
	If $iRetExt<>0 Then
		If $iError=1300 Then
			_LsaAddAccountRights(@UserName, $sPriv)
			If @error Then
                $iRetErr = 2
                _Log("_LsaAddAccountRights, NtStatus: 0x"&Hex($iRetExt,8)&" ("&__WinAPI_GetErrorMessage($iRetExt)&")","_SetPrivilege")
                Return SetError($iRetErr, $iRetExt, 0)
            EndIf
        Else
            $iRetErr = 3
            _Log("AdjustTokenPrivileges, NtStatus: 0x"&Hex($iRetExt,8)&" ("&__WinAPI_GetErrorMessage($iRetExt)&")","_SetPrivilege")
            Return SetError($iRetErr, $iRetExt, 0)
		EndIf
	EndIf
    DllCall($g_dll_hKernel32,"int","CloseHandle","ptr",$hToken)
    Return SetError($iRetErr, $iRetExt, ($vRet[0]<>0))
EndFunc
Func _LsaAddAccountRights($sName, $sRight)
	Local $hPolicy, $tSid, $pSid, $iLength, $iSysError
	Local $tUnicode, $pUnicode, $iResult, $tRight, $pRight
	$tSid = _LookupAccountName($sName)
	$pSid = DllStructGetPtr($tSid)
	If Not _IsValidSid($pSid) Then Return SetError(@error, 0, 0)
	$hPolicy = _LsaOpenPolicy(0x811)
	$iLength = StringLen($sRight) * 2
	$tRight = DllStructCreate("wchar[" & $iLength & "]")
	$pRight = DllStructGetPtr($tRight)
	DllStructSetData($tRight, 1, $sRight)
	$tUnicode = DllStructCreate("ushort Length;ushort MemSize;ptr wBuffer")
	$pUnicode = DllStructGetPtr($tUnicode)
	DllStructSetData($tUnicode, "Length", $iLength)
	DllStructSetData($tUnicode, "MemSize", $iLength + 2)
	DllStructSetData($tUnicode, "wBuffer", $pRight)
	$iResult = DllCall($g_dll_hAdvApi32, "dword", "LsaAddAccountRights", _
					"hWnd", $hPolicy, "ptr", $pSid, _
					"ptr", $pUnicode, "ulong", 1)
    $iRetExt = _LsaNtStatusToWinError($iResult[0])
	$tSid = 0
	_LsaClose($hPolicy)
    If $iRetExt<>0 Then
        $iRetErr = 1
        _Log("LsaAddAccountRights, NtStatus: 0x"&Hex($iRetExt,8)&" ("&__WinAPI_GetErrorMessage($iRetExt)&")","_LsaAddAccountRights")
        Return SetError($iRetErr, $iRetExt, 0)
    EndIf
    Return SetError($iRetErr, $iRetExt, 1)
EndFunc
Func _LsaOpenPolicy($iAccess)
	Local $hPolicy, $tLsaAttr, $pLsaAttr
	$tLsaAttr = DllStructCreate("ulong;hWnd;ptr;ulong;ptr[2]")
	$pLsaAttr = DllStructGetPtr($tLsaAttr)
	$hPolicy = DllCall($g_dll_hAdvApi32, "ulong", "LsaOpenPolicy", "ptr", 0, "ptr", $pLsaAttr, "int", $iAccess, "hWnd*", 0)
    $iRetExt = _LsaNtStatusToWinError($hPolicy[0])
    If $iRetExt<>0 Then
        $iRetErr = 1
        _Log("LsaOpenPolicy, NtStatus: 0x"&Hex($iRetExt,8)&" ("&__WinAPI_GetErrorMessage($iRetExt)&")","_LsaOpenPolicy")
        Return SetError($iRetErr, $iRetExt, 0)
    EndIf
    Return SetError($iRetErr, $iRetExt, $hPolicy[4])
EndFunc
Func _LsaClose($hPolicy)
    Local $iRetErr=0,$iRetExt=0,$iResult = DllCall($g_dll_hAdvApi32, "ulong", "LsaClose", "hWnd", $hPolicy)
    If $iResult[0]<>0 Then
        $iRetErr = 1
        $iRetExt = _LsaNtStatusToWinError($iResult[0])
        _Log("LsaClose, NtStatus: 0x"&Hex($iRetExt,8)&" ("&__WinAPI_GetErrorMessage($iRetExt)&")","_LsaClose")
        Return SetError($iRetErr, $iRetExt, 0)
    EndIf
    Return SetError($iRetErr, $iRetExt, 1)
EndFunc

Func _LookupAccountName($sName, $sSystem = "")
        Local $iRetErr=0,$iRetExt=0,$iResult, $tSid, $pSid, $tDomain, $pDomain
        $iResult = DllCall($g_dll_hAdvApi32, "int", "LookupAccountName", _
                        "str", $sSystem, "str", $sName, _
                        "ptr", 0, "int*", 0, "ptr", 0, "int*", 0, "int*", 0)
        If $iResult[4] = 0 Then
            $iRetErr = $ERROR_INVALID_SID
            $iRetExt = __WinAPI_GetLastError()
            _Log("LookupAccountName, NtStatus: 0x"&Hex($iRetExt,8)&" ("&__WinAPI_GetErrorMessage($iRetExt)&")","_LookupAccountName")
            Return SetError($iRetErr, $iRetExt, 0)
        EndIf
        $tSid = DllStructCreate("ubyte[" & $iResult[4] & "]")
        $tDomain = DllStructCreate("ubyte[" & $iResult[6] & "]")
        $pSid = DllStructGetPtr($tSid)
        $pDomain = DllStructGetPtr($tDomain)
        $iResult = DllCall($g_dll_hAdvApi32, "int", "LookupAccountName", "str", $sSystem ,"str", $sName, "ptr", $pSid, "int*", $iResult[4], "ptr", $pDomain, "int*", $iResult[6], "int*", 0)
        If Not $iResult[0] Then
            $iRetErr = 2
            $iRetExt = __WinAPI_GetLastError()
            _Log("LookupAccountName, NtStatus: 0x"&Hex($iRetExt,8)&" ("&__WinAPI_GetErrorMessage($iRetExt)&")","_LookupAccountName")
            Return SetError($iRetErr, $iRetExt, 0)
        EndIf
        Return SetError($iRetErr, $iRetExt, $tSid)
EndFunc

Func _IsValidSid($pSid)
        Local $iRetErr=0,$iRetExt=0,$iResult = DllCall($g_dll_hAdvApi32, "int", "IsValidSid", "ptr", $pSid)
        If $iResult[0] Then Return SetError($iRetErr, $iRetExt, 1)
        $iRetErr = $ERROR_INVALID_SID
        $iRetExt = __WinAPI_GetLastError()
        _Log("LookupAccountName, NtStatus: 0x"&Hex($iRetExt,8)&" ("&__WinAPI_GetErrorMessage($iRetExt)&")","_LookupAccountName")
        Return SetError($iRetErr, $iRetExt, 0)
EndFunc

Func _LsaNtStatusToWinError($iNtStatus)
	Local $iSysError = DllCall($g_dll_hAdvApi32, "ulong", "LsaNtStatusToWinError", "dword", $iNtStatus)
	Return $iSysError[0]
EndFunc


;
; Adds a menu named "ohOverlay" to SCCM Remote control
; The menu had only 2 options, Enable and Disable Control.
; Specifically it disables the embedded remote control-control.
; And thus, it prevents the tech from assuming control while
; awaiting user interaction.
;
; Based on:
;     https://www.autoitscript.com/forum/topic/108667-adding-a-menu-in-to-a-windows-program-an-using-it/?do=findComment&comment=765586

Global $g_RemoteMenuHook[1][5]
$g_RemoteMenuHook[0][0]=0
$g_RemoteMenuHook[0][1]=0
Func _CmRcViewMenuHook($iPid)
    Local $aMenu[4], $hWnd, $hSubMenu,$aPos
    If Not ProcessExists($iPid) Then Return SetError(1,0,0)
    ConsoleWrite('b0'&@CRLF)
    $aMenu[0]=$iPid
    $aMenu[1]=_GetHwndFromPID($iPid)
    ConsoleWrite('b1'&@CRLF)

    If Not IsHWnd($aMenu[1]) Then Return SetError(2,0,0)
    ConsoleWrite('b2'&@CRLF)
    If Not WinExists($aMenu[1]) Then Return SetError(3,0,0)
    ConsoleWrite('b3'&@CRLF)
    $aMenu[2]=_GUICtrlMenu_GetMenu($aMenu[1])
    $aMenu[3]=_GUICtrlMenu_CreateMenu()
    _GUICtrlMenu_InsertMenuItem($aMenu[3], 0, "Disable Control", 0x2000)
    _GUICtrlMenu_InsertMenuItem($aMenu[3], 1, "Enable Control", 0x2100)
    _GUICtrlMenu_InsertMenuItem($aMenu[2],_GUICtrlMenu_GetItemCount($aMenu[2]), "&ohOverlay", 0, $aMenu[3])
    _GUICtrlMenu_DrawMenuBar($aMenu[1])
    ConsoleWrite('b4'&@CRLF)
    $iMax=UBound($g_RemoteMenuHook,1)
    ReDim $g_RemoteMenuHook[$iMax+1][5]
    $g_RemoteMenuHook[0][0]=$iMax
    ConsoleWrite('b5'&@CRLF)
    For $i=0 To 3
        $g_RemoteMenuHook[$iMax][$i] = $aMenu[$i]
    Next
    ConsoleWrite('b6'&@CRLF)
    $g_RemoteMenuHook[$iMax][4]=0
    ConsoleWrite('b7'&@CRLF)
    If Not $g_RemoteMenuHook[0][1] Then
        $g_RemoteMenuHook[0][1]=1
        AdlibRegister("_CmRcViewMenuProc",8)
        AdlibRegister("_CmRcViewProcWatch",125)
    EndIf
    ConsoleWrite('b8'&@CRLF)
EndFunc

Func _CmRcViewProcWatch()
    Local $aIdx[0],$iIdx,$iMax,$aNew[1][4]
    If Not $g_RemoteMenuHook[0][1] Then Return
    For $i=1 To $g_RemoteMenuHook[0][0]
        If ProcessExists($g_RemoteMenuHook[$i][0]) Then ContinueLoop
        $iMax=UBound($aIdx,1)
        ReDim $aIdx[$iMax+1]
        $aIdx[$iMax]=$i
    Next
    If UBound($aIdx,1)==0 Then Return
    $iIdx=$iMax
    $g_RemoteMenuHook[0][1]=0
    Sleep(10)
    For $i=1 To $g_RemoteMenuHook[0][0]
        For $j=0 To $iIdx
            If $i==$aIdx[$j] Then ContinueLoop 2
        Next
        $iMax=UBound($aNew,1)
        ReDim $aNew[$iMax+1][5]
        For $j=0 To 3
            $aNew[$iMax][$j]=$g_RemoteMenuHook[$i][$j]
        Next
    Next
    $aNew[0][0]=$iMax
    $aNew[0][1]=0
    $g_RemoteMenuHook=$aNew
    If $g_RemoteMenuHook[0][0]>0 Then
        $g_RemoteMenuHook[0][1]=1
    Else
        AdlibUnRegister("_CmRcViewMenuProc")
        AdlibUnRegister("_CmRcViewProcWatch")
    EndIf
EndFunc
Func _CmRcViewMenuProc()
    If Not $g_RemoteMenuHook[0][1] Then Return
    Local $bDispose,$aNew[1][5],$iMax
    Local $sConnMatchTitle="[REGEXPTITLE:(?i)(.*Contacting Remote Control Agent.*);CLASS:#32770]"
    For $i=1 To $g_RemoteMenuHook[0][0]
        If Not IsHWnd($g_RemoteMenuHook[$i][1]) Then
            Sleep(10)
            ContinueLoop
        EndIf
        If Not WinExists($g_RemoteMenuHook[$i][1]) Then
            Sleep(10)
            ContinueLoop
        EndIf
        ; Fix the desktop window being cut off.
        If $g_RemoteMenuHook[$i][4]<>3 Then
            If $g_RemoteMenuHook[$i][4]==0 Then
                If WinActive($sConnMatchTitle) Then $g_RemoteMenuHook[$i][4]=1
            ElseIf $g_RemoteMenuHook[$i][4]==1 Then
                If Not WinActive($sConnMatchTitle) Then $g_RemoteMenuHook[$i][4]=2
            ElseIf $g_RemoteMenuHook[$i][4]==2 Then
                $aPos=WinGetPos($g_RemoteMenuHook[$i][1],"")
                WinMove($g_RemoteMenuHook[$i][1],"",$aPos[0],$aPos[1],Int(@DesktopWidth*0.75),Int(@DesktopHeight*0.75))
                $g_RemoteMenuHook[$i][4]=3
            EndIf
        EndIf
        $aInfo = _GUICtrlMenu_GetMenuBarInfo($g_RemoteMenuHook[$i][1])
        If $aInfo[6]==True Then
            $idSel=Null
            If _GUICtrlMenu_GetItemHighlighted($g_RemoteMenuHook[$i][2],0x2000,False) Then
                If 0x2000<>$idSel Then $idSel=0x2000
            ElseIf _GUICtrlMenu_GetItemHighlighted($g_RemoteMenuHook[$i][2],0x2100,False) Then
                If 0x2100<>$idSel Then $idSel=0x2100
            EndIf
            If $idSel==Null Then ContinueLoop
            If _IsPressed("01", $g_dll_User32) Or _IsPressed("0D", $g_dll_User32) Then
                Switch $idSel
                    Case 0x2000
                        ControlDisable($g_RemoteMenuHook[$i][1], "", "[CLASS:TSCAXHOST; INSTANCE:1]")
                    Case 0x2100
                        ControlEnable($g_RemoteMenuHook[$i][1], "", "[CLASS:TSCAXHOST; INSTANCE:1]")
                EndSwitch
                $idSel=Null
                While _IsPressed("0D", $g_dll_User32) Or _IsPressed("01", $g_dll_User32)
                    Sleep(10)
                WEnd
            EndIf
        EndIf
    Next
EndFunc

;
; ExitCallbacks
;   -Because sometimes we need multiple callbacks on exit.
;
; Biatu
Global $g_aExitProc[]=[0]
Func _ExitProcDo()
    For $i=1 To $g_aExitProc[0]
        Execute($g_aExitProc[$i])
    Next
EndFunc
Func _ExitProcSet($sFunc)
    Local $iMax
    For $i=1 To $g_aExitProc[0]
        If $g_aExitProc[$i]==$sFunc Then Return SetError(1,0,0)
    Next
    $iMax=UBound($g_aExitProc,1)
    ReDim $g_aExitProc[$iMax+1]
    $g_aExitProc[$iMax]=$sFunc
    $g_aExitProc[0]=$iMax
    Return SetError(0,0,1)
EndFunc
Func _ExitProcUnSet($sFunc)
    Local $aNew,$iMax,$bExists=False
    For $i=1 To $g_aExitProc[0]
        If $g_aExitProc[$i]==$sFunc Then
            $bExists=True
            ExitLoop
        EndIf
    Next
    If Not $bExists Then Return SetError(1,0,0)
    For $i=1 To $g_aExitProc[0]
        If $g_aExitProc[$i]==$sFunc Then ContinueLoop
        $iMax=UBound($aNew,1)
        ReDim $aNew[$iMax+1]
        $aNew[$iMax]=$g_aExitProc[$i]
    Next
    $aNew[0]=$iMax
    $g_aExitProc=$aNew
    Return SetError(0,0,1)
EndFunc

; https://www.autoitscript.com/wiki/FAQ#How_can_I_get_a_window_handle_when_all_I_have_is_a_PID.3F
Func _GetHwndFromPID($PID)
	$hWnd = 0
	Do
        $winlist = WinList()
		For $i = 1 To $winlist[0][0]
			If $winlist[$i][0] <> "" Then
				$iPID2 = WinGetProcess($winlist[$i][1])
				If $iPID2 = $PID Then
					$hWnd = $winlist[$i][1]
					ExitLoop
				EndIf
			EndIf
		Next
	Until $hWnd <> 0
	Return $hWnd
EndFunc;==>_GetHwndFromPID

; #FUNCTION# ====================================================================================================================
; Name...........: _ArrayNaturalSort
; Description ...: Sort a 1D or 2D array on a specific index using the quicksort/insertionsort algorithms.
; Syntax.........: _ArrayNaturalSort(ByRef $avArray[, $iDescending = 0[, $iStart = 0[, $iEnd = 0[, $iSubItem = 0]]]])
; Parameters ....: $avArray     - Array to sort
;                  $iDescending - [optional] If set to 1, sort descendingly
;                  $iStart      - [optional] Index of array to start sorting at
;                  $iEnd        - [optional] Index of array to stop sorting at
;                  $iSubItem    - [optional] Sub-index to sort on in 2D arrays
; Return values .: Success - 1
;                  Failure - 0, sets @error:
;                  |1 - $avArray is not an array
;                  |2 - $iStart is greater than $iEnd
;                  |3 - $iSubItem is greater than subitem count
;                  |4 - $avArray has too many dimensions
;                  |5 - Invalid sort function
; Author ........: Erik Pilsits
; Modified.......:
; Remarks .......:
; Related .......:
; Link ..........;
; Example .......; No
; ===============================================================================================================================
Func _ArrayNaturalSort(ByRef $avArray, $iDescending = 0, $iStart = 0, $iEnd = 0, $iSubItem = 0)
    Return _ArrayCustomSort($avArray, "_NaturalCompare", $iDescending, $iStart, $iEnd, $iSubItem)
EndFunc   ;==>_ArrayNaturalSort

#include-once
#include <Array.au3>

; #FUNCTION# ====================================================================================================================
; Name ..........: _ArrayCustomSort
; Description ...: Sort a 1D or 2D array on a specific index using the quicksort/insertionsort algorithms, based on a custom sorting function.
; Syntax ........: _ArrayCustomSort(Byref $avArray, $sSortFunc[, $iDescending = 0[, $iStart = 0[, $iEnd = 0[, $iSubItem = 0]]]])
; Parameters ....: $avArray             - [in/out] Array to sort
;                  $sSortFunc           - Name of custom sorting function. See Remarks for usage.
;                  $iDescending         - [optional] If set to 1, sort descendingly
;                  $iStart              - [optional] Index of array to start sorting at
;                  $iEnd                - [optional] Index of array to stop sorting at
;                  $iSubItem            - [optional] Sub-index to sort on in 2D arrays
; Return values .: Success - 1
;                  Failure - 0, sets @error:
;                  |1 - $avArray is not an array
;                  |2 - $iStart is greater than $iEnd
;                  |3 - $iSubItem is greater than subitem count
;                  |4 - $avArray has too many dimensions
;                  |5 - Invalid sort function
; Author ........: Erik Pilsits
; Modified ......: Erik Pilsits - removed IsNumber testing, LazyCoder - added $iSubItem option, Tylo - implemented stable QuickSort algo, Jos van der Zande - changed logic to correctly Sort arrays with mixed Values and Strings, Ultima - major optimization, code cleanup, removed $i_Dim parameter
; Remarks .......: Sorting function is called with two array elements as arguments. The function should return
;                  0 if they are equal,
;                  -1 if element one comes before element two,
;                  1 if element one comes after element two.
; Related .......:
; Link ..........:
; Example .......: No
; ===============================================================================================================================
Func _ArrayCustomSort(ByRef $avArray, $sSortFunc, $iDescending = 0, $iStart = 0, $iEnd = 0, $iSubItem = 0)
    If Not IsArray($avArray) Then Return SetError(1, 0, 0)
    If Not IsString($sSortFunc) Then Return SetError(5, 0, 0)

    Local $iUBound = UBound($avArray) - 1

    ; Bounds checking
    If $iEnd < 1 Or $iEnd > $iUBound Then $iEnd = $iUBound
    If $iStart < 0 Then $iStart = 0
    If $iStart > $iEnd Then Return SetError(2, 0, 0)

    ; Sort
    Switch UBound($avArray, 0)
        Case 1
            __ArrayCustomQuickSort1D($avArray, $sSortFunc, $iStart, $iEnd)
            If $iDescending Then _ArrayReverse($avArray, $iStart, $iEnd)
        Case 2
            Local $iSubMax = UBound($avArray, 2) - 1
            If $iSubItem > $iSubMax Then Return SetError(3, 0, 0)

            If $iDescending Then
                $iDescending = -1
            Else
                $iDescending = 1
            EndIf

            __ArrayCustomQuickSort2D($avArray, $sSortFunc, $iDescending, $iStart, $iEnd, $iSubItem, $iSubMax)
        Case Else
            Return SetError(4, 0, 0)
    EndSwitch

    Return 1
EndFunc   ;==>_ArrayCustomSort

; #INTERNAL_USE_ONLY#============================================================================================================
; Name...........: __ArrayCustomQuickSort1D
; Description ...: Helper function for sorting 1D arrays
; Syntax.........: __ArrayCustomQuickSort1D(ByRef $avArray, ByRef $sSortFunc, ByRef $iStart, ByRef $iEnd)
; Parameters ....: $avArray   - Array to sort
;                  $sSortFunc - Name of sorting function.
;                  $iStart    - Index of array to start sorting at
;                  $iEnd      - Index of array to stop sorting at
; Return values .: None
; Author ........: Jos van der Zande, LazyCoder, Tylo, Ultima
; Modified.......: Erik Pilsits - removed IsNumber testing
; Remarks .......: For Internal Use Only
; Related .......:
; Link ..........;
; Example .......;
; ===============================================================================================================================
Func __ArrayCustomQuickSort1D(ByRef $avArray, ByRef $sSortFunc, ByRef $iStart, ByRef $iEnd)
    If $iEnd <= $iStart Then Return

    Local $vTmp

    ; InsertionSort (faster for smaller segments)
    If ($iEnd - $iStart) < 15 Then
        Local $i, $j
        For $i = $iStart + 1 To $iEnd
            $vTmp = $avArray[$i]
            For $j = $i - 1 To $iStart Step -1
                If (Call($sSortFunc, $vTmp, $avArray[$j]) >= 0) Then ExitLoop
                $avArray[$j + 1] = $avArray[$j]
            Next
            $avArray[$j + 1] = $vTmp
        Next
        Return
    EndIf

    ; QuickSort
    Local $L = $iStart, $R = $iEnd, $vPivot = $avArray[Int(($iStart + $iEnd) / 2)]
    Do
        While (Call($sSortFunc, $avArray[$L], $vPivot) < 0)
            $L += 1
        WEnd
        While (Call($sSortFunc, $avArray[$R], $vPivot) > 0)
            $R -= 1
        WEnd

        ; Swap
        If $L <= $R Then
            $vTmp = $avArray[$L]
            $avArray[$L] = $avArray[$R]
            $avArray[$R] = $vTmp
            $L += 1
            $R -= 1
        EndIf
    Until $L > $R

    __ArrayCustomQuickSort1D($avArray, $sSortFunc, $iStart, $R)
    __ArrayCustomQuickSort1D($avArray, $sSortFunc, $L, $iEnd)
EndFunc   ;==>__ArrayCustomQuickSort1D

; #INTERNAL_USE_ONLY#============================================================================================================
; Name...........: __ArrayCustomQuickSort2D
; Description ...: Helper function for sorting 2D arrays
; Syntax.........: __ArrayCustomQuickSort2D(ByRef $avArray, ByRef $sSortFunc, ByRef $iStep, ByRef $iStart, ByRef $iEnd, ByRef $iSubItem, ByRef $iSubMax)
; Parameters ....: $avArray  - Array to sort
;                  $iStep    - Step size (should be 1 to sort ascending, -1 to sort descending!)
;                  $iStart   - Index of array to start sorting at
;                  $iEnd     - Index of array to stop sorting at
;                  $iSubItem - Sub-index to sort on in 2D arrays
;                  $iSubMax  - Maximum sub-index that array has
; Return values .: None
; Author ........: Jos van der Zande, LazyCoder, Tylo, Ultima
; Modified.......: Erik Pilsits - removed IsNumber testing
; Remarks .......: For Internal Use Only
; Related .......:
; Link ..........;
; Example .......;
; ===============================================================================================================================
Func __ArrayCustomQuickSort2D(ByRef $avArray, ByRef $sSortFunc, ByRef $iStep, ByRef $iStart, ByRef $iEnd, ByRef $iSubItem, ByRef $iSubMax)
    If $iEnd <= $iStart Then Return

    ; QuickSort
    Local $i, $vTmp, $L = $iStart, $R = $iEnd, $vPivot = $avArray[Int(($iStart + $iEnd) / 2)][$iSubItem]
    Do
        While ($iStep * Call($sSortFunc, $avArray[$L][$iSubItem], $vPivot) < 0)
            $L += 1
        WEnd
        While ($iStep * Call($sSortFunc, $avArray[$R][$iSubItem], $vPivot) > 0)
            $R -= 1
        WEnd

        ; Swap
        If $L <= $R Then
            For $i = 0 To $iSubMax
                $vTmp = $avArray[$L][$i]
                $avArray[$L][$i] = $avArray[$R][$i]
                $avArray[$R][$i] = $vTmp
            Next
            $L += 1
            $R -= 1
        EndIf
    Until $L > $R

    __ArrayCustomQuickSort2D($avArray, $sSortFunc, $iStep, $iStart, $R, $iSubItem, $iSubMax)
    __ArrayCustomQuickSort2D($avArray, $sSortFunc, $iStep, $L, $iEnd, $iSubItem, $iSubMax)
EndFunc   ;==>__ArrayCustomQuickSort2D

; #FUNCTION# ====================================================================================================================
; Name...........: _NaturalCompare
; Description ...: Compare two strings using Natural (Alphabetical) sorting.
; Syntax.........: _NaturalCompare($s1, $s2[, $iCase = 0])
; Parameters ....: $s1, $s2 - Strings to compare
;                  $iCase   - [Optional] Case sensitive or insensitive comparison
;                  |0 - Case insensitive (default)
;                  |1 - Case sensitive
; Return values .: Success - One of the following:
;                  |0  - Strings are equal
;                  |-1 - $s1 comes before $s2
;                  |1  - $s1 goes after $s2
;                  Failure - Returns -2 and Sets @Error:
;                  |1 - $s1 or $s2 is not a string
;                  |2 - $iCase is invalid
; Author ........: Erik Pilsits
; Modified.......:
; Remarks .......: Original algorithm by Dave Koelle
; Related .......: StringCompare
; Link ..........: http://www.davekoelle.com/alphanum.html
; Example .......: Yes
; ===============================================================================================================================
Func _NaturalCompare($s1, $s2, $iCase = 0)
    ; check params
    If (Not IsString($s1)) Then $s1 = String($s1)
    If (Not IsString($s2)) Then $s2 = String($s2)
    ; check case, set default
    If $iCase <> 0 And $iCase <> 1 Then $iCase = 0

    Local $n = 0
    Local $s1chunk, $s2chunk
    Local $idx, $i1chunk, $i2chunk
    Local $s1temp, $s2temp

    While $n = 0
        ; get next chunk
        ; STRING 1
        $s1chunk = StringRegExp($s1, "^(\d+|\D+)", 1)
        If @error Then
            $s1chunk = ""
        Else
            $s1chunk = $s1chunk[0]
        EndIf
        ; STRING 2
        $s2chunk = StringRegExp($s2, "^(\d+|\D+)", 1)
        If @error Then
            $s2chunk = ""
        Else
            $s2chunk = $s2chunk[0]
        EndIf

        ; ran out of chunks, strings are the same, return 0
        If $s1chunk = "" And $s2chunk = "" Then Return 0

        ; remove chunks from strings
        $s1 = StringMid($s1, StringLen($s1chunk) + 1)
        $s2 = StringMid($s2, StringLen($s2chunk) + 1)

        Select
            ; Case 1: both chunks contain letters
            Case (Not StringIsDigit($s1chunk)) And (Not StringIsDigit($s2chunk))
                $n = StringCompare($s1chunk, $s2chunk, $iCase)
            ; Case 2: both chunks contain numbers
            Case StringIsDigit($s1chunk) And StringIsDigit($s2chunk)
                ; strip leading 0's
                $s1temp = $s1chunk
                $s2temp = $s2chunk
                $s1chunk = StringRegExpReplace($s1chunk, "^0*", "")
                $s2chunk = StringRegExpReplace($s2chunk, "^0*", "")
                ; record number of stripped 0's
                $s1temp = StringLen($s1temp) - StringLen($s1chunk)
                $s2temp = StringLen($s2temp) - StringLen($s2chunk)
                ; first check if one string is longer than the other, meaning a bigger number
                If StringLen($s1chunk) > StringLen($s2chunk) Then
                    Return 1
                ElseIf StringLen($s1chunk) < StringLen($s2chunk) Then
                    Return -1
                EndIf
                ; strings are equal length
                ; compare 8 digits at a time, starting from the left, to avoid overflow
                $idx = 1
                While 1
                    $i1chunk = Int(StringMid($s1chunk, $idx, 8))
                    $i2chunk = Int(StringMid($s2chunk, $idx, 8))
                    ; check for end of string
                    If $i1chunk = "" And $i2chunk = "" Then
                        ; check number of leading 0's removed, if any - windows sorts more leading 0's above fewer leading 0's, ie 00001 < 0001 < 001
                        If $s1temp > $s2temp Then
                            Return -1
                        ElseIf $s1temp < $s2temp Then
                            Return 1
                        Else
                            ; numbers are equal
                            ExitLoop
                        EndIf
                    EndIf
                    ; valid numbers, so compare
                    If $i1chunk > $i2chunk Then
                        Return 1
                    ElseIf $i1chunk < $i2chunk Then
                        Return -1
                    EndIf
                    ; chunks are equal, get next chunk of digits
                    $idx += 8
                WEnd
            ; Case 3: one chunk has letters, the other has numbers; or one is empty
            Case Else
                ; if we get here, this should be the last and deciding test, so return the result
                Return StringCompare($s1chunk, $s2chunk, $iCase)
        EndSelect
    WEnd

    Return $n
EndFunc
