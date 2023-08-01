#include-once
#include <WinAPI.au3>

; #INDEX# =======================================================================================================================
; Title .........: CryptProtect
; AutoIt Version : 3.3.8.1++
; Description ...: Wrapper functions for the Windows API calls CryptProtectData and CryptUnProtectData.
; Author(s) .....: funkey
; Dll ...........: crypt32.dll
; ===============================================================================================================================


; #CURRENT# =====================================================================================================================
;$tagCRYPTPROTECT_PROMPTSTRUCT
;_CryptProtectData
;_CryptUnprotectData
; ===============================================================================================================================

; #INTERNAL_USE_ONLY# ===========================================================================================================
;$tagDATA_BLOB
;__DataToBlob
;__CryptProtect_DllClose
; ===============================================================================================================================


; #CONSTANTS# ===================================================================================================================
Global Const $CRYPTPROTECT_LOCAL_MACHINE = 0x4
Global Const $CRYPTPROTECT_UI_FORBIDDEN = 0x1
Global Const $CRYPTPROTECT_LOCAL_AUDIT = 0x10
Global Const $CRYPTPROTECT_VERIFY_PROTECTION = 0x40
Global Const $CRYPTPROTECT_PROMPT_ON_PROTECT = 0x2
Global Const $CRYPTPROTECT_PROMPT_ON_UNPROTECT = 0x1

Global Const $CRYPT_I_NEW_PROTECTION_REQUIRED = 0x80091012
; ===============================================================================================================================


; #VARIABLES# ===================================================================================================================
Global $hDLL_Crypt32 = DllOpen("crypt32.dll")
; ===============================================================================================================================

OnAutoItExitRegister("__CryptProtect_DllClose")


; #INTERNAL_USE_ONLY# ===========================================================================================================
; Name...........: $tagDATA_BLOB
; Description ...: The $tagDATA_BLOB structure contains an arbitrary array of bytes
; Fields ........: cbData - A DWORD variable that contains the count, in bytes, of data
;                  pbData - A pointer to the data buffer
; Author ........: funkey
; Remarks .......:
; ===============================================================================================================================
Global Const $tagDATA_BLOB = "DWORD cbData;ptr pbData;"

; #STRUCTURE# ===================================================================================================================
; Name...........: $tagCRYPTPROTECT_PROMPTSTRUCT
; Description ...: The $tagCRYPTPROTECT_PROMPTSTRUCT structure provides the text of a prompt and information about when and where that prompt is to be displayed when using the _CryptProtectData and _CryptUnprotectData functions
; Fields ........: cbSize        - The size, in bytes, of this structure
;                  dwPromptFlags - DWORD flags that indicate when prompts to the user are to be displayed. Current dwPromptFlags values are as follows
;                  |$CRYPTPROTECT_PROMPT_ON_PROTECT   - This flag is used to provide the prompt for the protect phase
;                  |$CRYPTPROTECT_PROMPT_ON_UNPROTECT - This flag can be combined with $CRYPTPROTECT_PROMPT_ON_PROTECT to enforce the UI (user interface) policy of the caller.
;                  +When _CryptUnprotectData is called, the dwPromptFlags specified in the _CryptProtectData call are enforced.
;                  hwndApp       - Window handle to the parent window
;                  szPrompt      - A string containing the text of a prompt to be displayed
; Author ........: funkey
; Remarks .......:
; ===============================================================================================================================
Global Const $tagCRYPTPROTECT_PROMPTSTRUCT = "DWORD cbSize;DWORD dwPromptFlags;HWND hwndApp;ptr szPrompt;"



; #FUNCTION# ====================================================================================================================
; Name...........: _CryptProtectData
; Description ...: Returns the unprotected information as string
; Syntax.........: _CryptProtectData($sString[, $sDesc = ""[, $sPwd = ""[, $iFlag = 0[, $pPrompt = 0]]]])
; Parameters ....: $sString     - String to protect
;                  $sDesc       - A description string for the protected information
;                  $sPwd        - A password string for additional safety if wanted
;                  $iFlag       - Following options can be set, zero means no option
;                  |$CRYPTPROTECT_LOCAL_MACHINE - When this flag is set, it associates the data encrypted with the current computer instead of with an individual user
;                  |$CRYPTPROTECT_UI_FORBIDDEN - For remote situations where UI is no option
;                  |$CRYPTPROTECT_AUDIT - This flag generates an audit on protect and unprotect operations
;                  $pPrompt     - Pointer to a filled $tagCRYPTPROTECT_PROMPTSTRUCT struct
; Return values .: Success      - Binary data with protected information is returned
;                  Failure      - An empty string is returned and @error is set to 1 or 2. When @error = 2 then @extended holds the last Windows error
; Author ........: funkey 2014.08.11th
; Modified.......:
; Remarks .......: Usually, the only user who can decrypt the data is a user with the same logon credentials as the user who encrypted the data.
;                  In addition, the encryption and decryption must be done on the same computer.
; Related .......: _CryptUnprotectData
; Link ..........: http://msdn.microsoft.com/en-us/library/aa380261(v=vs.85).aspx
; Example .......: Yes
; ===============================================================================================================================
Func _CryptProtectData($sString, $sDesc = "", $sPwd = "", $iFlag = 0, $pPrompt = 0)
	Local $aRet, $iError, $tEntropy, $tDesc, $pEntropy = 0, $pDesc = 0
	Local $tDataIn = __DataToBlob($sString)
	If $sPwd <> "" Then
		$tEntropy = __DataToBlob($sPwd)
		$pEntropy = DllStructGetPtr($tEntropy)
	EndIf

	If $sDesc <> "" Then
		$tDesc = DllStructCreate("wchar desc[" & StringLen($sDesc) + 1 & "]")
		DllStructSetData($tDesc, "desc", $sDesc)
		$pDesc = DllStructGetPtr($tDesc)
	EndIf

	Local $tDataBuf = DllStructCreate($tagDATA_BLOB)

	$aRet = DllCall($hDLL_Crypt32, "BOOL", "CryptProtectData", "struct*", $tDataIn, "ptr", $pDesc, "ptr", $pEntropy, "ptr", 0, "ptr", $pPrompt, "DWORD", $iFlag, "struct*", $tDataBuf)
	$iError = @error

	_WinAPI_LocalFree(DllStructGetData($tDataIn, "pbData"))

	If $sPwd <> "" Then _WinAPI_LocalFree(DllStructGetData($tEntropy, "pbData"))
	If $iError Then Return SetError(1, 0, "")
	If $aRet[0] = 0 Then Return SetError(2, _WinAPI_GetLastError(), "")

	Local $tDataOut = DllStructCreate("byte data[" & DllStructGetData($tDataBuf, "cbData") & "]", DllStructGetData($tDataBuf, "pbData"))
	Local $bData = DllStructGetData($tDataOut, "data")

	_WinAPI_LocalFree(DllStructGetData($tDataBuf, "pbData"))

	Return $bData
EndFunc   ;==>_CryptProtectData


; #FUNCTION# ====================================================================================================================
; Name...........: _CryptUnprotectData
; Description ...: Returns the unprotected information as string
; Syntax.........: _CryptUnprotectData($bData, ByRef $sDesc[, $sPwd = ""[, $iFlag = 0[, $pPrompt = 0]]])
; Parameters ....: $bData       - Binary data holding the protected information
;                  $sDesc       - A variable to receive the posible description for the protected information
;                  $sPwd        - A password string for additional safety if wanted
;                  $iFlag       - Following options can be set, zero means no option
;                  |$CRYPTPROTECT_UI_FORBIDDEN - for remote situations where UI is no option
;                  |$CRYPTPROTECT_VERIFY_PROTECTION - Enable higher protection level ($CRYPT_I_NEW_PROTECTION_REQUIRED is returned if higher protection level was used)
;                  $pPrompt     - Pointer to a filled $tagCRYPTPROTECT_PROMPTSTRUCT struct
; Return values .: Success      - A string with unprotected information is returned, $sDesc is filled if needed
;                  Failure      - An empty string is returned and @error is set to 1 or 2. When @error = 2 then @extended holds the last Windows error
; Author ........: funkey 2014.08.11th
; Modified.......:
; Remarks .......: Usually, the only user who can decrypt the data is a user with the same logon credentials as the user who encrypted the data.
;                  In addition, the encryption and decryption must be done on the same computer.
; Related .......: _CryptProtectData
; Link ..........: http://msdn.microsoft.com/en-us/library/aa380882(v=vs.85).aspx
; Example .......: Yes
; ===============================================================================================================================
Func _CryptUnprotectData($bData, ByRef $sDesc, $sPwd = "", $iFlag = 0, $pPrompt = 0)
	Local $aRet, $iError, $tEntropy, $pEntropy = 0
	Local $tDataIn = __DataToBlob($bData)
	$sDesc = ""

	If $sPwd <> "" Then
		$tEntropy = __DataToBlob($sPwd)
		$pEntropy = DllStructGetPtr($tEntropy)
	EndIf

	Local $tDataBuf = DllStructCreate($tagDATA_BLOB)
	Local $tDesc = DllStructCreate("ptr desc")
	Local $pDesc = DllStructGetPtr($tDesc)

	$aRet = DllCall($hDLL_Crypt32, "BOOL", "CryptUnprotectData", "struct*", $tDataIn, "ptr*", $pDesc, "ptr", $pEntropy, "ptr", 0, "ptr", $pPrompt, "DWORD", $iFlag, "struct*", $tDataBuf)
	$iError = @error
	_WinAPI_LocalFree(DllStructGetData($tDataIn, "pbData"))

	If $sPwd <> "" Then _WinAPI_LocalFree(DllStructGetData($tEntropy, "pbData"))
	If $iError Then Return SetError(1, 0, "")
	If $aRet[0] = 0 Then Return SetError(2, _WinAPI_GetLastError(), "")

	Local $tDataOut = DllStructCreate("char data[" & DllStructGetData($tDataBuf, "cbData") & "]", DllStructGetData($tDataBuf, "pbData"))
	Local $sData = DllStructGetData($tDataOut, "data")

	Local $aLen = DllCall("msvcrt.dll", "UINT:cdecl", "wcslen", "ptr", $aRet[2])
	Local $tDescNew = DllStructCreate("wchar desc[" & $aLen[0] + 1 & "]", $aRet[2])
	$sDesc = DllStructGetData($tDescNew, "desc")

	_WinAPI_LocalFree($aRet[2])
	_WinAPI_LocalFree(DllStructGetData($tDataBuf, "pbData"))

	Return $sData
EndFunc   ;==>_CryptUnprotectData


; #INTERNAL_USE_ONLY# ===========================================================================================================
; Name...........: __DataToBlob
; Description ...: Creates a DATA_BLOB structure where the function stores the decrypted data.
; Syntax.........: __DataToBlob($data)
; Parameters ....: $Data        - Data can be binary or string
; Return values .: Returns a filled $DATA_BLOB structure
; Author ........: funkey
; Modified.......:
; Remarks .......: When you have finished using the DATA_BLOB structure, free its pbData member by calling the _WinAPI_LocalFree function.
; Related .......: _CryptProtectData, _CryptUnprotectData
; Link ..........:
; Example .......: Yes
; ===============================================================================================================================
Func __DataToBlob($data)
	;funkey 2014.08.11th
	Local $iLen, $tDataIn, $tData, $aMem
	Local Const $LMEM_ZEROINIT = 0x40
	Select
		Case IsString($data)
			$iLen = StringLen($data)
		Case IsBinary($data)
			$iLen = BinaryLen($data)
		Case Else
			Return SetError(1, 0, 0)
	EndSelect

	$tDataIn = DllStructCreate($tagDATA_BLOB)
	$aMem = DllCall("Kernel32.dll", "handle", "LocalAlloc", "UINT", $LMEM_ZEROINIT, "UINT", $iLen)
	$tData = DllStructCreate("byte[" & $iLen & "]", $aMem[0])

	DllStructSetData($tData, 1, $data)
	DllStructSetData($tDataIn, "cbData", $iLen)
	DllStructSetData($tDataIn, "pbData", DllStructGetPtr($tData))

	Return $tDataIn
EndFunc   ;==>__DataToBlob

; #INTERNAL_USE_ONLY# ===========================================================================================================
; Name...........: __CryptProtect_DllClose
; Description ...: Closes the Dll handle to 'crypt32.dll'
; Syntax.........: __CryptProtect_DllClose()
; Parameters ....:
; Return values .: none
; Author ........: funkey
; Modified.......:
; Remarks .......: Function is called automatically when AutoIt exits
; Related .......: _CryptProtectData, _CryptUnprotectData
; Link ..........:
; Example .......:
; ===============================================================================================================================
Func __CryptProtect_DllClose()
	DllClose($hDLL_Crypt32)
EndFunc
