#include-once

Func _WinAPI_LZNTDecompress(ByRef $tInput, ByRef $tOutput, $iBufferSize)
	$tOutput = DllStructCreate("byte[" & $iBufferSize & "]")
	If @error Then Return SetError(1, 0, 0)
	Local $aRet = DllCall("ntdll.dll", "uint", "RtlDecompressBuffer", "ushort", 0x0002, "struct*", $tOutput, "ulong", $iBufferSize, "struct*", $tInput, "ulong", DllStructGetSize($tInput), "ulong*", 0)
	If @error Then Return SetError(2, 0, 0)
	If $aRet[0] Then Return SetError(3, $aRet[0], 0)
	Return $aRet[6]
EndFunc   ;==>_WinAPI_LZNTDecompress

Func _LzntDecompress($bBinary) ; by trancexx
    $bBinary=Binary($bBinary)
    Local $tInput=DllStructCreate('byte['&BinaryLen($bBinary)&']')
    DllStructSetData($tInput,1,$bBinary)
    Local $tBuffer=DllStructCreate('byte['&16*DllStructGetSize($tInput)&']')
    Local $a_Call=DllCall('ntdll.dll','int','RtlDecompressBuffer','ushort',2,'ptr',DllStructGetPtr($tBuffer),'dword',DllStructGetSize($tBuffer),'ptr',DllStructGetPtr($tInput),'dword',DllStructGetSize($tInput),'dword*',0)
    If @error Or $a_Call[0] Then Return SetError(1,0,0)
    Local $tOutput=DllStructCreate('byte['&$a_Call[6]&']',DllStructGetPtr($tBuffer))
    Return SetError(0,0,DllStructGetData($tOutput,1))
EndFunc ;==>_LzntDecompress()
