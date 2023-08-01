#include-once

; Base64 - Trancexx
Func _Base64Encode($input)

    $input = Binary($input)

    Local $struct = DllStructCreate("byte[" & BinaryLen($input) & "]")

    DllStructSetData($struct, 1, $input)

    Local $strc = DllStructCreate("int")

    Local $a_Call = DllCall("Crypt32.dll", "int", "CryptBinaryToString", _
            "ptr", DllStructGetPtr($struct), _
            "int", DllStructGetSize($struct), _
            "int", 0x40000001, _
            "ptr", 0, _
            "ptr", DllStructGetPtr($strc))

    If @error Or Not $a_Call[0] Then
        Return SetError(1, 0, "") ; error calculating the length of the buffer needed
    EndIf

    Local $a = DllStructCreate("char[" & DllStructGetData($strc, 1) & "]")

    $a_Call = DllCall("Crypt32.dll", "int", "CryptBinaryToString", _
            "ptr", DllStructGetPtr($struct), _
            "int", DllStructGetSize($struct), _
            "int", 0x40000001, _
            "ptr", DllStructGetPtr($a), _
            "ptr", DllStructGetPtr($strc))

    If @error Or Not $a_Call[0] Then
        Return SetError(2, 0, ""); error encoding
    EndIf

    Return DllStructGetData($a, 1)

EndFunc   ;==>_Base64Encode

Func _Base64Decode($input_string)

    Local $struct = DllStructCreate("int")

    Local $a_Call = DllCall("Crypt32.dll", "int", "CryptStringToBinary", _
            "str", $input_string, _
            "int", 0, _
            "int", 1, _
            "ptr", 0, _
            "ptr", DllStructGetPtr($struct, 1), _
            "ptr", 0, _
            "ptr", 0)

    If @error Or Not $a_Call[0] Then
        Return SetError(1, 0, "") ; error calculating the length of the buffer needed
    EndIf

    Local $a = DllStructCreate("byte[" & DllStructGetData($struct, 1) & "]")

    $a_Call = DllCall("Crypt32.dll", "int", "CryptStringToBinary", _
            "str", $input_string, _
            "int", 0, _
            "int", 1, _
            "ptr", DllStructGetPtr($a), _
            "ptr", DllStructGetPtr($struct, 1), _
            "ptr", 0, _
            "ptr", 0)

    If @error Or Not $a_Call[0] Then
        Return SetError(2, 0, ""); error decoding
    EndIf

    Return DllStructGetData($a, 1)

EndFunc   ;==>_Base64Decode
