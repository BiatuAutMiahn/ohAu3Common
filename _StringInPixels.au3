#cs
	These functions provide pixel-accurate height and width dimensions for a given string. The more commonly-used _GDIPlus_GraphicsMeasureString
built-in UDF is problematic because it returns the width padded by roughly one en-space (for reasons related to the various ways Windows
produces anti-aliased fonts).
	These are AutoIt translations of Pierre Arnaud's C# functions, described in his CodeProject article "Bypass Graphics.MeasureString limitations"
<https://www.codeproject.com/Articles/2118/Bypass-Graphics-MeasureString-limitations>
	The first is an all-purpose version that takes a window handle, string, font family, font size (in points), style, and (optionally) width of the layout column (in pixels) as
parameters.
	The second, more efficient version is intended for applications where GDI+ fonts are already in use, and takes handles to the existing graphics
context, string, font, layout and format as parameters.
	Both functions return a two-row array with the exact width [0] and height [1] of the string (in pixels).
#ce


#include <GDIPlus.au3>
#include <GUIConstantsEx.au3>

; #FUNCTION# ====================================================================================================================
; Name ..........: _StringInPixels
; Description ...: Returns a pixel-accurate height and width for a given string using a given font, style and size.
; Syntax ........: _StringInPixels($hGUI, $sString, $sFontFamily, $fSize, $iStyle[, $iColWidth = 0])
; Parameters ....: $hGUI                - Handle to the window.
;                  $sString             - The string to be measured.
;                  $sFontFamily         - Full name of the font to use.
;                  $fSize               - Font size in points (half-point increments).
;                  $iStyle              - Combination of 0-normal, 1-bold, 2-italic, 4-underline, 8-strikethrough
;                  $iColWidth           - [optional] If word-wrap is desired, column width in pixels
; Return values .: 2-row array. [0] is width in pixels; [1] is height in pixels.
; Author ........: Tim Curran; adapted from Pierre Arnaud's C# function
; Modified ......:
; Remarks .......: This version is longer and less efficient but works for all purposes.
; Related .......: <https://www.codeproject.com/Articles/2118/Bypass-Graphics-MeasureString-limitations>
; Link ..........:
; Example .......: Example-StringInPixels.au3
; ===============================================================================================================================
#include <GDIPlus.au3>
#include <GUIConstantsEx.au3>

Func _StringInPixels($hGUI, $sString, $sFontFamily, $fSize, $iStyle, $iColWidth = 0)
	_GDIPlus_Startup()
	Local $hGraphic = _GDIPlus_GraphicsCreateFromHWND($hGUI) ;Create a graphics object from a window handle

	Local $aRanges[2][2] = [[1]]
	$aRanges[1][0] = 0 ;Measure first char (0-based)
	$aRanges[1][1] = StringLen($sString) ;Region = String length

	Local $hFormat = _GDIPlus_StringFormatCreate()
	Local $hFamily = _GDIPlus_FontFamilyCreate($sFontFamily)
	Local $hFont = _GDIPlus_FontCreate($hFamily, $fSize, $iStyle)

	_GDIPlus_GraphicsSetTextRenderingHint($hGraphic, $GDIP_TEXTRENDERINGHINT_ANTIALIASGRIDFIT)
	_GDIPlus_StringFormatSetMeasurableCharacterRanges($hFormat, $aRanges) ;Set ranges

	Local $aWinClient = WinGetClientSize($hGUI)
	If $iColWidth = 0 Then $iColWidth = $aWinClient[0]
	Local $tLayout = _GDIPlus_RectFCreate(10, 10, $iColWidth, $aWinClient[1])
	Local $aRegions = _GDIPlus_GraphicsMeasureCharacterRanges($hGraphic, $sString, $hFont, $tLayout, $hFormat) ;get array of regions
	Local $aBounds = _GDIPlus_RegionGetBounds($aRegions[1], $hGraphic)
	Local $aWidthHeight[2] = [$aBounds[2], $aBounds[3]]

	; Clean up resources
	_GDIPlus_FontDispose($hFont)
	_GDIPlus_RegionDispose($aRegions[1])
	_GDIPlus_FontFamilyDispose($hFamily)
	_GDIPlus_StringFormatDispose($hFormat)
	_GDIPlus_GraphicsDispose($hGraphic)
	_GDIPlus_Shutdown()

	Return $aWidthHeight
EndFunc   ;==>_StringInPixels


; #FUNCTION# ====================================================================================================================
; Name ..........: _StringInPixels_gdip
; Description ...: Returns a pixel-accurate height and width for a given string using a GDI+ font, layout and format
; Syntax ........: _StringInPixels_gdip($hGraphic, $sString, $hFont, $tLayout, $hFormat)
; Parameters ....: $hGraphic            - Handle to a GDI+ graphics object.
;                  $sString             - The string to be measured.
;                  $hFont               - Handle to a GDI+ font.
;                  $tLayout             - A $tagGDIPRECTF structure that bounds the string.
;                  $hFormat             - Handle to a GDI+ string format.
; Return values .: 2-row array. [0] is width in pixels; [1] is height in pixels.
; Author ........: Tim Curran; adapted from Pierre Arnaud's C# function
; Modified ......:
; Remarks .......: This much more efficient version is for use with GDI+ fonts
; Related .......:
; Link ..........: <https://www.codeproject.com/Articles/2118/Bypass-Graphics-MeasureString-limitations>
; Example .......: Example-StringInPixels.au3
; ===============================================================================================================================
#include <GDIPlus.au3>
#include <GUIConstantsEx.au3>

Func _StringInPixels_gdip($hGraphic, $sString, $hFont, $tLayout, $hFormat)
	Local $aRanges[2][2] = [[1]]
	$aRanges[1][0] = 0 ;Measure first char (0-based)
	$aRanges[1][1] = StringLen($sString) ;Region = String length

	_GDIPlus_GraphicsSetTextRenderingHint($hGraphic, $GDIP_TEXTRENDERINGHINT_CLEARTYPEGRIDFIT)
	_GDIPlus_StringFormatSetMeasurableCharacterRanges($hFormat, $aRanges) ;Set ranges

	Local $aRegions = _GDIPlus_GraphicsMeasureCharacterRanges($hGraphic, $sString, $hFont, $tLayout, $hFormat) ;get array of regions
	Local $aBounds = _GDIPlus_RegionGetBounds($aRegions[1], $hGraphic)
	Local $aWidthHeight[2] = [$aBounds[2], $aBounds[3]]
	_GDIPlus_RegionDispose($aRegions[1])
	Return $aWidthHeight
EndFunc   ;==>_StringInPixels_gdip
