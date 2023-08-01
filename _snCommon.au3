#include-once
#include "_Common.au3"
#include "base64.au3"

Global $__snSoapPassword=BinaryToString(_Base64Decode("<redacted>"))

Func _snGetById($sId,$sMod)
    $SoapMsg = '<soapenv:Envelope xmlns:soapenv="http://schemas.xmlsoap.org/soap/envelope/" xmlns:inc="http://<redacted>.service-now.com/'&$sMod&'">' & @CRLF _
             & '   <soapenv:Header/>' & @CRLF _
             & '   <soapenv:Body>' & @CRLF _
             & '	  <inc:get>' & @CRLF _
             & '		<sys_id>'&$sId&'</sys_id>' & @CRLF _
             & '	  </inc:get>' & @CRLF _
             & '   </soapenv:Body>' & @CRLF _
             & '</soapenv:Envelope>'
    $sQuery=__snSoapQuery($sMod,$SoapMsg)
    $oXml = ObjCreate("Msxml2.DOMDocument.3.0")
    $oXml.loadXML($sQuery)
    $oEnvelope=__snSoapGetNode($oXml,"SOAP-ENV:Envelope")
    $oBody=__snSoapGetNode($oEnvelope,"SOAP-ENV:Body")
    $oRecordsResponse=__snSoapGetNode($oBody,"getResponse")
    Return $oRecordsResponse
EndFunc

Func _snQuery($sQuery,$sMod)
    ;sc_task_list|incident_list|sc_req_item_list|cmdb_ci_printer_list|
    $SoapMsg = '<soapenv:Envelope xmlns:soapenv="http://schemas.xmlsoap.org/soap/envelope/" xmlns:inc="http://<redacted>.service-now.com/'&$sMod&'">' & @CRLF _
                    & '   <soapenv:Header/>' & @CRLF _
                    & '   <soapenv:Body>' & @CRLF _
                    & '	  <inc:getRecords>' & @CRLF _
                    & '		<__encoded_query>'&$sQuery&'</__encoded_query>' & @CRLF _
                    & '	  </inc:getRecords>' & @CRLF _
                    & '   </soapenv:Body>' & @CRLF _
                    & '</soapenv:Envelope>'
    ConsoleWrite("SoapMsg:"&$SoapMsg&@CRLF)
    $sQuery=__snSoapQuery($sMod,$SoapMsg)
    ConsoleWrite("SoapRet:"&$sQuery&@CRLF)
    $oXml = ObjCreate("Msxml2.DOMDocument.3.0")
    $oXml.loadXML($sQuery)
    $oEnvelope=__snSoapGetNode($oXml,"SOAP-ENV:Envelope")
    $oBody=__snSoapGetNode($oEnvelope,"SOAP-ENV:Body")
    $oRecordsResponse=__snSoapGetNode($oBody,"getRecordsResponse")
    $oRecordsResults=__snSoapGetNode($oRecordsResponse,"getRecordsResult")
    Return $oRecordsResults
EndFunc

;
; From OHFunctions.au3
Func __snSoapQuery($Database, $SoapMsg, $Environment="", $User="soap.deskeng")
    $objHTTP = ObjCreate("Microsoft.XMLHTTP")
	$objReturn = ObjCreate("Msxml2.DOMDocument.3.0")
	Select
		Case $Environment = "Cloud"
			$objHTTP.open ("post", "https://<redacted>.service-now.com/"& $Database & ".do?SOAP&displayvalue=true", False, $User, $__snSoapPassword)
		Case $Environment = "Test"
			$objHTTP.open ("post", "https://<redacted>.service-now.com/"& $Database & ".do?SOAP&displayvalue=true", False, $User, $__snSoapPassword)
		Case $Environment = "Live"
			$objHTTP.open ("post", "https://<redacted>.service-now.com/"& $Database & ".do?SOAP&displayvalue=true", False, $User, $__snSoapPassword)
		Case Else
			$objHTTP.open ("post", "https://<redacted>.service-now.com/"& $Database & ".do?SOAP&displayvalue=true", False, $User, $__snSoapPassword)
	EndSelect
		If @error Then Return(-1)
	$objHTTP.setRequestHeader ("Content-Type", "text/xml")
		If @error Then Return(-2)
	$objHTTP.send ($SoapMsg)
		If @error Then Return(-3)
	$strReturn = $objHTTP.responseText
		If @error Then Return(-4)
	$objReturn.loadXML ($strReturn)
		If @error Then Return(-5)
	$Soap = $objReturn.XML
		If @error Then Return(-6)
	Return($Soap)
EndFunc


Func __snSoapGetRecordsArray($vObj,$bIsArray=False)
    Local $iErr=0, $iExt=0
    If IsArray($vObj) Then
        Local $aRet[1][1]
        $aRet[0][0]=0
        For $i=1 To $vObj[0]
            $aRes=__snSoapGetRecordsArray($vObj[$i],True)
            If @error Then
                $iErr=1
                $iExt+=1
                ContinueLoop
            EndIf
            If UBound($aRet,2)<>@extended Then ReDim $aRet[UBound($aRet,1)][@extended]
            $aRet[$aRet[0][0]][0]=UBound($aRet,1)
            ReDim $aRet[$aRet[0][0]+1][@extended]
            For $i=0 To UBound($aRes,1)-1
                $aRet[$aRet[0][0]][$i]=$aRes[$i]
            Next
        Next
        Return SetError($iErr,$iExt,$aRet)
    EndIf
    If Not IsObj($vObj) Then Return SetError(1,0,False)
    $iAttrMax=__snSoapGetAttrCount($vObj)
    Local $aRet[$iAttrMax]
    $iAttr=0
    For $oNode In $vObj.childnodes
        $aRet[$iAttr]=$oNode.text
        $iAttr+=1
    Next
    Return SetError(0,$iAttrMax,$aRet)
EndFunc

Func __snSoapGetAttrCount($vObj)
    If Not IsObj($vObj) Then Return SetError(1,0,False)
    Local $iRet=0
    For $oNode In $vObj.childnodes
        $iRet+=1
    Next
    Return $iRet
EndFunc



Func __snSoapGetAttr($vObj,$sValue="")
    If Not IsObj($vObj) Then Return SetError(1,0,False)
    If $sValue="" Then
        Local $aRet[]=[0]
        For $oNode In $vObj.childnodes
            $aRet[0]=UBound($aRet,1)
            ReDim $aRet[$aRet[0]+1]
            $aRet[$aRet[0]]=$oNode.nodename
        Next
        Return $aRet
    EndIf
    For $oNode In $vObj.childnodes
        If $oNode.nodename<>$sValue Then ContinueLoop
        Return $oNode.text
    Next
EndFunc


Func __snSoapGetNode($oObj,$sName)
    Local $oaRet[1]=[0]
    $iMax=0
    If Not IsObj($oObj) Then Return SetError(1,0,False)
    For $oI In $oObj.childNodes
        If $oI.nodename<>$sName Then ContinueLoop
        $oaRet[0]=UBound($oaRet,1)
        ReDim $oaRet[$oaRet[0]+1]
        $oaRet[$oaRet[0]]=$oI
    Next
    If $oaRet[0]==0 Then
        Return SetError(2,0,False)
    ElseIf $oaRet[0]>1 Then
        Return $oaRet
    Else
        Return $oaRet[1]
    EndIf
EndFunc
