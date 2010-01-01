Sub DoWaitForDevices()
  strComputer = "."
  Set objWMIService = GetObject("winmgmts:\\" & strComputer & "\root\cimv2")
  
  ' WScript.Echo "Waiting until at least one XEN\ device exists"
  
  Set colMonitoredEvents = objWMIService.ExecNotificationQuery _
    ("SELECT * FROM __InstanceOperationEvent WITHIN 5 WHERE " _
        & "Targetinstance ISA 'Win32_PnPEntity'")
  
  Set colItems = objWMIService.ExecQuery _
    ("Select * from Win32_PnPEntity WHERE DeviceID LIKE 'XEN\\%'")
  
  XenExistsFlag = False
  For Each objItem in colItems
    ' WScript.Echo objItem.getObjectText_
    ' WScript.Echo "Devices Exist"
    XenExistsFlag = True
    Exit For
  Next

  Do While Not XenExistsFlag
    Set objEventObject = colMonitoredEvents.NextEvent()
    Set objItem = objEventObject.Targetinstance
    ' WScript.Echo objItem.DeviceID
    If LCase(Left(objItem.DeviceID, 4)) = "xen\" Then
      ' WScript.Echo "New Xen Device Created"   
      XenExistsFlag = True
    End If
  Loop

  ' WScript.Echo "The End"
End Sub
