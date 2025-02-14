$files = gci "$env:Temp\T1485" -Recurse -Filter *.t1485 | % { 
	$bytes  = [System.IO.File]::ReadAllBytes($_.FullName)
	for($i=0; $i -lt 1024; $i++){
		try {
			$bytes[$i] = 0xCC
		} catch {
			Write-Host $_
		}
	}
	[System.IO.File]::WriteAllBytes($_.FullName, $bytes)
	$newName = $_.BaseName + ".wgate"
	Rename-Item -Path $_.FullName -NewName $newName
}
