Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

# download sst
$sst_file_path = (New-TemporaryFile).FullName
[Console]::Error.WriteLine("Downloading Root CA Certificates from Windows Update... to ${sst_file_path}")
CertUtil.exe -generateSSTFromWU -f "$sst_file_path" 2>&1 | Out-Null

# read sst
[Console]::Error.WriteLine("Reading ${sst_file_path}...")
$collection = New-Object System.Security.Cryptography.X509Certificates.X509Certificate2Collection
$collection.Import("$sst_file_path")
[Console]::Error.WriteLine(" -> $($collection.Count) certificates are imported.")
Remove-Item "$sst_file_path"

 # generate table
$sb = New-Object System.Text.StringBuilder
[void]$sb.AppendLine("// Generated at " + [System.DateTime]::Now.ToString('o') + " // $($collection.Count) certificates are imported.");
foreach ($cert in $collection) {
  $SUBJECT = $cert.Subject
  $SHA1    = $cert.GetCertHashString([System.Security.Cryptography.HashAlgorithmName]::SHA1)
  $MD5     = $cert.GetCertHashString([System.Security.Cryptography.HashAlgorithmName]::MD5)
  [void]$sb.AppendLine("CERT_ENTRY($SHA1,$MD5), // $SUBJECT")
}
$output = $sb.ToString().Replace("`r`n", "`n") 

# output to file or console
If($args.Count -ge 1) {
  [System.IO.File]::WriteAllText($args[0], $output, [System.Text.Encoding]::UTF8)
} else {
  [Console]::Write($output, [System.Text.Encoding]::UTF8)
}
