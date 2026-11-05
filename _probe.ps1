$ErrorActionPreference = 'SilentlyContinue'
$out = @()
$out += "=== cargo/rustc processes ==="
Get-CimInstance Win32_Process | Where-Object { $_.Name -match '^(cargo|rustc|kaspa)' } | ForEach-Object {
    $out += ("{0} pid={1} : {2}" -f $_.Name, $_.ProcessId, $_.CommandLine)
}
$out += "=== lock files ==="
Get-ChildItem -Path .\target -Filter '.cargo-lock' -Recurse -Force | ForEach-Object { $out += $_.FullName }
$out += "=== files ==="
Get-ChildItem -Path . -File | Where-Object { $_.Name -match '^(cb-test\.log|cb-diff\.txt|procs\.txt)$' } | ForEach-Object { $out += ("{0} size={1}" -f $_.Name, $_.Length) }
$out | Set-Content -Path .\_probe.out -Encoding utf8
