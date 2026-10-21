$ErrorActionPreference = 'Stop'
$sw = 'C:\anyWorkspace\nx\Nxus\switch'
Set-Location $sw
$bash = 'C:\devkitPro\msys2\usr\bin\bash.exe'
$orig = Get-Content nxus.json -Raw

function Set-Flags([string]$allow, [string]$force, [string]$prod) {
    $j = $orig
    $j = $j -replace '"allow_debug":\s*(true|false)', ('"allow_debug": ' + $allow)
    $j = $j -replace '"force_debug":\s*(true|false)', ('"force_debug": ' + $force)
    $j = $j -replace '"force_debug_prod":\s*(true|false)', ('"force_debug_prod": ' + $prod)
    Set-Content -Path nxus.json -Value $j -Encoding UTF8 -NoNewline
}

$variants = @(
    @{ name = 'allow'; a = 'true';  f = 'false'; p = 'false' },
    @{ name = 'force'; a = 'false'; f = 'true';  p = 'false' },
    @{ name = 'prod';  a = 'false'; f = 'false'; p = 'true'  },
    @{ name = 'none';  a = 'false'; f = 'false'; p = 'false' }
)

foreach ($v in $variants) {
    Set-Flags $v.a $v.f $v.p
    & $bash -lc "cd /c/anyWorkspace/nx/Nxus/switch && rm -f nxus.npdm && make 2>&1 | tail -2" | Out-Null
    if (Test-Path nxus.npdm) {
        Copy-Item nxus.npdm ("npdm_" + $v.name + ".bin") -Force
        "variant $($v.name): npdm ok ($((Get-Item nxus.npdm).Length) bytes)"
    } else { "variant $($v.name): FAILED" }
}

Set-Content -Path nxus.json -Value $orig -Encoding UTF8 -NoNewline

$names = @('none','allow','force','prod')
$bytes = @{}
foreach ($n in $names) { $bytes[$n] = [System.IO.File]::ReadAllBytes((Join-Path $sw ("npdm_" + $n + ".bin"))) }
"npdm size = $($bytes['none'].Length)"
for ($i = 0; $i -lt $bytes['none'].Length; $i++) {
    $vals = @()
    foreach ($n in $names) { $vals += $bytes[$n][$i] }
    if ($vals[0] -ne $vals[1] -or $vals[0] -ne $vals[2] -or $vals[0] -ne $vals[3]) {
        "offset 0x{0:X4}: none=0x{1:X2} allow=0x{2:X2} force=0x{3:X2} prod=0x{4:X2}" -f $i, $vals[0], $vals[1], $vals[2], $vals[3]
    }
}
