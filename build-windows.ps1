# Builds leakcheck on Windows with MinGW-w64 (g++ 11 or later, 64-bit); CMake is not needed.
#
#   .\build-windows.ps1                 build into .\build
#   .\build-windows.ps1 -Test           build, then run the unit tests and the test suites (needs Python 3)
#   .\build-windows.ps1 -Cxx C:\mingw64\bin\g++.exe -Build out
#
# It makes build\leakcheck.exe and build\leakcheck_preload.dll (keep them together),
# plus unit_*.exe and test-programs\ with -Test.
param(
    [string]$Build = "build",
    [string]$Cxx = "g++",
    [int]$Jobs = [Environment]::ProcessorCount,
    [switch]$Test
)
$ErrorActionPreference = "Stop"
$src = $PSScriptRoot
if (-not [IO.Path]::IsPathRooted($Build)) { $Build = Join-Path $src $Build }
$cc = $Cxx -replace "g\+\+(\.exe)?$", "gcc"
$obj = Join-Path $Build "obj"
New-Item -ItemType Directory -Force $obj | Out-Null

function P([string]$rel) { Join-Path $src $rel }
$inc = @("static-engine/include", "dynamic-engine/include", "reporter/include", "shared/include",
         "static-engine/src", "reporter/src") | ForEach-Object { "-I" + (P $_) }
$rtinc = @("dynamic-engine/src/preload", "dynamic-engine/src/win", "shared/include") | ForEach-Object { "-I" + (P $_) }

$core = "static-engine/src/analyzer.cpp", "static-engine/src/lexer.cpp", "static-engine/src/parser.cpp",
        "static-engine/src/malware_scan.cpp", "static-engine/src/malware_table.cpp",
        "static-engine/src/scan.cpp", "static-engine/src/scan_engine.cpp", "static-engine/src/security.cpp",
        "static-engine/src/static_engine.cpp", "reporter/src/compose.cpp", "reporter/src/render_console.cpp", "reporter/src/render_json.cpp",
        "reporter/src/render_sarif.cpp", "reporter/src/report.cpp", "reporter/src/runtime_stream.cpp",
        "reporter/src/suppress.cpp", "reporter/src/symbolize.cpp", "dynamic-engine/src/dynamic_engine_win.cpp"
$runtime = "dynamic-engine/src/preload/behavior.cpp", "dynamic-engine/src/preload/blocks.cpp",
        "dynamic-engine/src/preload/heap.cpp", "dynamic-engine/src/preload/leakscan.cpp",
        "dynamic-engine/src/preload/report.cpp", "dynamic-engine/src/preload/resources.cpp",
        "dynamic-engine/src/preload/stacks.cpp", "dynamic-engine/src/win/behavior_win.cpp",
        "dynamic-engine/src/win/guard_win.cpp", "dynamic-engine/src/win/init_win.cpp",
        "dynamic-engine/src/win/locks_win.cpp", "dynamic-engine/src/win/mem_win.cpp",
        "dynamic-engine/src/win/net_win.cpp", "dynamic-engine/src/win/res_win.cpp",
        "dynamic-engine/src/win/rt_win.cpp", "dynamic-engine/src/win/threads_win.cpp",
        "dynamic-engine/src/win/win_hooks.cpp"

# Runs compiler commands, $Jobs at a time; stops at the first failure and shows its output.
function Run-All($commands) {
    $running = @()
    foreach ($c in $commands) {
        while ($running.Count -ge $Jobs) {
            $done = $running | Where-Object { $_.Proc.HasExited }
            if (-not $done) { Start-Sleep -Milliseconds 100; continue }
            foreach ($d in $done) { Finish $d; $running = $running | Where-Object { $_ -ne $d } }
        }
        $log = [IO.Path]::GetTempFileName()
        $p = Start-Process -FilePath $c.Exe -ArgumentList $c.Args -NoNewWindow -PassThru -RedirectStandardError $log
        $null = $p.Handle # (without this PowerShell 5 loses the exit code of a process it did not wait for)
        $running += [pscustomobject]@{ Proc = $p; Log = $log; Name = $c.Name }
    }
    foreach ($d in $running) { Finish $d }
}
function Finish($d) {
    [void]$d.Proc.WaitForExit()
    if ($d.Proc.ExitCode -ne 0) {
        Get-Content $d.Log | Write-Host
        Remove-Item $d.Log -ErrorAction SilentlyContinue
        throw "failed: $($d.Name)"
    }
    Remove-Item $d.Log -ErrorAction SilentlyContinue
}
function Compile($files, $flags, $prefix) {
    $out = @()
    $cmds = foreach ($f in $files) {
        $o = Join-Path $obj ($prefix + ($f -replace "[/\\]", "_" -replace "\.cpp$", ".o"))
        $out += $o
        [pscustomobject]@{ Name = $f; Exe = $Cxx; Args = @("-std=c++20", "-O2", "-Wall", "-Wextra") + $flags + @("-c", (P $f), "-o", $o) }
    }
    Run-All $cmds
    $out
}
function Link($exe, $inputs) {
    $inputs = @($inputs | Where-Object { $_ -is [string] -and $_ -ne "" })
    & $Cxx @inputs -o $exe
    if ($LASTEXITCODE -ne 0) { throw "link failed: $exe" }
}

Write-Host "compiling the command-line program..."
$coreObjs = Compile $core $inc "core_"
Write-Host "compiling the runtime..."
$rtObjs = Compile $runtime ($rtinc + @("-g", "-fno-exceptions", "-fno-rtti", "-fno-threadsafe-statics", "-fno-omit-frame-pointer")) "rt_"

Link (Join-Path $Build "leakcheck_preload.dll") (@("-shared") + $rtObjs + @("-static-libgcc", "-nostdlib++"))
$mainObj = Compile @("src/main.cpp") $inc "main_"
# the manifest that makes leakcheck.exe's strings UTF-8 (a user name with a dotless i, say)
$windres = $Cxx -replace "g\+\+(\.exe)?$", "windres"
$rcObj = Join-Path $obj "leakcheck_rc.o"
Push-Location (P "src/windows")
& $windres -O coff -i leakcheck.rc -o $rcObj
Pop-Location
if ($LASTEXITCODE -ne 0) { throw "windres failed" }
Link (Join-Path $Build "leakcheck.exe") (@($mainObj) + $coreObjs + @($rcObj, "-static", "-pthread"))
Write-Host "built $(Join-Path $Build 'leakcheck.exe')"

if ($Test) {
    Write-Host "unit tests..."
    foreach ($u in "static", "scan", "reporter") {
        $o = Compile @("tests/unit/${u}_test.cpp") $inc "unit_"
        Link (Join-Path $Build "unit_$u.exe") (@($o) + $coreObjs + @("-static", "-pthread"))
        & (Join-Path $Build "unit_$u.exe") | Select-Object -Last 1
        if ($LASTEXITCODE -ne 0) { throw "unit_$u failed" }
    }
    Write-Host "test programs..."
    $tp = Join-Path $Build "test-programs"
    New-Item -ItemType Directory -Force $tp | Out-Null
    $progs = "no_bugs.c", "leaks.c", "heap_errors.c", "stress.c", "cxx_errors.cpp", "mixed_bugs.cpp",
             "threads.cpp", "win_resources.c", "win_locks.c", "win_locks_cxx.cpp", "win_behavior.c", "win_sockets.c"
    $cmds = foreach ($f in $progs) {
        $name = [IO.Path]::GetFileNameWithoutExtension($f)
        $exe = if ($f.EndsWith(".cpp")) { $Cxx } else { $cc }
        $extra = if ($name -in "win_behavior", "win_sockets") { @("-lws2_32") } else { @() }
        [pscustomobject]@{ Name = $f; Exe = $exe; Args = @("-g", "-O0", "-fno-omit-frame-pointer", "-w", (P "tests/dynamic/programs/$f"), "-o", (Join-Path $tp "$name.exe")) + $extra }
    }
    Run-All $cmds
    # whichever Python 3 starts (the Store's stub and a launcher entry for a missing version do not)
    $py = $null
    foreach ($cand in @(@("py", "-3.12"), @("py", "-3.11"), @("py", "-3.10"), @("py", "-3"), @("python"), @("python3"))) {
        try {
            $extra = @($cand | Select-Object -Skip 1)
            & $cand[0] @extra -c "import sys; sys.exit(0 if sys.version_info[0] == 3 else 1)" 2>$null | Out-Null
            if ($LASTEXITCODE -eq 0) { $py = $cand; break }
        } catch { }
    }
    if (-not $py) { Write-Host "Python 3 not found: the test suites were not run"; return }
    $extra = @($py | Select-Object -Skip 1)
    foreach ($suite in "cli", "static", "scan", "windows") {
        Write-Host "suite $suite..."
        & $py[0] @extra (P "tests/run_tests.py") --build $Build --source $src --suite $suite | Select-Object -Last 3
        if ($LASTEXITCODE -ne 0) { throw "suite $suite failed" }
    }
}
