param(
    [string]$BaseUrl = 'http://127.0.0.1:8080',
    [ValidateRange(1, 10000)][int]$Requests = 100,
    [ValidateRange(1, 100)][int]$Concurrency = 10
)
$ErrorActionPreference = 'Stop'
$failures = [Collections.Generic.List[string]]::new()
function Invoke-Probe([string]$Method, [string]$Path, [string]$Body = '') {
    $arguments = @{ Uri = $BaseUrl + $Path; Method = $Method; SkipHttpErrorCheck = $true; TimeoutSec = 10 }
    if ($Body) { $arguments.Body = $Body; $arguments.ContentType = 'application/json' }
    Invoke-WebRequest @arguments
}
$health = Invoke-Probe GET '/api/v1/health'
if ($health.StatusCode -ne 200) { $failures.Add("health returned $($health.StatusCode)") }
foreach ($pair in @{
    'X-Content-Type-Options' = 'nosniff'
    'X-Frame-Options' = 'DENY'
    'Referrer-Policy' = 'no-referrer'
    'Cache-Control' = 'no-store'
}.GetEnumerator()) {
    if ($health.Headers[$pair.Key] -ne $pair.Value) { $failures.Add("missing or invalid $($pair.Key)") }
}
$protected = Invoke-Probe GET '/api/v1/profile'
if ($protected.StatusCode -ne 401) { $failures.Add("protected route returned $($protected.StatusCode) without a token") }
$malformed = Invoke-Probe POST '/api/v1/auth/login' '{'
if ($malformed.StatusCode -ge 500) { $failures.Add('malformed JSON caused a server error') }
$injection = Invoke-Probe POST '/api/v1/auth/login' '{"email":"'' OR 1=1 --","password":"test-value"}'
if ($injection.StatusCode -ge 500 -or $injection.StatusCode -eq 200) { $failures.Add("injection probe returned $($injection.StatusCode)") }
$metrics = Invoke-Probe GET '/api/v1/metrics'
if ($metrics.StatusCode -notin 401, 403, 503) { $failures.Add("metrics fail-closed probe returned $($metrics.StatusCode)") }
$trace = Invoke-Probe TRACE '/api/v1/health'
if ($trace.StatusCode -lt 400) { $failures.Add('TRACE method was accepted') }
$watch = [Diagnostics.Stopwatch]::StartNew()
$load = 1..$Requests | ForEach-Object -Parallel {
    try {
        $response = Invoke-WebRequest -Uri ($using:BaseUrl + '/api/v1/health') -SkipHttpErrorCheck -TimeoutSec 10
        $response.StatusCode -eq 200
    } catch { $false }
} -ThrottleLimit $Concurrency
$watch.Stop()
$loadFailures = @($load | Where-Object { -not $_ }).Count
if ($loadFailures) { $failures.Add("$loadFailures of $Requests load requests failed") }
$result = [pscustomobject]@{
    Requests = $Requests
    Concurrency = $Concurrency
    Failures = $loadFailures
    DurationMS = $watch.ElapsedMilliseconds
    RequestsPerSecond = [math]::Round($Requests / [math]::Max($watch.Elapsed.TotalSeconds, 0.001), 2)
    SecurityFailures = $failures.Count
}
$result
if ($failures.Count) { $failures | ForEach-Object { Write-Error $_ }; exit 1 }
