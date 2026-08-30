param(
    [string]$RepositoryRoot = (Split-Path -Parent $PSScriptRoot),
    [string]$OutputFile = (Join-Path (Split-Path -Parent $PSScriptRoot) 'docs\PROJECT_FILE_INVENTORY_THANGGLISH.md')
)
$ErrorActionPreference = 'Stop'
$root = (Resolve-Path -LiteralPath $RepositoryRoot).Path
$excluded = @('\.git\','\.venv\','\.codex\','\.agents\','\node_modules\','\__pycache__\','\.gocache\','\.pytest_cache\','\backend-go\bin\','\backend-go\storage\')
$files = Get-ChildItem -LiteralPath $root -Recurse -File | Where-Object {
    $path = $_.FullName
    $path -ne $OutputFile -and -not ($excluded | Where-Object { $path -like "*$_*" })
} | Sort-Object FullName

function Get-Purpose([string]$relative, [string]$name, [string]$extension) {
    $lower = $name.ToLowerInvariant()
    if ($lower -match '_test\.(go|py)$|\.test\.(ts|tsx)$') { return 'Automated test: corresponding implementation behavior/regression verify pannum.' }
    if ($lower -eq 'module.go') { return 'Module facade: routes/handler wiring அல்லது compact feature API implementation.' }
    if ($lower -eq 'routes.go') { return 'HTTP routes define செய்து middleware/handler-க்கு connect pannum.' }
    if ($lower -match 'handler') { return 'HTTP request validation, auth context, response mapping handle pannum.' }
    if ($lower -match 'repository') { return 'PostgreSQL persistence/query layer; tenant-scoped data access pannum.' }
    if ($lower -match 'service') { return 'Business rules/workflow orchestration layer.' }
    if ($lower -match 'worker') { return 'Background queue/poll/retry processing worker.' }
    if ($lower -match 'dto|schema') { return 'Request/response/data-contract schema and validation definitions.' }
    if ($lower -match 'model|domain') { return 'Domain entity/state representation.' }
    if ($lower -match 'config|\.env') { return 'Runtime/build configuration contract; secrets values contain panna koodathu.' }
    if ($lower -match 'middleware') { return 'Cross-cutting HTTP security/auth/request processing.' }
    if ($lower -match 'migration|^\d+_.*\.sql$|seed') { return 'Database schema/data migration; ordered deployment lifecycle-oda connect aagum.' }
    if ($lower -match 'dockerfile|docker-compose') { return 'Containerized runtime/test environment definition.' }
    if ($lower -match 'readme|\.md$') { return 'Architecture/setup/operations documentation.' }
    if ($lower -match 'package(-lock)?\.json|go\.mod|go\.sum|requirements\.txt') { return 'Dependency manifest/lock file; reproducible build-க்கு use aagum.' }
    if ($lower -match 'vite|tsconfig') { return 'Frontend TypeScript/Vite build configuration.' }
    if ($extension -in '.tsx','.ts') { return 'React/TypeScript UI, API client, navigation அல்லது type definition.' }
    if ($extension -eq '.py') { return 'Python AI/ML analysis, scoring, training அல்லது API runtime code.' }
    if ($extension -eq '.go') { return 'Go backend application/business/infrastructure source code.' }
    if ($extension -eq '.ps1') { return 'Windows operations, readiness, recovery அல்லது automation script.' }
    if ($extension -eq '.sql') { return 'PostgreSQL schema/seed script.' }
    if ($extension -in '.onnx','.data','.xml') { return 'ML inference model/model-data/computer-vision classifier asset.' }
    if ($extension -in '.jpg','.jpeg','.png') { return 'Test/training/sample image asset.' }
    if ($extension -in '.json','.yaml','.yml') { return 'Machine-readable configuration, dataset manifest, or CI definition.' }
    return 'Project source/support asset; exact consumer path/name context-la documented.'
}

function Get-Connection([string]$relative) {
    $parts = $relative -split '[\\/]'
    if ($relative -like 'backend-go\internal\*') {
        $module = if ($parts.Count -gt 2) { $parts[2] } else { 'backend' }
        return "backend-go/internal/$module package -> router/API or another backend service -> PostgreSQL/external adapter as applicable."
    }
    if ($relative -like 'backend-go\cmd\api\*') { return 'Main API entrypoint -> config/database/router -> workers and HTTP server.' }
    if ($relative -like 'backend-go\cmd\migrate\*') { return 'Migration CLI -> .env config -> PostgreSQL -> scripts/migrations/seed.' }
    if ($relative -like 'backend-go\cmd\dev-security-config\*') { return 'Development setup CLI -> backend-go/.env -> metrics/evidence runtime.' }
    if ($relative -like 'frontend-react\src\pages\*') { return 'React router/App -> page -> shared API client -> Go /api/v1 endpoints.' }
    if ($relative -like 'frontend-react\src\components\*') { return 'React pages -> shared layout/component.' }
    if ($relative -like 'frontend-react\src\lib\*') { return 'Frontend pages -> shared API/navigation/module metadata utilities.' }
    if ($relative -like 'ai-engine\app\*') { return 'FastAPI main/routes -> analyzer/scoring/model runner -> model assets; Go backend calls engine over authenticated HTTP.' }
    if ($relative -like 'ai-engine\models\*') { return 'Python media model runner -> ONNX/OpenCV runtime inference.' }
    if ($relative -like 'scripts\migrations\*') { return 'Go/PowerShell migrator -> PostgreSQL schema used by backend repositories/workers.' }
    if ($relative -like 'scripts\*') { return 'Operator/administrator -> OS or database/API operational workflow.' }
    if ($relative -like '.github\workflows\*') { return 'GitHub event -> build/test/vet/race/vulnerability/migration CI gates.' }
    if ($relative -like 'datasets\*') { return 'Training pipeline/tests -> dataset manifest and labeled media.' }
    if ($relative -like 'docs\*') { return 'Developers/operators/readiness process; runtime dependency illa.' }
    return 'Repository-level build, documentation, database bootstrap, or workspace coordination.'
}

$lines = [Collections.Generic.List[string]]::new()
$lines.Add('# Complete Project File Inventory — Thanglish')
$lines.Add('')
$lines.Add("Generated at: $((Get-Date).ToUniversalTime().ToString('yyyy-MM-dd HH:mm:ss')) UTC")
$lines.Add('')
$lines.Add("Total inventoried files: **$($files.Count)**. Git/cache/runtime storage and node_modules excluded.")
$lines.Add('')
$lines.Add('| File | Purpose | Connect aagura flow |')
$lines.Add('|---|---|---|')
foreach ($file in $files) {
    $relative = $file.FullName.Substring($root.Length + 1)
    $safePath = $relative.Replace('|','\|')
    $purpose = Get-Purpose $relative $file.Name $file.Extension
    $connection = Get-Connection $relative
    $lines.Add("| ``$safePath`` | $purpose | $connection |")
}
$directory = Split-Path -Parent $OutputFile
if (-not (Test-Path -LiteralPath $directory)) { New-Item -ItemType Directory -Path $directory | Out-Null }
$lines | Set-Content -LiteralPath $OutputFile -Encoding utf8
Write-Host "Generated $OutputFile with $($files.Count) file entries."
