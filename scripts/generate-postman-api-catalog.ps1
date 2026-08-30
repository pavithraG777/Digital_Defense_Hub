param(
 [string]$RouteLog = "$PSScriptRoot\..\backend-go\storage\logs\route-scan.stdout.log",
 [string]$CollectionOutput = "$PSScriptRoot\..\docs\postman\Cyber-Security-Platform.postman_collection.json",
 [string]$EnvironmentOutput = "$PSScriptRoot\..\docs\postman\Local.postman_environment.json",
 [string]$CatalogOutput = "$PSScriptRoot\..\docs\API_CATALOG_THANGGLISH.md"
)
$ErrorActionPreference='Stop'
$routePattern='\[GIN-debug\]\s+(GET|POST|PUT|PATCH|DELETE)\s+(/\S+)\s+-->\s+(\S+)'
$routes=@(Get-Content -LiteralPath $RouteLog|ForEach-Object{if($_ -match $routePattern){[pscustomobject]@{method=$matches[1];path=$matches[2];handler=$matches[3]}}}|Sort-Object path,method -Unique)
if($routes.Count-eq 0){throw 'No Gin routes found'}
$backendInternal=(Resolve-Path "$PSScriptRoot\..\backend-go\internal").Path
$contractCache=@{}
function Handler-Contract($handler){
 if($contractCache.ContainsKey($handler)){return $contractCache[$handler]}
 $contract='none'
 if($handler -match '/internal/([^/]+)\.'){
  $package=$matches[1];$files=Get-ChildItem -LiteralPath (Join-Path $backendInternal $package) -Filter '*.go' -File -ErrorAction SilentlyContinue|Where-Object{$_.Name-notmatch '_test\.go$'}
  $method='';if($handler -match '\)\.([A-Za-z0-9_]+)-fm$'){$method=$matches[1]}
  foreach($file in $files){
   $source=Get-Content -LiteralPath $file.FullName -Raw
   $segment=$source
   if($method -and $source -match "(?s)func\s*\([^)]*\)\s*$method\s*\([^)]*\).*?(?=\nfunc\s|\z)"){$segment=$matches[0]}
   elseif($method){continue}
   if($segment -match 'FormFile\s*\('){$contract='multipart';break}
   if($segment -match '(ShouldBindJSON|BindJSON)\s*\('){$contract='json';break}
  }
 }
 $contractCache[$handler]=$contract;return $contract
}

function Sample-Body($method,$path,$handler){
 if($method -in 'GET','DELETE'){return $null}
 switch -Regex ($path){
  '/auth/login$' {return @{official_email='admin@digitaldefensehub.local';password='change-me';device_fingerprint='postman-device'}}
  '/auth/mfa/verify$' {return @{challenge_id='{{challenge_id}}';email_code='123456';totp_code='123456';recovery_code=''}}
  '/auth/refresh$' {return @{refresh_token='{{refresh_token}}'}}
  '/auth/revoke-refresh-token$' {return @{refresh_token='{{refresh_token}}'}}
  '/security-events$' {return @{event_id='{{event_id}}';schema_version=1;event_type='PROCESS_START';source='postman';occurred_at='2026-08-14T12:00:00Z';entity=@{type='PROCESS';id='powershell.exe'};payload=@{command_line='powershell.exe -NoProfile'}}}
  '/command-analysis/analyze$' {return @{command='powershell.exe -EncodedCommand VwByAGkAdABlAC0ASABvAHMAdAAgAHQAZQBzAHQA';language='POWERSHELL';artifact_uri='evidence://postman/script.ps1';run_dynamic=$false}}
  '/threat-intelligence/enrich/provider$' {return @{type='IP';value='8.8.8.8';idempotency_key='postman-ti-001'}}
  '/threat-intelligence/enrich$' {return @{type='IP';value='8.8.8.8';sources=@(@{name='manual-lab';reputation=25;confidence=80;tags=@('dns')})}}
  '/threat-intelligence/indicators/.+/review$' {return @{status='ACTIVE'}}
  '/attribution/observations$' {return @{provider='lab-provider';source_reference='case-001';indicator_type='IP';indicator_value='8.8.8.8';asn='AS15169';country_code='US';organization='Example Network';association='unknown';reputation=25;provider_confidence=80;last_seen_at='2026-08-14T12:00:00Z';expires_at='2026-09-14T12:00:00Z';raw=@{source='postman'}}}
  '/attribution/leads$' {return @{indicator_type='IP';indicator_value='8.8.8.8'}}
  '/attribution/leads/.+/disposition$' {return @{disposition='INCONCLUSIVE';note='Postman validation'}}
  '/recovery/plans$' {return @{name='Postman recovery plan';reason='Controlled validation';idempotency_key='postman-recovery-plan-001';actions=@(@{type='ISOLATE_DEVICE';target_type='DEVICE';target_id='{{device_id}}';parameters=@{reason='containment'}})}}
  '/recovery/plans/.+/execute$' {return @{idempotency_key='postman-recovery-execution-001'}}
  '/recovery/emergency-stop$' {return @{reason='Postman emergency-stop validation'}}
  '/recovery/emergency-stop/clear$' {return @{reason='Postman clear validation'}}
  '/evidence-vault/manifests$' {return @{evidence_id='{{evidence_id}}';case_id='{{case_id}}';object_uri='evidence://postman/object';object_version_id='v1';evidence_sha256=('a'*64);encryption_key_id='dev-key';collected_at='2026-08-14T12:00:00Z'}}
  '/verify$' {return @{observed_sha256=('a'*64)}}
  '/credential-abuse' {return @{user_id='{{user_id}}';credential_type='PASSWORD';source_ip='10.0.0.10';device_id='{{device_id}}';occurred_at='2026-08-14T12:00:00Z';signals=@('HONEY_CREDENTIAL','ABNORMAL_SOURCE')}}
  '/lateral-movement' {return @{source_device_id='{{device_id}}';destination_device_id='{{destination_device_id}}';user_id='{{user_id}}';protocol='SMB';occurred_at='2026-08-14T12:00:00Z'}}
  '/privilege-escalation' {return @{user_id='{{user_id}}';from_privilege='USER';to_privilege='ADMIN';process='powershell.exe';occurred_at='2026-08-14T12:00:00Z'}}
  default {
   return @{_documentation='Payload varies by handler DTO; API catalog handler column points to exact source. Replace this object before positive test.'}
  }
 }
}
function Is-Public($path){return $path -match '^/api/v1/(health|ready|metrics|auth/|organizations/register|_dbg/)'}
function Group-Name($path){$parts=$path.Trim('/')-split '/';if($parts.Count-gt 2){return $parts[2]}return 'root'}
function Postman-Path($path){return [regex]::Replace($path,':([A-Za-z0-9_]+)','{{$1}}')}
$groups=@{}
$variables=[Collections.Generic.HashSet[string]]::new()
foreach($route in $routes){
 $group=Group-Name $route.path;if(-not$groups.ContainsKey($group)){$groups[$group]=[Collections.Generic.List[object]]::new()}
 $postmanPath=Postman-Path $route.path
 [regex]::Matches($route.path,':([A-Za-z0-9_]+)')|ForEach-Object{[void]$variables.Add($_.Groups[1].Value)}
 $headers=@(@{key='Content-Type';value='application/json';type='text'})
 if(-not(Is-Public $route.path)){$headers+=@{key='Authorization';value='Bearer {{access_token}}';type='text'}}
 if($route.path -eq '/api/v1/metrics'){$headers+=@{key='Authorization';value='Bearer {{metrics_token}}';type='text'}}
 $request=[ordered]@{method=$route.method;header=$headers;url="{{base_url}}$postmanPath";description="Runtime handler: $($route.handler). Success response envelope usually: success/message/data; validation/auth errors use success/message/error."}
 $body=Sample-Body $route.method $route.path $route.handler;if($null-ne$body){$request.body=@{mode='raw';raw=($body|ConvertTo-Json -Depth 12);options=@{raw=@{language='json'}}}}
 $tests=@("pm.test('Response is not a server crash', function () { pm.expect(pm.response.code).to.be.below(500); });","pm.test('Response is JSON when body exists', function () { if (pm.response.text()) { pm.response.to.be.json; } });")
 if($route.path -eq '/api/v1/auth/login'){$tests+=@("try { const r=pm.response.json(); const d=r.data||r; if(d.access_token) pm.environment.set('access_token',d.access_token); if(d.refresh_token) pm.environment.set('refresh_token',d.refresh_token); if(d.challenge_id) pm.environment.set('challenge_id',d.challenge_id); } catch(e) {}")}
 $item=[ordered]@{name="$($route.method) $($route.path)";request=$request;event=@(@{listen='test';script=@{type='text/javascript';exec=$tests}})}
 $groups[$group].Add($item)
}
$folders=@($groups.Keys|Sort-Object|ForEach-Object{@{name=$_;item=@($groups[$_])}})
$collection=[ordered]@{info=@{_postman_id=[guid]::NewGuid().ToString();name="Cyber Security Platform - $($routes.Count) Runtime APIs";schema='https://schema.getpostman.com/json/collection/v2.1.0/collection.json';description='Generated from Gin runtime route table. Generic placeholder payloads are explicitly marked and must be replaced using handler DTO source.'};item=$folders}
$envValues=@(@{key='base_url';value='http://127.0.0.1:8080';enabled=$true},@{key='access_token';value='';enabled=$true},@{key='refresh_token';value='';enabled=$true},@{key='challenge_id';value='';enabled=$true},@{key='metrics_token';value='';enabled=$true},@{key='event_id';value=[guid]::NewGuid().ToString();enabled=$true})
foreach($name in $variables|Sort-Object){$envValues+=@{key=$name;value=[guid]::NewGuid().ToString();enabled=$true}}
$environment=@{id=[guid]::NewGuid().ToString();name='Cyber Security Platform - Local';values=$envValues;_postman_variable_scope='environment';_postman_exported_at=(Get-Date).ToUniversalTime().ToString('o');_postman_exported_using='Codex API catalog generator'}
$outDir=Split-Path $CollectionOutput -Parent;if(-not(Test-Path $outDir)){New-Item -ItemType Directory -Path $outDir|Out-Null}
$collection|ConvertTo-Json -Depth 30|Set-Content -LiteralPath $CollectionOutput -Encoding utf8
$environment|ConvertTo-Json -Depth 10|Set-Content -LiteralPath $EnvironmentOutput -Encoding utf8

$catalog=[Collections.Generic.List[string]]::new();$catalog.Add('# Complete Runtime API Catalog — Thanglish');$catalog.Add('');$catalog.Add("Runtime endpoint count: **$($routes.Count)**.");$catalog.Add('');$catalog.Add('| # | Method | Path | Auth | Payload | Handler / exact contract source |');$catalog.Add('|---:|---|---|---|---|---|');$i=0
foreach($route in $routes){$i++;$body=Sample-Body $route.method $route.path $route.handler;$payload=if($null-eq$body){'Body illa'}elseif($body.ContainsKey('_documentation')){'DTO/multipart-specific; handler source follow pannanum'}else{'Sample body collection-la ready'};$auth=if(Is-Public $route.path){'Public/flow-specific'}elseif($route.path-eq'/api/v1/metrics'){'Metrics token'}else{'Bearer JWT + RBAC'};$catalog.Add("| $i | $($route.method) | ``$($route.path)`` | $auth | $payload | ``$($route.handler)`` |")}
$catalog|Set-Content -LiteralPath $CatalogOutput -Encoding utf8
Write-Host "Generated $($routes.Count) API requests, environment, and catalog."
