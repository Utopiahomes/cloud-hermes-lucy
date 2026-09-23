param(
  [string]$PythonExecutable = ".\.venv\Scripts\python.exe",
  [string]$OutputDirectory = ".\dist\aws",
  [string]$ArtifactName = "lucy-security-executors-v1.2.zip",
  [string]$RequirementsLock = "deploy\aws\lambda-requirements.lock",
  [string[]]$Package = @(),
  [switch]$AllowDirtyForLocalTest
)

$ErrorActionPreference = "Stop"
$projectRoot = (Resolve-Path (Join-Path $PSScriptRoot "..\..")).Path
$outputPath = [System.IO.Path]::GetFullPath((Join-Path $projectRoot $OutputDirectory))
if (-not $outputPath.StartsWith($projectRoot + [System.IO.Path]::DirectorySeparatorChar)) {
  throw "Artifact output must stay inside the project directory"
}
$temporaryRoot = Join-Path ([System.IO.Path]::GetTempPath()) ("lucy-executor-" + [guid]::NewGuid())
$staging = Join-Path $temporaryRoot "staging"
if ([System.IO.Path]::GetFileName($ArtifactName) -ne $ArtifactName -or
    -not $ArtifactName.EndsWith(".zip", [System.StringComparison]::OrdinalIgnoreCase)) {
  throw "ArtifactName must be a .zip filename without a directory"
}
$artifact = Join-Path $outputPath $ArtifactName

try {
  $sourceCommit = (& git -C $projectRoot rev-parse HEAD).Trim()
  if ($LASTEXITCODE -ne 0 -or $sourceCommit -notmatch '^[0-9a-f]{40}$') {
    throw "A full source commit is required for the artifact manifest"
  }
  $dirtyPaths = @(& git -C $projectRoot status --porcelain=v1 --untracked-files=all)
  if ($LASTEXITCODE -ne 0) { throw "Unable to verify source-tree cleanliness" }
  $sourceState = "clean"
  if ($dirtyPaths.Count -gt 0) {
    if (-not $AllowDirtyForLocalTest) {
      throw "Release artifacts require a clean committed source tree"
    }
    $sourceState = "dirty-local-test"
  }

  New-Item -ItemType Directory -Path $staging -Force | Out-Null
  New-Item -ItemType Directory -Path $outputPath -Force | Out-Null
  & $PythonExecutable -m pip install `
    --disable-pip-version-check `
    --no-compile `
    --only-binary=:all: `
    --implementation cp `
    --python-version 3.12 `
    --platform manylinux2014_x86_64 `
    --require-hashes `
    --target $staging `
    --requirement (Join-Path $projectRoot $RequirementsLock)
  if ($LASTEXITCODE -ne 0) { throw "Locked Lambda dependency installation failed" }

  & $PythonExecutable (Join-Path $PSScriptRoot "build_executor_artifact.py") `
    --project-root $projectRoot `
    --staging $staging `
    --output $artifact `
    --source-commit $sourceCommit `
    --source-state $sourceState `
    --requirements-lock $RequirementsLock `
    @($Package | ForEach-Object { "--package"; $_ })
  if ($LASTEXITCODE -ne 0) { throw "Deterministic Lambda packaging failed" }
}
finally {
  if (Test-Path -LiteralPath $temporaryRoot) {
    Remove-Item -LiteralPath $temporaryRoot -Recurse -Force
  }
}
