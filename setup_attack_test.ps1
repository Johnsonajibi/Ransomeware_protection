# Setup fresh test folder for attack simulation
$testPath = 'C:\Users\ajibi\OneDrive\Desktop\TestLogging'
if (Test-Path $testPath) { Remove-Item $testPath -Recurse -Force }
New-Item -ItemType Directory -Path $testPath -Force | Out-Null

# Create sample files
'sample data 1' | Set-Content "$testPath\sample1.txt"
'sample data 2' | Set-Content "$testPath\sample2.txt"

Write-Host "Test folder created: $testPath" -ForegroundColor Green
Get-ChildItem $testPath
