$ErrorActionPreference = 'Stop'
Set-Location -LiteralPath $PSScriptRoot
python -m PyInstaller --noconfirm --clean --windowed --onedir --name PBAssetTool --add-data "assets;assets" --collect-all unicorn --collect-all capstone --hidden-import convert_rm5 --hidden-import rm5_native --hidden-import rm5_runtime --exclude-module scipy --exclude-module matplotlib --exclude-module pandas --exclude-module pytest --exclude-module IPython app.py
if ($LASTEXITCODE -ne 0) { throw 'Build failed' }
Copy-Item -LiteralPath (Join-Path $PSScriptRoot '使い方.txt') -Destination (Join-Path $PSScriptRoot 'dist\PBAssetTool\使い方.txt')
Copy-Item -LiteralPath (Join-Path $PSScriptRoot 'THIRD_PARTY.txt') -Destination (Join-Path $PSScriptRoot 'dist\PBAssetTool\THIRD_PARTY.txt')

python -m PyInstaller --noconfirm --clean --console --onedir --name PBVideoWorker --collect-all unicorn --collect-all capstone --exclude-module scipy --exclude-module matplotlib --exclude-module pandas --exclude-module pytest --exclude-module IPython video_worker.py
if ($LASTEXITCODE -ne 0) { throw 'Video worker build failed' }
python prepare_worker.py
if ($LASTEXITCODE -ne 0) { throw 'Worker preparation failed' }
Copy-Item -LiteralPath 'dist\PBVideoWorker\PBVideoWorker.exe' -Destination 'dist\PBAssetTool\PBVideoWorker.exe'
Copy-Item -Path 'dist\PBVideoWorker\_internal\*' -Destination 'dist\PBAssetTool\_internal' -Recurse -Force
