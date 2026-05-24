# Genera Informe-Practica-OSINT.pdf: índice + cada apartado (h2) en página nueva.
$ErrorActionPreference = "Stop"
$Root = Split-Path $PSScriptRoot -Parent
Set-Location $Root

$MdIn = "Informe-Practica-OSINT.md"
$MdTmp = "_build\Informe-Practica-OSINT-local.md"
$HtmlOut = "_build\Informe-Practica-OSINT.html"
$PdfOut = "Informe-Practica-OSINT.pdf"
$Css = Join-Path $PSScriptRoot "informe-print.css"

New-Item -ItemType Directory -Force -Path "_build" | Out-Null

$content = Get-Content -Path $MdIn -Raw -Encoding UTF8
$prefix = "https://raw.githubusercontent.com/alejandroquinonesgamez/GEE_OSINT/main/"
$content = $content -replace [regex]::Escape($prefix), ""
$content = [System.Uri]::UnescapeDataString($content)
$content | Set-Content -Path $MdTmp -Encoding UTF8

$pandoc = "$env:LOCALAPPDATA\Pandoc\pandoc.exe"
if (-not (Test-Path $pandoc)) {
    $cmd = Get-Command pandoc -ErrorAction SilentlyContinue
    if ($cmd) { $pandoc = $cmd.Source } else { throw "pandoc no encontrado. Instale: winget install JohnMacFarlane.Pandoc" }
}

# Indice: tabla en la seccion Introduccion del .md (evita TOC de Pandoc entre titulo e Intro)
& $pandoc $MdTmp -o $HtmlOut `
    --standalone `
    --embed-resources `
    --resource-path="." `
    -c $Css `
    -V lang=es `
    --metadata title="Reconocimiento DNS de una empresa - Grupo GEE"

$edge = "${env:ProgramFiles(x86)}\Microsoft\Edge\Application\msedge.exe"
if (-not (Test-Path $edge)) { $edge = "$env:ProgramFiles\Microsoft\Edge\Application\msedge.exe" }
if (-not (Test-Path $edge)) { throw "Microsoft Edge no encontrado" }

$htmlPath = (Resolve-Path $HtmlOut).Path
$pdfFull = Join-Path $Root $PdfOut
$uri = [System.Uri]::new($htmlPath).AbsoluteUri

$pdfTmp = Join-Path $Root "_build\$PdfOut"
if (Test-Path $pdfTmp) { Remove-Item $pdfTmp -Force }

Start-Process -FilePath $edge -ArgumentList @(
    "--headless", "--disable-gpu", "--no-pdf-header-footer",
    "--print-to-pdf=`"$pdfTmp`"", $uri
) -Wait -NoNewWindow | Out-Null

Start-Sleep -Seconds 3
if (-not (Test-Path $pdfTmp)) { throw "No se generó el PDF intermedio" }

try {
    if (Test-Path $pdfFull) { Remove-Item $pdfFull -Force }
    Move-Item -Path $pdfTmp -Destination $pdfFull -Force
} catch {
    Write-Host "AVISO: cierra el PDF si esta abierto en el visor. Salida generada en:"
    Write-Host "       $pdfTmp"
    if (-not (Test-Path $pdfFull)) {
        Copy-Item -Path $pdfTmp -Destination $pdfFull -Force -ErrorAction SilentlyContinue
    }
}

$mb = [math]::Round((Get-Item $pdfFull).Length / 1MB, 2)
Write-Host "PDF generado: $pdfFull ($mb MB)"
Write-Host "  - Indice: tabla en Introduccion del informe"
Write-Host "  - Apartados 1-8: nueva pagina (sin hoja en blanco entre ellos)"
