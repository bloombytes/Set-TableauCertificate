[CmdletBinding()]

param (
    [Parameter(Mandatory=$true, HelpMessage="Path to the SSL certificate file (.crt)")]
    [ValidateScript({Test-Path $_ -PathType Leaf})]
    [string]$certificatePath,

    [Parameter(Mandatory=$true, HelpMessage="Path to the SSL key file (.key)")]
    [ValidateScript({Test-Path $_ -PathType Leaf})]
    [string]$keyPath
)

function Get-OpenSSLPath {
    try {
        $tsmPath = Split-Path -Parent (Get-Command -Name tsm).Source
        $TableauPath = Split-Path -Parent $tsmPath
        $apachePath = Get-ChildItem -Path $TableauPath -Recurse -Directory -Filter apache* | Select-Object -First 1
        $OpenSSLPath = Join-Path -Path $apachePath.FullName -ChildPath "bin\openssl.exe"

        if (-not (Test-Path -Path $OpenSSLPath)) {
            throw "OpenSSL binary not found."
        }

        return $OpenSSLPath
    } catch {
        Write-Error -Message "Error locating OpenSSL binary: $_"
        return $null
    }
}

function Compare-Modulus {
    param (
        [string]$certPath,
        [string]$keyPath,
        [string]$OpenSSLPath
    )

    try {
        $certModulus = & $OpenSSLPath x509 -noout -modulus -in $certPath | openssl md5
        $keyModulus = & $OpenSSLPath rsa -noout -modulus -in $keyPath | openssl md5

        return $certModulus -eq $keyModulus
    } catch {
        throw "Error comparing modulus of certificate and key: $_"
    }
}

function Set-Certificate {
    param (
        [string]$certPath,
        [string]$keyPath,
        [string]$OpenSSLPath
    )

    try {
        if (Compare-Modulus -certPath $certPath -keyPath $keyPath -OpenSSLPath $OpenSSLPath) {
            tsm security external-ssl enable --cert-file $certPath --key-file $keyPath
            Write-Output "SSL Certificate set as pending change. Please remember to apply the change."

            # Prompt to apply the certificate changes
            $applyChanges = Read-Host "Do you want to apply the certificate changes now? (y/n)"
            if ($applyChanges -eq "y") {
                Apply-PendingChanges
            }
        } else {
            Write-Error -Message "Certificate and Key do not match."
        }
    } catch {
        Write-Error -Message "Error setting SSL Certificate and Key in Tableau Server: $_"
    }
}

function Apply-PendingChanges {
    try {
        $pendingChanges = tsm pending-changes apply -v
        $pendingChanges | ForEach-Object {
            # Translate and print the Tableau command output
            $output = $_.Line
            if ($output -match "INFO") {
                Write-Host $output -ForegroundColor Green
            } elseif ($output -match "WARN") {
                Write-Host $output -ForegroundColor Yellow
            } elseif ($output -match "ERROR") {
                Write-Host $output -ForegroundColor Red
            } else {
                Write-Host $output
            }
        }
    } catch {
        Write-Error -Message "Error applying pending changes: $_"
    }
}

try {
    $OpenSSLPath = Get-OpenSSLPath
    if ($OpenSSLPath -ne $null) {
        Set-Certificate -certPath $certificatePath -keyPath $keyPath -OpenSSLPath $OpenSSLPath
    } else {
        Write-Error -Message "OpenSSL binary not located, unable to continue."
    }
} catch {
    Write-Error -Message "An error occurred: $_"
}
