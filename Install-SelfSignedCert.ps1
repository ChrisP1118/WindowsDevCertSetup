<#
.SYNOPSIS
Creates a new self-signed cert and binds the cert.

.DESCRIPTION
Creates a new self-signed cert (with subjectAltName), and binds the cert to a range of localhost ports.

.PARAMETER DomainName
The domain (and subject) for the cert. The default value is "localhost".

.PARAMETER StartPort
The first port to bind this cert to. The default value is "44300".

.PARAMETER EndPort
The last port to bind this cert to. The default value is "44399".

.PARAMETER Years
The number of years the cert should be issued for. The default value is "5".

.EXAMPLE
Setup-LocalhostCert

Creates and installs a new self-signed cert for localhost and binds it to ports 44300-44399.

.EXAMPLE
Setup-LocalhostCert -DomainName "client.com" -StartPort 44300 -EndPort 44300

Creates and installs a new self-signed cert for "client.com" and binds it to port 44300.

#>

[CmdletBinding()]
Param(
    [string] $DomainName = 'localhost',
    [int] $StartPort = 44300,
    [int] $EndPort = 44399,
    [int] $Years = 5
)

# Creates the cert and adds it to the Local Machine "Personal" store - this makes it usable for web server use
$cert = New-SelfSignedCertificate -DnsName $DomainName, $DomainName -CertStoreLocation "cert:\LocalMachine\My" -NotAfter (Get-Date).AddYears($Years)
$thumb = $cert.GetCertHashString()

# Removes any existing bindings
For ($i = $StartPort; $i -le $EndPort; $i++) {
    netsh http delete sslcert ipport=0.0.0.0:$i
}

# Adds new bindings
For ($i = $StartPort; $i -le $EndPort; $i++) {
    # The GUID used here is arbitrary
    netsh http add sslcert ipport=0.0.0.0:$i certhash=$thumb appid=`{214124cd-d05b-4309-9af9-9caa44b2b74a`}
}

# Adds the cert to "Trusted Root" store - this makes web browsers trust the cert
$store = New-Object  -TypeName System.Security.Cryptography.X509Certificates.X509Store  -ArgumentList 'root', 'LocalMachine'
$store.Open([System.Security.Cryptography.X509Certificates.OpenFlags]::ReadWrite)
$store.Add($cert)
$store.Close()