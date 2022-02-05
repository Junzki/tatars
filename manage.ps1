#!/usr/bin/env pwsh

[CmdletBinding()]
Param(
[Parameter()]
    [String]$Opt,
    $Port
)

$VerbosePreference="continue"

$Env:FLASK_APP="server.app:app"
$Env:FLASK_ENV="development"


function Start-DevServer ($Port) {
    flask run -p $Port
}

switch ($Opt)
{
    "server" {
        Start-DevServer $Port
    }
    "shell" {
        flask shell
    }
}
