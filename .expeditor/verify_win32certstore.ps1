#!/usr/bin/env powershell

#Requires -Version 5


$ErrorActionPreference = "Stop"

Write-Output "--- :ruby: Removing existing Ruby instances"

$rubies = Get-ChildItem -Path "C:\ruby*"
foreach ($ruby in $rubies){
  Remove-Item -LiteralPath $ruby.FullName -Recurse -Force -ErrorAction SilentlyContinue
}
Write-Output "`r"

Write-Output "--- :screwdriver: Installing the latest Chef-Client"
choco install chef-client -y
if (-not $?) { throw "unable to install Chef-Client" }
Write-Output "`r"

Write-Output "--- :chopsticks: Refreshing the build environment to pick up Chef binaries"
refreshenv
$env:Path = [System.Environment]::GetEnvironmentVariable("Path", "Machine") + ";" + [System.Environment]::GetEnvironmentVariable("Path", "User") + ";c:\opscode\chef\embedded\bin"
Write-Output "`r"

Write-Output "--- :building_construction: Correcting a gem build problem, moving header files around"
$filename = "ansidecl.h"
$locale = Get-ChildItem -path c:\opscode -Include $filename -Recurse -ErrorAction Ignore
if ($locale -is [Array]) { $locale = $locale[0] }
Write-Output "Copying ansidecl.h to the correct folder"
$parent_folder = $locale.Directory.Parent.FullName
$child_folder = $parent_folder + "\x86_64-w64-mingw32\include"
Copy-Item $locale.FullName -Destination $child_folder -ErrorAction Continue
Write-Output "`r"

Write-Output "--- :bank: Installing Gems for the Chef-PowerShell Gem"
gem install bundler
gem install libyajl2-gem
gem install chef-powershell
if (-not $?) { throw "unable to install this build"}
Write-Output "`r"

Write-Output "--- :bank: Installing Node via Choco"
choco install nodejs -y
if (-not $?) { throw "unable to install Node"}
Write-Output "`r"

Write-Output "--- :bank: Refreshing the build environment to pick up Node.js binaries"
refreshenv
$env:Path = [System.Environment]::GetEnvironmentVariable("Path", "Machine") + ";" + [System.Environment]::GetEnvironmentVariable("Path", "User") + ";c:\opscode\chef\embedded\bin"
Write-Output "`r"

Write-Output "--- :bank: Installing CSPell via NPM, Getting Ready to SpellCheck the Gem code"
npm install -g cspell
if (-not $?) { throw "unable to install CSpell"}
Write-Output "`r"

Write-Output "--- :building_construction: Setting up Environment Variables for Ruby and Chef PowerShell"
$temp = Get-Location
$gem_path = [string]$temp.path + "\vendor\bundle\ruby\3.0.0"
[Environment]::SetEnvironmentVariable("GEM_PATH", $gem_path)
[Environment]::SetEnvironmentVariable("GEM_ROOT", $gem_path)
[Environment]::SetEnvironmentVariable("BUNDLE_GEMFILE", "$($temp.path)\Gemfile")
Write-Output "`r"

Write-Output "--- :put_litter_in_its_place: Removing any existing Chef PowerShell DLL's since they'll conflict with rspec"
# remove the existing chef.powershell.dll and chef.powershell.wrapper.dll files under embedded\bin
$file = get-command bundle
$parent_folder = Split-Path -Path $file.Source
Write-Output "Removing files from here : $parent_folder"
if (Test-Path $($parent_folder + "\chef.powershell.dll")){
  Remove-item -path $($parent_folder + "\chef.powershell.dll")
  Remove-item -path $($parent_folder + "\chef.powershell.wrapper.dll")
}
Write-Output "`r"

Write-Output "--- :mag: Where are all the Chef PowerShell DLLs located?"
$files = Get-ChildItem -Path c:\ -Name "Chef.PowerShell.Wrapper.dll" -Recurse
foreach($file in $files){
  Write-Output "I found a copy here: $file"
}

Write-Output "--- :point_right: finally verifying the gem code"
bundle update
bundle exec rake spec
if (-not $?) { throw "Bundle Gem failed"}
Write-Output "`r"
