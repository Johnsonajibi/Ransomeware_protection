#Requires -RunAsAdministrator

<#
.SYNOPSIS
    Build kernel driver using MSBuild (proper WDK method)
#>

$ErrorActionPreference = "Stop"

Write-Host "==========================================================" -ForegroundColor Cyan
Write-Host "   KERNEL DRIVER BUILD (MSBuild)" -ForegroundColor Cyan
Write-Host "==========================================================" -ForegroundColor Cyan
Write-Host ""

$ProjectRoot = Split-Path -Parent $MyInvocation.MyCommand.Path

# Find MSBuild
Write-Host "[1/4] Locating MSBuild..." -ForegroundColor Yellow
$msBuildPath = & "${env:ProgramFiles(x86)}\Microsoft Visual Studio\Installer\vswhere.exe" `
    -latest -products * -requires Microsoft.Component.MSBuild `
    -find MSBuild\**\Bin\MSBuild.exe | Select-Object -First 1

if (-not $msBuildPath -or -not (Test-Path $msBuildPath)) {
    throw "MSBuild not found"
}
Write-Host "    Found: $msBuildPath" -ForegroundColor Green

# Create vcxproj file
Write-Host "[2/4] Creating project file..." -ForegroundColor Yellow
$projFile = Join-Path $ProjectRoot "AntiRansomwareDriver.vcxproj"

@"
<?xml version="1.0" encoding="utf-8"?>
<Project DefaultTargets="Build" ToolsVersion="4.0" xmlns="http://schemas.microsoft.com/developer/msbuild/2003">
  <ItemGroup Label="ProjectConfigurations">
    <ProjectConfiguration Include="Release|x64">
      <Configuration>Release</Configuration>
      <Platform>x64</Platform>
    </ProjectConfiguration>
  </ItemGroup>
  <PropertyGroup Label="Globals">
    <ProjectGuid>{12345678-1234-1234-1234-123456789012}</ProjectGuid>
    <TemplateGuid>{dd38f7fc-d7bd-488b-9242-7d8754cde80d}</TemplateGuid>
    <TargetFrameworkVersion>v4.5</TargetFrameworkVersion>
    <MinimumVisualStudioVersion>12.0</MinimumVisualStudioVersion>
    <Configuration>Release</Configuration>
    <Platform Condition="'`$(Platform)' == ''">x64</Platform>
    <RootNamespace>AntiRansomwareKernel</RootNamespace>
  </PropertyGroup>
  <Import Project="`$(VCTargetsPath)\Microsoft.Cpp.Default.props" />
  <PropertyGroup Condition="'`$(Configuration)|`$(Platform)'=='Release|x64'" Label="Configuration">
    <TargetVersion>Windows10</TargetVersion>
    <UseDebugLibraries>false</UseDebugLibraries>
    <PlatformToolset>WindowsKernelModeDriver10.0</PlatformToolset>
    <ConfigurationType>Driver</ConfigurationType>
    <DriverType>WDM</DriverType>
  </PropertyGroup>
  <Import Project="`$(VCTargetsPath)\Microsoft.Cpp.props" />
  <PropertyGroup>
    <OutDir>`$(ProjectDir)build_production\</OutDir>
    <IntDir>`$(ProjectDir)build_production\obj\</IntDir>
  </PropertyGroup>
  <ItemDefinitionGroup Condition="'`$(Configuration)|`$(Platform)'=='Release|x64'">
    <ClCompile>
      <WppEnabled>false</WppEnabled>
      <WppRecorderEnabled>false</WppRecorderEnabled>
      <WppScanConfigurationData Condition="'%(ClCompile.ScanConfigurationData)' == ''">trace.h</WppScanConfigurationData>
      <WppKernelMode>true</WppKernelMode>
    </ClCompile>
    <Link>
      <AdditionalDependencies>%(AdditionalDependencies);fltMgr.lib</AdditionalDependencies>
    </Link>
    <Inf>
      <TimeStamp>*</TimeStamp>
    </Inf>
  </ItemDefinitionGroup>
  <ItemGroup>
    <FilesToPackage Include="`$(TargetPath)" />
  </ItemGroup>
  <ItemGroup>
    <ClCompile Include="real_kernel_driver.c" />
  </ItemGroup>
  <ItemGroup>
    <Inf Include="anti_ransomware_minifilter.inf" />
  </ItemGroup>
  <Import Project="`$(VCTargetsPath)\Microsoft.Cpp.targets" />
</Project>
"@ | Set-Content $projFile -Encoding UTF8
Write-Host "    Created: $projFile" -ForegroundColor Green

# Build
Write-Host "[3/4] Building driver..." -ForegroundColor Yellow
$buildArgs = @(
    $projFile
    "/p:Configuration=Release"
    "/p:Platform=x64"
    "/t:Build"
    "/m"
    "/v:minimal"
)

& $msBuildPath $buildArgs 2>&1 | Tee-Object -Variable buildOutput | Out-Host

if ($LASTEXITCODE -ne 0) {
    Write-Host "    BUILD FAILED!" -ForegroundColor Red
    throw "Build failed with exit code: $LASTEXITCODE"
}

# Verify
Write-Host "[4/4] Verifying output..." -ForegroundColor Yellow
$sysFile = Join-Path $ProjectRoot "build_production\AntiRansomwareKernel.sys"
if (-not (Test-Path $sysFile)) {
    throw "Driver file not created"
}

$info = Get-Item $sysFile
Write-Host "    Driver: $($info.Name)" -ForegroundColor Green
Write-Host "    Size: $([math]::Round($info.Length / 1KB, 2)) KB" -ForegroundColor Green
Write-Host ""

Write-Host "==========================================================" -ForegroundColor Green
Write-Host "   BUILD SUCCESSFUL!" -ForegroundColor Green
Write-Host "==========================================================" -ForegroundColor Green
Write-Host ""
Write-Host "Next: bcdedit /set testsigning on (reboot required)" -ForegroundColor Yellow
