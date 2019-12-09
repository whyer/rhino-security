properties { 
  $base_dir  = resolve-path .
  $build_dir = "$base_dir\build" 
  $buildartifacts_dir = "$build_dir\" 
  $sln_file = "$base_dir\Rhino.Security.sln" 
  $version = "2.0.0.0"
  $humanReadableversion = "2.+"
  $tools_dir = "$base_dir\Tools"
  $release_dir = "$base_dir\Release"
  $uploadCategory = "Rhino-Security"
  $uploader = "..\Uploader\S3Uploader.exe"
  
  # core package
  $NuGetPackageName = "Rhino.Security" #http://trycatchfail.com/blog/post/Building-And-Publishing-NuGet-Packages-With-psake.aspx
  $NuGetPackDir = Join-Path "$build_dir" "nuspecs"
  $NuSpecFileName = "Rhino.Security.nuspec"
  $NuGets = Join-Path $build_dir "nugets"
  
  # windsor package
  $NuGetPackageNameWindsor = "Rhino.Security.Windsor"
  $NuSpecFileNameWindsor = "$NuGetPackageNameWindsor.nuspec"
  $NuSpecFileNameWindsor = "Rhino.Security.Windsor.nuspec"
} 

include .\psake_ext.ps1
	
task default -depends Pack

task Clean { 
  remove-item -force -recurse $buildartifacts_dir -ErrorAction SilentlyContinue 
  remove-item -force -recurse $release_dir -ErrorAction SilentlyContinue 
  # Build-SharedLibs-For-Processor 
} 

task Init -depends Clean { 
	Generate-Assembly-Info `
		-file "$base_dir\Rhino.Security\Properties\AssemblyInfo.cs" `
		-title "Rhino Security $version" `
		-description "Security Library for NHibernate" `
		-company "Hibernating Rhinos" `
		-product "Rhino Security $version" `
		-version $version `
		-copyright "Hibernating Rhinos & Ayende Rahien 2004 - 2009 & Contributors 2010-2011"
		
	Generate-Assembly-Info `
		-file "$base_dir\Rhino.Security.Tests\Properties\AssemblyInfo.cs" `
		-title "Rhino Security Tests $version" `
		-description "Security Library for NHibernate" `
		-company "Hibernating Rhinos" `
		-product "Rhino Security Tests $version" `
		-version $version `
		-clsCompliant "false" `
		-copyright "Hibernating Rhinos & Ayende Rahien 2004 - 2009"
		
	Generate-Assembly-Info `
		-file "$base_dir\Rhino.Security.Windsor\Properties\AssemblyInfo.cs" `
		-title "Rhino Security Windsor $version" `
		-description "Windsor Integation with Rhino Security" `
		-company "Hibernating Rhinos" `
		-product "Rhino Security Windsor $version" `
		-version $version `
		-clsCompliant "false" `
		-copyright "Interfleet Technology AB 2011"
		
	Generate-Assembly-Info `
		-file "$base_dir\Rhino.Security.ActiveRecord\Properties\AssemblyInfo.cs" `
		-title "Rhino Security $version" `
		-description "Security Library for NHibernate" `
		-company "Hibernating Rhinos" `
		-product "Rhino Security $version" `
		-version $version `
		-copyright "Hibernating Rhinos & Ayende Rahien 2004 - 2009"
		
	new-item $release_dir -itemType directory 
	new-item $buildartifacts_dir -itemType directory 
} 

task Compile -depends Init { 
  # & msbuild "$sln_file" "/p:OutDir=$build_dir\\" /p:Configuration=Release
  & "C:\Program Files (x86)\Microsoft Visual Studio\2019\Enterprise\MSBuild\Current\Bin\MSBuild.exe" "$sln_file" "/p:OutDir=$build_dir\\" /p:Configuration=Release
  if ($lastExitCode -ne 0) {
        throw "Error: Failed to execute msbuild"
  }
} 

task Test -depends Compile {
  $old = pwd
  cd $build_dir
  exec "$tools_dir\xunit\xunit.console.x86.exe" "$build_dir\Rhino.Security.Tests.dll"
  cd $old		
}

task Release -depends Test, Pack, Push {
	& $tools_dir\zip.exe -9 -A -j `
		$release_dir\Rhino.Security-$humanReadableversion-Build-$env:ccnetnumericlabel.zip `
		$build_dir\Rhino.Security.dll `
		Rhino.Security\Rhino.Security.xml `
		license.txt `
		"How to use.txt" `
		acknowledgements.txt
	if ($lastExitCode -ne 0) {
        throw "Error: Failed to execute ZIP command"
    }
}

task PreparePack {
    mkdir $NuGetPackDir
    cp $NuSpecFileName $NuGetPackDir
    cp $NuSpecFileNameWindsor $NuGetPackDir
}

task PackCore {
    $s = Join-Path $NuGetPackDir $NuSpecFileName

    $Spec = [xml](get-content $s)
    $Spec.package.metadata.version = ([string]$Spec.package.metadata.version).Replace("{Version}",$Version)
    $Spec.Save($s)

    & ".\$(Join-Path 'tools' 'nuget.exe')" pack -symbols $s
}

task PackWindsor {
    $s = Join-Path $NuGetPackDir $NuSpecFileNameWindsor

    $Spec = [xml](get-content $s)
    $Spec.package.metadata.version = ([string]$Spec.package.metadata.version).Replace("{Version}",$Version)
    $Spec.package.metadata.dependencies.dependency[1].version = ([string]$Spec.package.metadata.dependencies.dependency[1].version).Replace("{Version}",$Version)
    $Spec.Save($s)

    & ".\$(Join-Path 'tools' 'nuget.exe')" pack -symbols $s
}

task Pack -depends Compile, PreparePack, PackCore, PackWindsor {
	mkdir $NuGets
	rm (Join-Path $NuGets "*.nupkg")
	mv "*.nupkg" $NuGets
}

task Push {
	ls $NuGets | % { 
		$p = join-path $NuGets $_
		echo "Pushing from $p"
		& ".\$(Join-Path 'tools' 'nuget.exe')" push "$p" -Source "http://teamcity:8080/" 
	}
}

task Upload -depends Release {
	Write-Host "Starting upload"
	if (Test-Path $uploader) {
		$log = $env:push_msg 
    if($log -eq $null -or $log.Length -eq 0) {
      $log = git log -n 1 --oneline		
    }
		&$uploader "$uploadCategory" "$release_dir\Rhino.Security-$humanReadableversion-Build-$env:ccnetnumericlabel.zip" "$log"
		
		if ($lastExitCode -ne 0) {
      write-host "Failed to upload to S3: $lastExitCode"
			throw "Error: Failed to publish build"
		}
	}
	else {
		Write-Host "could not find upload script $uploadScript, skipping upload"
	}
}
