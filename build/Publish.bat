@echo off

::go to parent folder
cd ..

::create nuget_packages
if not exist nuget_packages (
    md nuget_packages
    echo Created nuget_packages folder.
)

::clear nuget_packages
for /R "nuget_packages" %%s in (*) do (
    del "%%s"
)
echo Cleaned up all nuget packages.
echo.

::get nuget key
set /p key=input key:

::start to package all projects
dotnet pack src/Cosmos.Encryption -c Release -o nuget_packages

for /R "nuget_packages" %%s in (*symbols.nupkg) do (
    del "%%s"
)

echo.
echo.

::set target nuget server url
set source=https://api.nuget.org/v3/index.json

::push nuget packages to server
for /R "nuget_packages" %%s in (*.nupkg) do ( 	
    dotnet nuget push "%%s" -k %key% -s %source% --skip-duplicate
	echo.
)

::get back to build folder
cd build

pause