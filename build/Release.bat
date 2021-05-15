@echo off

echo =======================================================================
echo Cosmos.Security
echo =======================================================================

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

::start to package all projects
dotnet pack src/Cosmos.Security/Cosmos.Security.csproj                           -c Release -o nuget_packages --no-restore
dotnet pack src/Cosmos.Security.Verification/Cosmos.Security.Verification.csproj -c Release -o nuget_packages --no-restore
dotnet pack src/Cosmos.Security.Cryptography/Cosmos.Security.Cryptography.csproj -c Release -o nuget_packages --no-restore

for /R "nuget_packages" %%s in (*symbols.nupkg) do (
    del "%%s"
)

echo.
echo.

::push nuget packages to server
for /R "nuget_packages" %%s in (*.nupkg) do ( 	
    dotnet nuget push "%%s" -s "Release" --skip-duplicate
	echo.
)

::get back to build folder
cd build