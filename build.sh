dotnet build -c Release /p:Version=${VERSION} .
mkdir /tmp/artifacts
for project in $(ls src/*/*.csproj | grep -vi "test"); do \
  dotnet pack -p:PackageVersion=${PACKAGE_VERSION} -c Release --no-build --no-restore -o /tmp/artifacts $project ; \
done
cd /tmp/artifacts
tar -czf /tmp/artifacts/packages.tar.gz *.nupkg