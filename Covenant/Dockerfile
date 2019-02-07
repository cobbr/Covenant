FROM microsoft/dotnet:2.1-sdk AS build
WORKDIR /app

COPY . ./
RUN dotnet restore 
RUN dotnet publish -c Release -o out

FROM microsoft/dotnet:2.1-aspnetcore-runtime AS runtime
WORKDIR /app
COPY --from=build /app/out .
COPY ./Data ./Data
EXPOSE 7443 80 443
ENTRYPOINT ["dotnet", "Covenant.dll"]
