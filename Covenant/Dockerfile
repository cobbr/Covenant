ARG WINVER=ltsc2022
FROM mcr.microsoft.com/dotnet/sdk:3.1-nanoserver-$WINVER AS build
WORKDIR /app

COPY . ./
RUN dotnet publish -c Release -o out

FROM mcr.microsoft.com/dotnet/sdk:3.1-nanoserver-$WINVER AS runtime
WORKDIR /app
COPY --from=build /app/out .
COPY ./Data ./Data
EXPOSE 7443 80 443
ENTRYPOINT ["dotnet", "Covenant.dll"]
