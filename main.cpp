#include <QCoreApplication>

#include <QDesktopServices>
#include <QUrl>
#include <QDir>
#include "websockettransport.h"
#include "websocketclientwrapper.h"
#include <QtWebSockets/QWebSocketServer>
#include <QWebChannel>

#define _WIN32_DCOM
#include <iostream>
using namespace std;
#include <comdef.h>
#include <Wbemidl.h>

#pragma comment(lib, "wbemuuid.lib")

#include <sstream>
#include <thread>
#include <memory>
#include <mutex>

class KillSwitch : public QObject
{
    Q_OBJECT
public:
    explicit KillSwitch(QObject *parent = 0)
        :QObject(parent)
    {
        //m_ruleMonitoringIsEnabled.store(false);
        InitializeComAndWMI();
        GetFirewallRuleClassObject();
        WriteFirewallRuleInstanceIfNotPresent(sDisabled);
        m_state = sDisabled;
    }
    KillSwitch(const KillSwitch& other) = delete;
    KillSwitch& operator=(const KillSwitch& other) = delete;
    ~KillSwitch()
    {
        Clean();
    }

signals:
    void PropagateState(const QString &state);
public slots:
    void Enable()
    {
        lock_guard<mutex> lock(m_StateLock);
        if (m_state == sEnabled)
            return;
        m_state = sEnabled;
        WriteFirewallRuleInstance(m_state);
        emit PropagateState(m_state);
    }
    void Disable()
    {
        lock_guard<mutex> lock(m_StateLock);
        if (m_state == sDisabled)
            return;
        m_state = sDisabled;
        WriteFirewallRuleInstance(m_state);
        emit PropagateState(m_state);
    }
    void RequestState()
    {
        emit PropagateState(m_state);
    }
private:
    void InitializeComAndWMI()
    {
        HRESULT hres{};
        // Initialize COM.
        hres = CoInitializeEx(0, COINIT_MULTITHREADED);
        if (FAILED(hres))
            OnFatalError("Failed to initialize COM library. Error code = 0x", hres);
        m_comIsInitialized = true;

        // Initialize
        hres = CoInitializeSecurity(
            NULL,
            -1,      // COM negotiates service
            NULL,    // Authentication services
            NULL,    // Reserved
            RPC_C_AUTHN_LEVEL_DEFAULT,    // authentication
            RPC_C_IMP_LEVEL_IMPERSONATE,  // Impersonation
            NULL,             // Authentication info
            EOAC_NONE,        // Additional capabilities
            NULL              // Reserved
        );

        if (FAILED(hres))
            OnFatalError("Failed to initialize security. Error code = 0x", hres);

        // Obtain the initial locator to Windows Management
        // on a particular host computer.

        hres = CoCreateInstance(
            CLSID_WbemLocator,
            0,
            CLSCTX_INPROC_SERVER,
            IID_IWbemLocator, (LPVOID *)&m_pLocator);

        if (FAILED(hres))
            OnFatalError("Failed to create IWbemLocator object. Error code = 0x", hres);

        // Connect to the root\cimv2 namespace with the
        // current user and obtain pointer pSvc
        // to make IWbemServices calls.

        hres = m_pLocator->ConnectServer(

            _bstr_t(L"ROOT\\StandardCimv2"), // WMI namespace
            NULL,                    // User name
            NULL,                    // User password
            0,                       // Locale
            NULL,                    // Security flags
            0,                       // Authority
            0,                       // Context object
            &m_pSvc                    // IWbemServices proxy
        );

        if (FAILED(hres))
            OnFatalError("Could not connect. Error code = 0x", hres);

        // Set the IWbemServices proxy so that impersonation
        // of the user (client) occurs.
        hres = CoSetProxyBlanket(
            m_pSvc,                         // the proxy to set
            RPC_C_AUTHN_WINNT,            // authentication service
            RPC_C_AUTHZ_NONE,             // authorization service
            NULL,                         // Server principal name
            RPC_C_AUTHN_LEVEL_CALL,       // authentication level
            RPC_C_IMP_LEVEL_IMPERSONATE,  // impersonation level
            NULL,                         // client identity
            EOAC_NONE                     // proxy capabilities
        );

        if (FAILED(hres))
            OnFatalError("Could not set proxy blanket. Error code = 0x", hres);

    }
    std::wstring GetHostName()
    {
        TCHAR hostName[MAX_COMPUTERNAME_LENGTH+1]{};
        DWORD hostNameSize = sizeof(hostName) / sizeof(hostName[0]);
        BOOL bRet = GetComputerNameW(hostName, &hostNameSize);
        if (!bRet)
            OnFatalError("Could not get computer name. ", 0);
        return hostName;
    }
    /*
    void MonitorRule()
    {
        HRESULT hres{};
        IEnumWbemClassObject* pEventEnumerator{};
        std::wstringstream query;
        query<<L"SELECT * FROM __InstanceModificationEvent WHERE InstanceID=\""<< sRuleGUID <<L"\"";
        do
        {
            hres = m_pSvc->ExecNotificationQuery(L"WQL", (BSTR)query.str().c_str()
                                          , WBEM_FLAG_RETURN_IMMEDIATELY | WBEM_FLAG_FORWARD_ONLY, 0
                                          , &pEventEnumerator );
            if(FAILED(hres))
            {
                if (hres == WBEM_E_NOT_FOUND)
                    continue;
                else
                    OnFatalError("Could not execute notification query. ", hres);
            }
            else
                break;

        }while(true);


        IWbemClassObject* pEventObject;
        ULONG eventObjectCount{};
        hres = pEventEnumerator->Next(WBEM_INFINITE, 1, &pEventObject, &eventObjectCount);
        if((hres == WBEM_S_FALSE || hres == WBEM_S_NO_ERROR ) && eventObjectCount == 1)
        {
            //do stuff
            int a = 42;
        }
        else
        {
            OnFatalError("Unexpecter response from notification query. ", hres);
        }
    }

    void StartRuleMonitoring()
    {
        if(monitorThread.get() != nullptr)
        {
            m_ruleMonitoringIsEnabled.store(false);
            //release the enum handle somehow;
            monitorThread->join();
        }
        m_ruleMonitoringIsEnabled.store(true);
        monitorThread.reset(new std::thread(std::bind(&KillSwitch::MonitorRule, this)));
        int x = 32;
    }
    */
    void GetFirewallRuleClassObject()
    {
        HRESULT hres{};
        std::wstring hostName = GetHostName();
        std::wstringstream firewallRuleObjectPath;
        firewallRuleObjectPath << L"\\\\" << hostName << L"\\Root\\StandardCimv2:MSFT_NetFirewallRule";

        hres = m_pSvc->GetObjectW((TCHAR*)(firewallRuleObjectPath.str().c_str())
                                  , WBEM_FLAG_RETURN_WBEM_COMPLETE, NULL, &m_pFirewallRuleClassObj, 0);
        if (FAILED(hres))
            OnFatalError("Could not get firewall rule object. Error code = 0x", hres);
    }

    void WriteFirewallRuleInstance(const QString& state)
    {
        HRESULT hres{};
        assert(m_pFirewallRuleInst == 0);

        hres = m_pFirewallRuleClassObj->SpawnInstance(NULL, &m_pFirewallRuleInst);
        if (FAILED(hres))
            OnFatalError("Could not spawn firewall rule class instance. Error code = 0x", hres);

        VARIANT v;
        VariantInit(&v);

        V_VT(&v) = VT_BSTR;
        V_BSTR(&v) = SysAllocString(sRuleName.c_str());
        LPCWSTR strRuleName = L"ElementName";
        hres = m_pFirewallRuleInst->Put(strRuleName, 0, &v, 0);
        VariantClear(&v);
        if (FAILED(hres))
            OnFatalError("Could not update firewall rule instance. Error code = 0x", hres);

        V_VT(&v) = VT_BSTR;
        V_BSTR(&v) = SysAllocString(sRuleGUID.c_str());
        LPCWSTR strRuleID = L"InstanceID";
        hres = m_pFirewallRuleInst->Put(strRuleID, 0, &v, 0);
        VariantClear(&v);
        if (FAILED(hres))
            OnFatalError("Could not update firewall rule instance. Error code = 0x", hres);

        V_VT(&v) = VT_I2;
        V_UINT(&v) = 2;
        LPCWSTR strRuleDirection = L"Direction";
        hres = m_pFirewallRuleInst->Put(strRuleDirection, 0, &v, 0);
        VariantClear(&v);
        if (FAILED(hres))
            OnFatalError("Could not update firewall rule instance. Error code = 0x", hres);

        V_VT(&v) = VT_I2;
        V_UINT(&v) = 4;
        LPCWSTR strRuleAction = L"Action";
        hres = m_pFirewallRuleInst->Put(strRuleAction, 0, &v, 0);
        VariantClear(&v);
        if (FAILED(hres))
            OnFatalError("Could not update firewall rule instance. Error code = 0x", hres);

        V_VT(&v) = VT_I2;
        V_UINT(&v) = (state == sEnabled)?1:2;
        LPCWSTR strRuleEnabled = L"Enabled";
        hres = m_pFirewallRuleInst->Put(strRuleEnabled, 0, &v, 0);
        VariantClear(&v);
        if (FAILED(hres))
            OnFatalError("Could not update firewall rule instance. Error code = 0x", hres);

        hres = m_pSvc->PutInstance(m_pFirewallRuleInst, 0, 0, 0);
        m_pFirewallRuleInst = 0;

        if (FAILED(hres))
            OnFatalError("Could not write firewall rule instance. Error code = 0x", hres);
    }
    void WriteFirewallRuleInstanceIfNotPresent(const QString& state)
    {
        HRESULT hres{};
        std::wstring hostName = GetHostName();

        wstringstream firewallRuleInstancePath;
        firewallRuleInstancePath<<L"\\\\"<<hostName<<L"\\Root\\StandardCimv2:MSFT_NetFirewallRule.CreationClassName=\"MSFT|FW|FirewallRule|"
                               <<sRuleGUID<<L"\",PolicyRuleName=\"\",SystemCreationClassName=\"\",SystemName=\"\"";
        hres = m_pSvc->GetObjectW((TCHAR*)firewallRuleInstancePath.str().c_str(), WBEM_FLAG_RETURN_WBEM_COMPLETE, 0, &m_pFirewallRuleInst, 0);
        m_pFirewallRuleInst = 0;
        if(FAILED(hres))
        {
            if (hres != WBEM_E_NOT_FOUND)
                OnFatalError("Unexpected error during firewall object search", hres);
            WriteFirewallRuleInstance(state);
        }
    }

    void OnFatalError(const std::string str, HRESULT err)
    {
        stringstream errStr;
        errStr << str << hex << err << endl;
        Clean();
        throw std::exception(errStr.str().c_str());
    }
    void Clean()
    {
        if(m_pLocator)
            m_pLocator->Release();
        if(m_pSvc)
            m_pSvc->Release();
        if(m_pFirewallRuleClassObj)
            m_pFirewallRuleClassObj->Release();
        if(m_pFirewallRuleInst)
            m_pFirewallRuleInst->Release();
        if(m_comIsInitialized)
            CoUninitialize();
    }
private:
    //std::atomic<bool> m_ruleMonitoringIsEnabled;
    //std::unique_ptr<std::thread> monitorThread;
    IWbemClassObject* m_pFirewallRuleClassObj{};
    IWbemClassObject* m_pFirewallRuleInst{};
    IWbemServices* m_pSvc{};
    bool m_comIsInitialized{};
    IWbemLocator* m_pLocator{};
    QString m_state{sUnknown};
    std::mutex m_StateLock;
private:
    static QString sEnabled;
    static QString sDisabled;
    static QString sUnknown;
    static std::wstring sRuleGUID;
    static std::wstring sRuleName;

};

QString KillSwitch::sEnabled    = "Enabled";
QString KillSwitch::sDisabled   = "Disabled";
QString KillSwitch::sUnknown    = "Unknown";
wstring KillSwitch::sRuleGUID   = L"{03dfbbba-0fe6-4081-aa28-adda42399ef6}";
wstring KillSwitch::sRuleName   = L"KillSwitch Rule";

int main(int argc, char *argv[])
{
    QCoreApplication a(argc, argv);

    // setup the QWebSocketServer
    QWebSocketServer server(QStringLiteral("KillSwitch Server"), QWebSocketServer::NonSecureMode);
    if (!server.listen(QHostAddress::LocalHost, 12345)) {
        qFatal("Failed to open web socket server.");
        return 1;
    }

    // wrap WebSocket clients in QWebChannelAbstractTransport objects
    WebSocketClientWrapper clientWrapper(&server);

    // setup the channel
    QWebChannel channel;
    QObject::connect(&clientWrapper, &WebSocketClientWrapper::clientConnected,
                     &channel, &QWebChannel::connectTo);

    // setup the killswitch and publish it to the QWebChannel
    try
    {
        KillSwitch killswitch;
        channel.registerObject(QStringLiteral("killswitch"), &killswitch);
        std::cout<<"Initialization complete.\n";
        return a.exec();
    }
    catch(std::exception& ex)
    {
        std::cerr<<ex.what();
    }
}

#include "main.moc"
