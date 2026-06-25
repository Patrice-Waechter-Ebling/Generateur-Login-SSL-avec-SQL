// monolithique.cpp
#define _CRT_SECURE_NO_WARNINGS
#include <windows.h>
#include <sqlext.h>
#include <sqltypes.h>
#include <sql.h>

#include <iostream>
#include <string>
#include <vector>
#include <random>
#include <ctime>
#include <limits>
using namespace std;
class CryptoService {
public:
    static vector<uint8_t> deriveKey(const string& password,
        const vector<uint8_t>& salt) {
        vector<uint8_t> key(32, 0);
        hash<string> h;
        string mix(password.begin(), password.end());
        mix.append(":");
        mix.append(reinterpret_cast<const char*>(salt.data()), salt.size());
        size_t v = h(mix);
        for (size_t i = 0; i < key.size(); ++i) {
            key[i] = static_cast<uint8_t>((v >> ((i % sizeof(size_t)) * 8)) & 0xFF);
            v = h(to_string(v) + mix);
        }
        return key;
    }
    static vector<uint8_t> encrypt(const vector<uint8_t>& plain,
        const vector<uint8_t>& key) {
        vector<uint8_t> out = plain;
        for (size_t i = 0; i < out.size(); ++i) { out[i] ^= key[i % key.size()];}
        return out;
    }
    static vector<uint8_t> decrypt(const vector<uint8_t>& cipher,const vector<uint8_t>& key) {return encrypt(cipher, key);}
};
class MSE2026Service {
public:
    static vector<uint8_t> deriveKey(const string& password,
        const vector<uint8_t>& salt) {
        vector<uint8_t> key(64, 0);
        hash<string> h;
        string mix = "MSE2026::" + password + "::";
        mix.append(reinterpret_cast<const char*>(salt.data()), salt.size());
        size_t v1 = h(mix);
        size_t v2 = h("X" + mix);
        for (size_t i = 0; i < key.size(); ++i) {
            size_t v = (i % 2 == 0) ? v1 : v2;
            key[i] = static_cast<uint8_t>((v >> ((i % sizeof(size_t)) * 8)) & 0xFF);
            v1 = h(to_string(v1) + mix);
            v2 = h(to_string(v2) + mix);
        }
        return key;
    }
    static vector<uint8_t> encrypt(const vector<uint8_t>& plain,const vector<uint8_t>& key) {
        vector<uint8_t> out = plain;
        for (size_t i = 0; i < out.size(); ++i) {out[i] ^= key[i % key.size()];}
        if (!out.empty()) {
            uint8_t last = out.back();
            for (size_t i = out.size() - 1; i > 0; --i) {out[i] = out[i - 1];}
            out[0] = last;
        }
        for (size_t i = 0; i < out.size(); i += 2) {out[i] ^= key[(i * 3) % key.size()];}
        return out;
    }
    static vector<uint8_t> decrypt(const vector<uint8_t>& cipher,const vector<uint8_t>& key) {
        vector<uint8_t> out = cipher;
        for (size_t i = 0; i < out.size(); i += 2) { out[i] ^= key[(i * 3) % key.size()];}
        if (!out.empty()) {
            uint8_t first = out[0];
            for (size_t i = 0; i + 1 < out.size(); ++i) { out[i] = out[i + 1];}
            out.back() = first;
        }
        for (size_t i = 0; i < out.size(); ++i) {out[i] ^= key[i % key.size()];}
        return out;
    }
};
vector<uint8_t> GenererSel(size_t len = 16) {
    static mt19937_64 rng{ random_device{}() };
    static uniform_int_distribution<int> dist(0, 255);
    vector<uint8_t> s(len);
    for (size_t i = 0; i < len; ++i) { s[i] = static_cast<uint8_t>(dist(rng));    }
    return s;
}
long long HorrodatageActuel() {   return static_cast<long long>(time(nullptr));}
vector<uint8_t> stringToBytes(const string& s) { return vector<uint8_t>(s.begin(), s.end());}
string bytesToString(const vector<uint8_t>& v) { return string(v.begin(), v.end());}
struct DbContext {  SQLHENV hEnv = nullptr;    SQLHDBC hDbc = nullptr;};
bool ConnectionDB(DbContext& ctx, const wstring& connStr) {
    if (SQLAllocHandle(SQL_HANDLE_ENV, SQL_NULL_HANDLE, &ctx.hEnv) != SQL_SUCCESS) return false;
    SQLSetEnvAttr(ctx.hEnv, SQL_ATTR_ODBC_VERSION, (void*)SQL_OV_ODBC3, 0);
    if (SQLAllocHandle(SQL_HANDLE_DBC, ctx.hEnv, &ctx.hDbc) != SQL_SUCCESS) return false;
    SQLRETURN ret = SQLDriverConnectW(ctx.hDbc,NULL,(SQLWCHAR*)connStr.c_str(),SQL_NTS,NULL,0,NULL,SQL_DRIVER_COMPLETE);
    return SQL_SUCCEEDED(ret);
}
void dbDisconnect(DbContext& ctx) {
    if (ctx.hDbc) {
        SQLDisconnect(ctx.hDbc);
        SQLFreeHandle(SQL_HANDLE_DBC, ctx.hDbc);
        ctx.hDbc = nullptr;
    }
    if (ctx.hEnv) {SQLFreeHandle(SQL_HANDLE_ENV, ctx.hEnv); ctx.hEnv = nullptr;  }
}
bool InsererLog(DbContext& ctx,
    const wstring& username,
    long long ts,
    const vector<uint8_t>& salt,
    const vector<uint8_t>& cipher,
    const wstring& algo) {
    SQLHSTMT hStmt = nullptr;
    if (SQLAllocHandle(SQL_HANDLE_STMT, ctx.hDbc, &hStmt) != SQL_SUCCESS)return false;
    SQLWCHAR sql[] = L"{CALL InsertEncryptedLog(?, ?, ?, ?, ?)}";
    if (SQLPrepareW(hStmt, sql, SQL_NTS) != SQL_SUCCESS) {SQLFreeHandle(SQL_HANDLE_STMT, hStmt);return false;}
    SQLBindParameter(hStmt, 1, SQL_PARAM_INPUT, SQL_C_WCHAR, SQL_WVARCHAR, 255, 0, (SQLPOINTER)username.c_str(), 0, nullptr);
    SQLBindParameter(hStmt, 2, SQL_PARAM_INPUT, SQL_C_SBIGINT, SQL_BIGINT,0, 0, (SQLPOINTER)&ts, 0, nullptr);
    SQLBindParameter(hStmt, 3, SQL_PARAM_INPUT, SQL_C_BINARY, SQL_VARBINARY,(SQLLEN)salt.size(), 0, (SQLPOINTER)salt.data(), 0, nullptr);
    SQLBindParameter(hStmt, 4, SQL_PARAM_INPUT, SQL_C_BINARY, SQL_VARBINARY, (SQLLEN)cipher.size(), 0, (SQLPOINTER)cipher.data(), 0, nullptr);
    SQLBindParameter(hStmt, 5, SQL_PARAM_INPUT, SQL_C_WCHAR, SQL_WVARCHAR, 32, 0, (SQLPOINTER)algo.c_str(), 0, nullptr);
    SQLRETURN ret = SQLExecute(hStmt);
    SQLFreeHandle(SQL_HANDLE_STMT, hStmt);
    return SQL_SUCCEEDED(ret);
}
bool LectureLog(DbContext& ctx,const wstring& username,vector<long long>& timestamps,vector<vector<uint8_t>>& salts, vector<vector<uint8_t>>& ciphers) {
    SQLHSTMT hStmt = nullptr;
    if (SQLAllocHandle(SQL_HANDLE_STMT, ctx.hDbc, &hStmt) != SQL_SUCCESS)return false;
    SQLWCHAR sql[] = L"{CALL GetEncryptedLogsByUser(?)}";
    if (SQLPrepareW(hStmt, sql, SQL_NTS) != SQL_SUCCESS) {SQLFreeHandle(SQL_HANDLE_STMT, hStmt);return false;}
    SQLBindParameter(hStmt, 1, SQL_PARAM_INPUT, SQL_C_WCHAR, SQL_WVARCHAR, 255, 0, (SQLPOINTER)username.c_str(), 0, nullptr);
    if (!SQL_SUCCEEDED(SQLExecute(hStmt))) {SQLFreeHandle(SQL_HANDLE_STMT, hStmt);return false;}
    SQLBIGINT ts;
    BYTE saltBuf[64];
    BYTE cipherBuf[4096];
    SQLLEN saltLen = 0, cipherLen = 0;
    while (SQLFetch(hStmt) == SQL_SUCCESS) {
        SQLGetData(hStmt, 2, SQL_C_SBIGINT, &ts, 0, nullptr);
        SQLGetData(hStmt, 3, SQL_C_BINARY, saltBuf, sizeof(saltBuf), &saltLen);
        SQLGetData(hStmt, 4, SQL_C_BINARY, cipherBuf, sizeof(cipherBuf), &cipherLen);
        timestamps.push_back((long long)ts);
        salts.emplace_back(saltBuf, saltBuf + saltLen);
        ciphers.emplace_back(cipherBuf, cipherBuf + cipherLen);
    }
    SQLFreeHandle(SQL_HANDLE_STMT, hStmt);
    return true;
}
int main() {
    SetConsoleTitle(L"Generateur Login SSL avec SQL");
    SetConsoleOutputCP(CP_UTF8);
    cout << "Creation: Patrice Waechter-Ebling 2026-06-24\n\tbase sur ma version de 2022" << endl;
    string usernameUtf8, password;
    cout << "Nom d'utilisateur : ";
    getline(cin, usernameUtf8);
    cout << "Mot de passe : ";
    getline(cin, password);
    wstring username(usernameUtf8.begin(), usernameUtf8.end());
    cout << "Choisir l'algo :\n";
    cout << "1) CryptoService (XOR simple)\n";
    cout << "2) MSE2026 (maison)\n";
    cout << "Choix : ";
    int algoChoice = 0;
    cin >> algoChoice;
    wstring algoName = (algoChoice == 2) ? L"MSE2026" : L"XOR";
    cout << "1) Ecrire un log chiffre\n2) Lire les logs\nChoix : ";
    int action = 0;
    cin >> action;
    DbContext db;
    wstring connStr =L"DRIVER={ODBC Driver 17 for SQL Server};SERVER=localhost;DATABASE=DemoLogsDB;Trusted_Connection=Yes;";
    if (!ConnectionDB(db, connStr)) {cerr << "Echec connexion ODBC.\n"; return 1;    }
    if (action == 1) {
        string message;
        cout << "Message de log : ";
        getline(cin, message);
        auto salt = GenererSel();
        vector<uint8_t> key;
        vector<uint8_t> cipher;
        if (algoChoice == 2) {
            key = MSE2026Service::deriveKey(password, salt);
            cipher = MSE2026Service::encrypt(stringToBytes(message), key);
        }
        else {
            key = CryptoService::deriveKey(password, salt);
            cipher = CryptoService::encrypt(stringToBytes(message), key);
        }
        long long ts = HorrodatageActuel();
        if (InsererLog(db, username, ts, salt, cipher, algoName)) { cout << "Log chiffre insere en base.\n";}
        else {cout << "Echec insertion log.\n";}
    }
    else if (action == 2) {
        vector<long long> timestamps;
        vector<vector<uint8_t>> salts;
        vector<vector<uint8_t>> ciphers;
        if (!LectureLog(db, username, timestamps, salts, ciphers)) {cout << "Echec lecture logs.\n";}
        else {
            for (size_t i = 0; i < timestamps.size(); ++i) {
                vector<uint8_t> key;
                vector<uint8_t> plainBytes;
                if (algoChoice == 2) {
                    key = MSE2026Service::deriveKey(password, salts[i]);
                    plainBytes = MSE2026Service::decrypt(ciphers[i], key);
                }
                else {
                    key = CryptoService::deriveKey(password, salts[i]);
                    plainBytes = CryptoService::decrypt(ciphers[i], key);
                }
                string plain = bytesToString(plainBytes);
                cout << "[LOG] " << timestamps[i] << " : " << plain << "\n";
            }
        }
    }
    else {cout << "Choix invalide.\n";}
    dbDisconnect(db);
    return 0;
}
