#include <Windows.h>
#include <iostream>
#include <string>
#include <vector>
#include <fstream>
#include <aclapi.h>
#include <algorithm>

using namespace std;

string GetFileName() {
    char buffer[MAX_PATH];
    GetModuleFileName(NULL, buffer, MAX_PATH);
    return string(buffer);
}

// получаем путь к текущей директории
string GetExePath() {
    string f = GetFileName();
    return f.substr(0, f.find_last_of("\\/"));
}
// парсим файл templates.tbl
int ParseTemplate(vector<string> &templates, string &password) {
    string line;
    ifstream tblfile("templates.tbl");
    if (tblfile.is_open()) {
        getline(tblfile, password);
        while (getline(tblfile, line)) {
            templates.emplace_back(line);
        }
        tblfile.close();
    } else {
        cout << "Unable to open a file\n";
        return 1;
    }
    return 0;
}

// проверка по маске
class Matcher {
public:
    Matcher(const char *name, const char *mask) : name(name), mask(mask) {}

    bool match() {
        if (!try_partial_match())
            return false;

        while (*mask == '*') {
            ++mask;
            while (!try_partial_match() && *name != '\0')
                ++name;
        }

        return is_full_match();
    }

private:
    bool is_full_match() const { return *name == '\0' && *mask == '\0'; }

    bool patrial_match() {
        while (*name != '\0' && (*name == *mask || *mask == '?')) {
            ++name;
            ++mask;
        }

        return is_full_match() || *mask == '*';
    }

    bool try_partial_match() {
        auto tmp = *this;
        if (tmp.patrial_match()) {
            *this = tmp;
            return true;
        }
        return false;
    }

    const char *name;
    const char *mask;
};

bool matching(const char *name, const char *mask) {
    return Matcher(name, mask).match();
}

// структура для сохранения информации о файлах
struct FileSecInfo {
    PSID psidOwner;
    PSID psidGroup;
    PACL pDACL;
    PSECURITY_DESCRIPTOR pSD;
};

// обновляем директорию после получения уведомления об изменениях в ней
int RefreshDirectory(vector<string> to_protect, vector<string> templates, string folder) {
    WIN32_FIND_DATAA Data;
    HANDLE hfind = FindFirstFileA(folder.c_str(), &Data);
    if (hfind != INVALID_HANDLE_VALUE) {
        do {
            if (!(Data.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY)) {
                for (int i = 0; i < templates.size(); i++) {
                    if (matching(Data.cFileName, templates[i].c_str())) {
                        if (find(to_protect.begin(), to_protect.end(), Data.cFileName) == to_protect.end()) {
                            if (!DeleteFile(Data.cFileName)) {
                                cout << "Error deleting a file " << Data.cFileName << endl;
                                cout << GetLastError() << endl;
                                return 1;
                            }
                            cout << "Have deleted " << Data.cFileName << endl;
                        }
                    }
                }

            }
        } while (FindNextFile(hfind, &Data));
        FindClose(hfind);
    }
    return 0;
}
// поток, который ожидает введения пароля
DWORD WINAPI thread2(LPVOID lpParam) {
    hash<string> hasher;
    string pass;

    while (true) {
        cout << "Enter a password: " << endl;
        cin >> pass;

        if (hasher(pass) == *(DWORD *) lpParam) {
            break;
        }
    }
    return 0;
}

int main() {
    int DEBUG = 0;
    WIN32_FIND_DATAA data;
    vector<string> to_protect;
    vector<string> templates;
    vector<FileSecInfo> to_restore;
    string password;

    string folder = GetExePath() + "\\*";

    if (DEBUG) {
        cout << folder << endl;
    }

    if (!ParseTemplate(templates, password)) {
        if (DEBUG) {
            cout << "The encrypted password is: " << password << endl;
            cout << "Templates given:" << endl;
            for (int i = 0; i < templates.size(); i++) {
                cout << templates[i] << endl;
            }
            cout << endl;
        }
    } else {
        cout << "Error parsing template file" << endl;
    }
    // проходимся по директории и находим файлы, подходящие под маски
    HANDLE hFind = FindFirstFileA(folder.c_str(), &data);
    if (hFind != INVALID_HANDLE_VALUE) {
        do {
            if (!(data.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY)) {
                for (int i = 0; i < templates.size(); i++) {
                    if (matching(data.cFileName, templates[i].c_str())) {
                        to_protect.emplace_back(data.cFileName);
                    }
                }

            }
        } while (FindNextFile(hFind, &data));
        FindClose(hFind);
    }
    if (DEBUG) {
        cout << "All the files to protect: " << endl;
        for (int i = 0; i < to_protect.size(); i++) {
            cout << to_protect[i] << endl;
        }
    }
    // запоминаем информацию о файлах, которые будем защищать
    for (int i = 0; i < to_protect.size(); i++) {
        PSID psidOwner;
        PSID psidGroup;
        PACL pDACL;

        PSECURITY_DESCRIPTOR pSD;
        SECURITY_INFORMATION SI = DACL_SECURITY_INFORMATION | OWNER_SECURITY_INFORMATION | GROUP_SECURITY_INFORMATION;
        DWORD result = GetNamedSecurityInfo(const_cast<char *>(to_protect[i].c_str()), SE_FILE_OBJECT, SI,
                                            &psidOwner, &psidGroup, &pDACL, NULL, &pSD);
        if (result != ERROR_SUCCESS) {
            cout << "Unable to get info from a file " << to_protect[i] << endl;
            cout << GetLastError();
            return 1;
        }
        FileSecInfo another = {psidOwner, psidGroup, pDACL, pSD};
        to_restore.emplace_back(another);
    }

    PSID pSIDAdmin = NULL;
    SID_IDENTIFIER_AUTHORITY SIDAuthNT = SECURITY_NT_AUTHORITY;
    // создаем новый DACL
    if (!AllocateAndInitializeSid(&SIDAuthNT, 2,
                                  SECURITY_BUILTIN_DOMAIN_RID,
                                  DOMAIN_ALIAS_RID_ADMINS,
                                  0, 0, 0, 0, 0, 0,
                                  &pSIDAdmin)) {
        cout << "Error " << GetLastError() << endl;
    }

    EXPLICIT_ACCESS ea = {
            GENERIC_ALL,
            GRANT_ACCESS,
            NO_INHERITANCE,
            // the one for whom those are applicable
            {0, NO_MULTIPLE_TRUSTEE, TRUSTEE_IS_SID, TRUSTEE_IS_GROUP, (LPTSTR) pSIDAdmin}
    };

    PACL pacl;
    DWORD err = SetEntriesInAcl(1, &ea, NULL, &pacl);
    if (err != ERROR_SUCCESS) {
        cout << "SetAcl Error " << GetLastError() << endl;
        return 1;
    }
    // устанавливаем новый DACL
    for (int i = 0; i < to_protect.size(); i++) {
        err = SetNamedSecurityInfo(const_cast<char *>(to_protect[i].c_str()), SE_FILE_OBJECT,
                                   DACL_SECURITY_INFORMATION | PROTECTED_DACL_SECURITY_INFORMATION, NULL, NULL, pacl,
                                   NULL);
        if (err != ERROR_SUCCESS) {
            cout << "SetNamedSecurityInfo() " << GetLastError() << endl;
            return 1;
        }
    }

    HANDLE rule = FindFirstChangeNotification(
            GetExePath().c_str(),                 // директория для просмотра
            FALSE,                                // не просматривать поддиректории
            FILE_NOTIFY_CHANGE_FILE_NAME);        // отслеживать изм. имён файлов
    if (rule == INVALID_HANDLE_VALUE) {
        cout << "Notification Error" << GetLastError() << endl;
        return 1;
    }
    int true_hash = stoi(password);
    // создаем поток, который ждет ввода пароля от пользователя
    HANDLE thread = CreateThread(NULL, 0, thread2, &true_hash, 0, NULL);
    if (thread == NULL) {
        cout << "Error thread" << endl;
        return 1;
    }

    HANDLE Array_Of_Thread_Handles[2];
    Array_Of_Thread_Handles[0] = rule;
    Array_Of_Thread_Handles[1] = thread;

    while (true) {

        DWORD status = WaitForMultipleObjects(2, Array_Of_Thread_Handles, FALSE, INFINITE);

        switch (status) {
            case WAIT_OBJECT_0:
                RefreshDirectory(to_protect, templates, folder);
                if (FindNextChangeNotification(rule) == FALSE) {
                    // cout << "FindNextChange() failed " << GetLastError() << endl;
                    return 1;
                }
                break;
            case WAIT_OBJECT_0 + 1:
                goto CleanUp;
            default:
                cout << "Error here " << GetLastError() << endl;
                return 1;
        }
    }
    // возвращаем на круги своя
    CleanUp:
    for (int i = 0; i < to_protect.size(); i++) {
        DWORD err = SetNamedSecurityInfo(const_cast<char *>(to_protect[i].c_str()), SE_FILE_OBJECT,
                                         DACL_SECURITY_INFORMATION, NULL, NULL, to_restore[i].pDACL, NULL);
        if (err != ERROR_SUCCESS) {
            cout << "SetNamedSecurityInfo2 " << GetLastError() << endl;
            return 1;
        }
    }

    return 0;
}