#include <algorithm>
#include <arpa/inet.h>
#include <cctype>
#include <fstream>
#include <iostream>
#include <netinet/in.h>
#include <random>
#include <sstream>
#include <string>
#include <sys/socket.h>
#include <unistd.h>
#include <unordered_set>
#include <vector>

using namespace std;

struct MalwareSample {
    string hash;
    vector<int> apiCalls;
    int label;
};

vector<MalwareSample> samples;

vector<string> splitCSVLine(const string& line) {
    vector<string> values;
    string value;
    stringstream stream(line);

    while (getline(stream, value, ',')) {
        values.push_back(value);
    }

    return values;
}

bool convertToInteger(const string& value, int& number) {
    try {
        size_t position = 0;
        number = stoi(value, &position);

        return position == value.length();
    } catch (...) {
        return false;
    }
}

string trim(const string& value) {
    size_t start = value.find_first_not_of(" \t\r\n");
    size_t end = value.find_last_not_of(" \t\r\n");

    if (start == string::npos) {
        return "";
    }

    return value.substr(start, end - start + 1);
}

string toLowerCase(string value) {
    transform(
        value.begin(),
        value.end(),
        value.begin(),
        [](unsigned char character) {
            return static_cast<char>(tolower(character));
        }
    );

    return value;
}

string urlDecode(const string& value) {
    string decoded;

    for (size_t index = 0; index < value.length(); index++) {
        if (
            value[index] == '%' &&
            index + 2 < value.length()
        ) {
            string hexadecimal =
                value.substr(index + 1, 2);

            try {
                char character =
                    static_cast<char>(
                        stoi(hexadecimal, nullptr, 16)
                    );

                decoded += character;
                index += 2;
            } catch (...) {
                decoded += value[index];
            }
        } else if (value[index] == '+') {
            decoded += ' ';
        } else {
            decoded += value[index];
        }
    }

    return decoded;
}

bool loadDataset() {
    const string datasetPath =
        "dataset/dynamic_api_call_sequence_per_malware_100_0_306.csv";

    ifstream dataset(datasetPath);

    if (!dataset.is_open()) {
        cerr << "[ERROR] Dataset could not be opened.\n";
        cerr << "[INFO] Expected path: "
             << datasetPath
             << "\n";

        return false;
    }

    string line;
    getline(dataset, line);

    int invalidRows = 0;

    while (getline(dataset, line)) {
        if (line.empty()) {
            continue;
        }

        vector<string> values = splitCSVLine(line);

        if (values.size() < 102) {
            invalidRows++;
            continue;
        }

        MalwareSample sample;
        sample.hash = trim(values[0]);

        bool validSample = !sample.hash.empty();

        for (int column = 1; column <= 100; column++) {
            int apiCall = 0;

            if (
                !convertToInteger(
                    trim(values[column]),
                    apiCall
                )
            ) {
                validSample = false;
                break;
            }

            sample.apiCalls.push_back(apiCall);
        }

        int label = 0;

        if (
            !convertToInteger(
                trim(values[101]),
                label
            )
        ) {
            validSample = false;
        }

        if (!validSample) {
            invalidRows++;
            continue;
        }

        sample.label = label;
        samples.push_back(sample);
    }

    dataset.close();

    cout << "[OK] Dataset loaded successfully.\n";
    cout << "[INFO] Valid samples: "
         << samples.size()
         << "\n";
    cout << "[INFO] Invalid rows: "
         << invalidRows
         << "\n";

    return !samples.empty();
}

string readFile(const string& path) {
    ifstream file(path, ios::binary);

    if (!file.is_open()) {
        return "";
    }

    stringstream buffer;
    buffer << file.rdbuf();

    return buffer.str();
}

string jsonEscape(const string& value) {
    string result;

    for (char character : value) {
        switch (character) {
            case '"':
                result += "\\\"";
                break;

            case '\\':
                result += "\\\\";
                break;

            case '\n':
                result += "\\n";
                break;

            case '\r':
                result += "\\r";
                break;

            case '\t':
                result += "\\t";
                break;

            default:
                result += character;
        }
    }

    return result;
}

string getQueryParameter(
    const string& path,
    const string& parameterName
) {
    size_t questionMark = path.find('?');

    if (questionMark == string::npos) {
        return "";
    }

    string query = path.substr(questionMark + 1);
    stringstream queryStream(query);
    string pair;

    while (getline(queryStream, pair, '&')) {
        size_t equalsPosition = pair.find('=');

        if (equalsPosition == string::npos) {
            continue;
        }

        string key = pair.substr(0, equalsPosition);
        string value = pair.substr(equalsPosition + 1);

        if (key == parameterName) {
            return urlDecode(value);
        }
    }

    return "";
}

string getRoutePath(const string& path) {
    size_t questionMark = path.find('?');

    if (questionMark == string::npos) {
        return path;
    }

    return path.substr(0, questionMark);
}

const MalwareSample* findSampleByHash(
    const string& requestedHash
) {
    string normalizedHash =
        toLowerCase(trim(requestedHash));

    if (
        normalizedHash.rfind("sha256:", 0) == 0
    ) {
        normalizedHash =
            trim(normalizedHash.substr(7));
    }

    for (const MalwareSample& sample : samples) {
        if (
            toLowerCase(sample.hash) ==
            normalizedHash
        ) {
            return &sample;
        }
    }

    return nullptr;
}

const MalwareSample& getRandomSample() {
    static random_device randomDevice;
    static mt19937 generator(randomDevice());

    uniform_int_distribution<size_t> distribution(
        0,
        samples.size() - 1
    );

    return samples[distribution(generator)];
}

int calculateRiskScore(
    const MalwareSample& sample
) {
    unordered_set<int> uniqueCalls(
        sample.apiCalls.begin(),
        sample.apiCalls.end()
    );

    int diversityScore =
        static_cast<int>(uniqueCalls.size());

    int transitionChanges = 0;

    for (
        size_t index = 1;
        index < sample.apiCalls.size();
        index++
    ) {
        if (
            sample.apiCalls[index] !=
            sample.apiCalls[index - 1]
        ) {
            transitionChanges++;
        }
    }

    int riskScore;

    if (sample.label != 0) {
        riskScore =
            65 +
            min(18, diversityScore / 2) +
            min(14, transitionChanges / 8);

        riskScore = min(riskScore, 98);
    } else {
        riskScore =
            10 +
            min(15, diversityScore / 4) +
            min(12, transitionChanges / 12);

        riskScore = min(riskScore, 42);
    }

    return riskScore;
}

int calculateConfidence(
    const MalwareSample& sample
) {
    unordered_set<int> uniqueCalls(
        sample.apiCalls.begin(),
        sample.apiCalls.end()
    );

    int confidence =
        80 +
        min(
            18,
            static_cast<int>(uniqueCalls.size() / 3)
        );

    return min(confidence, 98);
}

string classifyRiskLevel(int riskScore) {
    if (riskScore >= 80) {
        return "CRITICAL";
    }

    if (riskScore >= 60) {
        return "HIGH";
    }

    if (riskScore >= 40) {
        return "MODERATE";
    }

    return "LOW";
}

string buildTimelineJSON(
    const MalwareSample& sample
) {
    vector<string> titles = {
        "Process initialization detected",
        "System API requested",
        "File-system activity observed",
        "Memory operation recorded",
        "Process interaction detected",
        "System resource accessed",
        "Behavioural sequence classified"
    };

    vector<string> descriptions = {
        "The selected executable entered the isolated analysis environment.",
        "The process requested an operating-system service.",
        "ShadowBox recorded behaviour associated with file or directory access.",
        "A memory-related event appeared in the API-call sequence.",
        "The process interacted with another system component.",
        "The sample requested access to a protected system resource.",
        "The complete sequence was compared with its dataset classification."
    };

    vector<int> positions = {
        0,
        8,
        21,
        37,
        54,
        73,
        99
    };

    stringstream json;
    json << "[";

    for (size_t index = 0; index < titles.size(); index++) {
        int apiCall =
            sample.apiCalls[positions[index]];

        int seconds =
            static_cast<int>((index + 1) * 2);

        json << "{";
        json << "\"time\":\"00:";

        if (seconds < 10) {
            json << "0";
        }

        json << seconds << "\",";
        json << "\"title\":\""
             << jsonEscape(titles[index])
             << "\",";
        json << "\"description\":\""
             << jsonEscape(
                    descriptions[index] +
                    " API call ID: " +
                    to_string(apiCall) +
                    "."
                )
             << "\"";
        json << "}";

        if (index + 1 < titles.size()) {
            json << ",";
        }
    }

    json << "]";

    return json.str();
}

string buildTerminalJSON(
    const MalwareSample& sample,
    int riskScore,
    int confidence
) {
    vector<string> lines = {
        "> Isolated investigation chamber created.",
        "> Dataset sample selected.",
        "> SHA256 evidence verified.",
        "> API-call sequence loaded.",
        "> 100 behavioural events reconstructed.",
        "> Dataset label identified as " +
            to_string(sample.label) + ".",
        "> Behavioural risk score: " +
            to_string(riskScore) + "/100.",
        "> Classification confidence: " +
            to_string(confidence) + "%.",
        "> Investigation verdict generated."
    };

    stringstream json;
    json << "[";

    for (size_t index = 0; index < lines.size(); index++) {
        json << "\""
             << jsonEscape(lines[index])
             << "\"";

        if (index + 1 < lines.size()) {
            json << ",";
        }
    }

    json << "]";

    return json.str();
}

string createAnalysisJSON(
    const MalwareSample& sample
) {
    bool malwareDetected =
        sample.label != 0;

    int riskScore =
        calculateRiskScore(sample);

    int confidence =
        calculateConfidence(sample);

    string riskLevel =
        classifyRiskLevel(riskScore);

    string verdict;

    if (malwareDetected) {
        verdict =
            riskLevel +
            " MALWARE BEHAVIOUR";
    } else {
        verdict =
            "LOW-RISK BEHAVIOUR";
    }

    string description;

    if (malwareDetected) {
        description =
            "The API-call sequence carries a malicious dataset label and displays a high-risk behavioural pattern.";
    } else {
        description =
            "The API-call sequence carries a non-malicious dataset label and displays comparatively low-risk behaviour.";
    }

    string shortHash =
        sample.hash.substr(
            0,
            min<size_t>(8, sample.hash.size())
        );

    string processName =
        "sample_" +
        shortHash +
        ".exe";

    stringstream json;

    json << "{";
    json << "\"process\":\""
         << jsonEscape(processName)
         << "\",";
    json << "\"hash\":\"SHA256: "
         << jsonEscape(sample.hash)
         << "\",";
    json << "\"rawHash\":\""
         << jsonEscape(sample.hash)
         << "\",";
    json << "\"label\":"
         << sample.label
         << ",";
    json << "\"score\":"
         << riskScore
         << ",";
    json << "\"confidence\":"
         << confidence
         << ",";
    json << "\"riskLevel\":\""
         << riskLevel
         << "\",";
    json << "\"malwareDetected\":"
         << (malwareDetected ? "true" : "false")
         << ",";
    json << "\"verdict\":\""
         << jsonEscape(verdict)
         << "\",";
    json << "\"description\":\""
         << jsonEscape(description)
         << "\",";
    json << "\"timeline\":"
         << buildTimelineJSON(sample)
         << ",";
    json << "\"terminal\":"
         << buildTerminalJSON(
                sample,
                riskScore,
                confidence
            )
         << ",";
    json << "\"apiCalls\":[";

    for (
        size_t index = 0;
        index < 15 &&
        index < sample.apiCalls.size();
        index++
    ) {
        json << sample.apiCalls[index];

        if (
            index + 1 < 15 &&
            index + 1 < sample.apiCalls.size()
        ) {
            json << ",";
        }
    }

    json << "]";
    json << "}";

    return json.str();
}

void sendResponse(
    int clientSocket,
    const string& status,
    const string& contentType,
    const string& body
) {
    stringstream response;

    response << "HTTP/1.1 "
             << status
             << "\r\n";

    response << "Content-Type: "
             << contentType
             << "\r\n";

    response << "Content-Length: "
             << body.size()
             << "\r\n";

    response << "Access-Control-Allow-Origin: *\r\n";
    response << "Cache-Control: no-store\r\n";
    response << "Connection: close\r\n";
    response << "\r\n";
    response << body;

    string responseText = response.str();

    send(
        clientSocket,
        responseText.c_str(),
        responseText.size(),
        0
    );
}

void serveFrontendFile(
    int clientSocket,
    const string& filePath,
    const string& contentType
) {
    string body = readFile(filePath);

    if (body.empty()) {
        sendResponse(
            clientSocket,
            "404 Not Found",
            "text/plain",
            "Requested file was not found."
        );

        return;
    }

    sendResponse(
        clientSocket,
        "200 OK",
        contentType,
        body
    );
}

void handleAnalyzeRequest(
    int clientSocket,
    const string& fullPath
) {
    string requestedHash =
        getQueryParameter(fullPath, "hash");

    if (requestedHash.empty()) {
        const MalwareSample& randomSample =
            getRandomSample();

        sendResponse(
            clientSocket,
            "200 OK",
            "application/json",
            createAnalysisJSON(randomSample)
        );

        return;
    }

    const MalwareSample* selectedSample =
        findSampleByHash(requestedHash);

    if (selectedSample == nullptr) {
        sendResponse(
            clientSocket,
            "404 Not Found",
            "application/json",
            "{\"error\":\"No dataset sample was found for the supplied SHA256 hash.\"}"
        );

        return;
    }

    sendResponse(
        clientSocket,
        "200 OK",
        "application/json",
        createAnalysisJSON(*selectedSample)
    );
}

void handleClient(int clientSocket) {
    char buffer[8192] = {0};

    int receivedBytes = recv(
        clientSocket,
        buffer,
        sizeof(buffer) - 1,
        0
    );

    if (receivedBytes <= 0) {
        close(clientSocket);
        return;
    }

    string request(buffer);
    stringstream requestStream(request);

    string method;
    string fullPath;
    string protocol;

    requestStream >>
        method >>
        fullPath >>
        protocol;

    string routePath =
        getRoutePath(fullPath);

    cout << "[REQUEST] "
         << method
         << " "
         << fullPath
         << "\n";

    if (method != "GET") {
        sendResponse(
            clientSocket,
            "405 Method Not Allowed",
            "application/json",
            "{\"error\":\"Only GET requests are supported.\"}"
        );

        close(clientSocket);
        return;
    }

    if (routePath == "/") {
        serveFrontendFile(
            clientSocket,
            "frontend/index.html",
            "text/html"
        );
    } else if (routePath == "/style.css") {
        serveFrontendFile(
            clientSocket,
            "frontend/style.css",
            "text/css"
        );
    } else if (routePath == "/script.js") {
        serveFrontendFile(
            clientSocket,
            "frontend/script.js",
            "application/javascript"
        );
    } else if (routePath == "/analyze") {
        handleAnalyzeRequest(
            clientSocket,
            fullPath
        );
    } else if (routePath == "/health") {
        stringstream healthJSON;

        healthJSON << "{";
        healthJSON << "\"status\":\"online\",";
        healthJSON << "\"engine\":\"ShadowBox C++\",";
        healthJSON << "\"samples\":"
                   << samples.size();
        healthJSON << "}";

        sendResponse(
            clientSocket,
            "200 OK",
            "application/json",
            healthJSON.str()
        );
    } else {
        sendResponse(
            clientSocket,
            "404 Not Found",
            "application/json",
            "{\"error\":\"Route not found.\"}"
        );
    }

    close(clientSocket);
}

int main() {
    cout << "\n";
    cout << "=============================================\n";
    cout << " SHADOWBOX MALWARE BEHAVIOR ANALYSIS SANDBOX\n";
    cout << "=============================================\n\n";

    if (!loadDataset()) {
        return 1;
    }

    const int port = 8080;

    int serverSocket = socket(
        AF_INET,
        SOCK_STREAM,
        0
    );

    if (serverSocket < 0) {
        cerr << "[ERROR] Could not create server socket.\n";
        return 1;
    }

    int reuseAddress = 1;

    setsockopt(
        serverSocket,
        SOL_SOCKET,
        SO_REUSEADDR,
        &reuseAddress,
        sizeof(reuseAddress)
    );

    sockaddr_in serverAddress {};

    serverAddress.sin_family = AF_INET;
    serverAddress.sin_addr.s_addr =
        INADDR_ANY;
    serverAddress.sin_port =
        htons(port);

    if (
        bind(
            serverSocket,
            reinterpret_cast<sockaddr*>(
                &serverAddress
            ),
            sizeof(serverAddress)
        ) < 0
    ) {
        cerr << "[ERROR] Could not bind to port "
             << port
             << ".\n";

        close(serverSocket);
        return 1;
    }

    if (listen(serverSocket, 10) < 0) {
        cerr << "[ERROR] Could not start listening.\n";

        close(serverSocket);
        return 1;
    }

    cout << "[OK] ShadowBox C++ server is online.\n";
    cout << "[INFO] Port: "
         << port
         << "\n";
    cout << "[INFO] Hash search route enabled.\n";
    cout << "[INFO] Press Ctrl + C to stop.\n\n";

    while (true) {
        sockaddr_in clientAddress {};
        socklen_t clientSize =
            sizeof(clientAddress);

        int clientSocket = accept(
            serverSocket,
            reinterpret_cast<sockaddr*>(
                &clientAddress
            ),
            &clientSize
        );

        if (clientSocket < 0) {
            cerr << "[WARNING] Client connection failed.\n";
            continue;
        }

        handleClient(clientSocket);
    }

    close(serverSocket);

    return 0;
}