const bootScreen = document.getElementById("boot-screen");

const startButton = document.getElementById("start-investigation");
const searchCaseButton = document.getElementById("search-case-button");
const randomCaseButton = document.getElementById("random-case-button");
const generateReportButton = document.getElementById(
    "generate-report-button"
);

const hashInput = document.getElementById("hash-input");
const searchMessage = document.getElementById("search-message");

const processName = document.getElementById("process-name");
const processHash = document.getElementById("process-hash");
const caseIdValue = document.getElementById("case-id-value");

const riskScore = document.getElementById("risk-score");
const verdictText = document.getElementById("verdict-text");
const verdictDescription = document.getElementById(
    "verdict-description"
);
const verdictStatus = document.getElementById("verdict-status");

const confidenceProgress = document.getElementById(
    "confidence-progress"
);
const confidenceValue = document.getElementById("confidence-value");

const timeline = document.getElementById("timeline");
const terminalOutput = document.getElementById("terminal-output");

const evidenceNodes = document.querySelectorAll(".evidence-node");
const navItems = document.querySelectorAll(".nav-item");
const riskRing = document.querySelector(".risk-ring");

const reportModal = document.getElementById("report-modal");
const closeReportButton = document.getElementById(
    "close-report-button"
);
const cancelReportButton = document.getElementById(
    "cancel-report-button"
);
const printReportButton = document.getElementById(
    "print-report-button"
);

const reportCaseId = document.getElementById("report-case-id");
const reportDate = document.getElementById("report-date");
const reportProcess = document.getElementById("report-process");
const reportLabel = document.getElementById("report-label");
const reportHash = document.getElementById("report-hash");
const reportRiskScore = document.getElementById(
    "report-risk-score"
);
const reportConfidence = document.getElementById(
    "report-confidence"
);
const reportRiskLevel = document.getElementById(
    "report-risk-level"
);
const reportVerdict = document.getElementById("report-verdict");
const reportDescription = document.getElementById(
    "report-description"
);
const reportTimeline = document.getElementById("report-timeline");

let selectedInvestigation = null;
let completedInvestigation = null;
let riskAnimationTimer = null;

window.addEventListener("load", () => {
    setTimeout(() => {
        bootScreen.classList.add("hidden");
    }, 2400);
});

searchCaseButton.addEventListener("click", async () => {
    const requestedHash = hashInput.value.trim();

    if (requestedHash === "") {
        showSearchMessage(
            "Enter a SHA256 hash or press Random Case.",
            "error"
        );

        hashInput.focus();
        return;
    }

    await acquireCase(requestedHash);
});

randomCaseButton.addEventListener("click", async () => {
    hashInput.value = "";
    await acquireCase("");
});

startButton.addEventListener("click", async () => {
    if (selectedInvestigation === null) {
        await acquireCase("");

        if (selectedInvestigation === null) {
            return;
        }
    }

    runInvestigation(selectedInvestigation);
});

generateReportButton.addEventListener("click", () => {
    if (completedInvestigation === null) {
        return;
    }

    openReport(completedInvestigation);
});

closeReportButton.addEventListener("click", closeReport);
cancelReportButton.addEventListener("click", closeReport);

printReportButton.addEventListener("click", () => {
    addTerminalLine(
        "> Preparing investigation report for PDF export..."
    );

    window.print();
});

reportModal.addEventListener("click", (event) => {
    if (event.target === reportModal) {
        closeReport();
    }
});

document.addEventListener("keydown", (event) => {
    if (
        event.key === "Escape" &&
        !reportModal.classList.contains("hidden")
    ) {
        closeReport();
    }
});

hashInput.addEventListener("keydown", (event) => {
    if (event.key === "Enter") {
        searchCaseButton.click();
    }
});

navItems.forEach((item) => {
    item.addEventListener("click", () => {
        navItems.forEach((button) => {
            button.classList.remove("active");
        });

        item.classList.add("active");

        const sectionName = item.textContent.trim();

        addTerminalLine(
            "> Navigation selected: " + sectionName
        );

        if (sectionName !== "Investigation Room") {
            addTerminalLine(
                "> " +
                sectionName +
                " module is currently locked."
            );
        }
    });
});

async function acquireCase(requestedHash) {
    setControlsDisabled(true);

    selectedInvestigation = null;
    completedInvestigation = null;
    generateReportButton.disabled = true;

    showSearchMessage(
        requestedHash
            ? "Searching dataset for the supplied hash..."
            : "Selecting a random behavioural sample...",
        ""
    );

    resetCasePreview();

    try {
        let endpoint = "/analyze";

        if (requestedHash !== "") {
            endpoint +=
                "?hash=" +
                encodeURIComponent(requestedHash);
        }

        const response = await fetch(endpoint, {
            cache: "no-store"
        });

        const responseData = await response.json();

        if (!response.ok) {
            throw new Error(
                responseData.error ||
                "The requested case could not be loaded."
            );
        }

        const safeHash = getSafeHash(responseData);

        responseData.rawHash = safeHash;
        responseData.score =
            Number(responseData.score) || 0;
        responseData.confidence =
            Number(responseData.confidence) || 0;

        responseData.riskLevel = getRiskLevel(
            responseData.score,
            responseData.riskLevel
        );

        selectedInvestigation = responseData;

        displayCasePreview(responseData);

        showSearchMessage(
            requestedHash
                ? "Exact dataset sample found. Case ready."
                : "Random dataset sample acquired. Case ready.",
            "success"
        );

        addTerminalLine(
            "> Case acquisition successful."
        );

        addTerminalLine(
            "> Evidence hash: " + safeHash
        );
    } catch (error) {
        selectedInvestigation = null;

        showSearchMessage(
            error.message,
            "error"
        );

        processName.textContent = "Case Not Found";

        processHash.textContent =
            "No matching dataset evidence was located.";

        caseIdValue.textContent = "#SB-ERROR";

        startButton.textContent =
            "Start Investigation";

        addTerminalLine(
            "> CASE ACQUISITION ERROR: " +
            error.message
        );
    } finally {
        setControlsDisabled(false);
    }
}

function runInvestigation(data) {
    setControlsDisabled(true);

    completedInvestigation = null;
    generateReportButton.disabled = true;

    resetInvestigation();

    processName.textContent =
        data.process || "Unknown Sample";

    processHash.textContent =
        data.hash ||
        "SHA256: " + getSafeHash(data);

    addTerminalLine(
        "> Connecting to ShadowBox C++ engine..."
    );

    addTerminalLine(
        "> Beginning forensic reconstruction..."
    );

    const terminalLines =
        Array.isArray(data.terminal)
            ? data.terminal
            : [
                "> Dataset sample loaded.",
                "> API-call sequence reconstructed.",
                "> Risk classification completed."
            ];

    terminalLines.forEach((line, index) => {
        setTimeout(() => {
            addTerminalLine(line);

            if (index < evidenceNodes.length) {
                evidenceNodes[index]
                    .classList
                    .add("active");
            }
        }, 450 + index * 450);
    });

    const resultDelay =
        450 +
        terminalLines.length * 450 +
        500;

    setTimeout(() => {
        const finalScore =
            Number(data.score) || 0;

        const finalConfidence =
            Number(data.confidence) || 0;

        const finalRiskLevel = getRiskLevel(
            finalScore,
            data.riskLevel
        );

        data.score = finalScore;
        data.confidence = finalConfidence;
        data.riskLevel = finalRiskLevel;

        showTimeline(
            Array.isArray(data.timeline)
                ? data.timeline
                : []
        );

        animateRiskScore(finalScore);

        verdictText.textContent =
            data.verdict ||
            (
                data.malwareDetected
                    ? "MALWARE BEHAVIOUR DETECTED"
                    : "LOW-RISK BEHAVIOUR"
            );

        verdictDescription.textContent =
            data.description ||
            "Behavioural analysis completed.";

        verdictStatus.textContent =
            finalRiskLevel +
            " risk classification";

        verdictText.style.color =
            data.malwareDetected
                ? "#ff5c7a"
                : "#72ffd2";

        confidenceProgress.style.width =
            finalConfidence + "%";

        confidenceValue.textContent =
            finalConfidence + "%";

        addTerminalLine(
            "> Final risk level: " +
            finalRiskLevel +
            "."
        );

        addTerminalLine(
            "> Investigation completed successfully."
        );

        completedInvestigation = data;
        generateReportButton.disabled = false;

        startButton.textContent =
            "Run Investigation Again";

        setControlsDisabled(false);
    }, resultDelay);
}

function openReport(data) {
    const currentDate = new Date();

    reportCaseId.textContent =
        caseIdValue.textContent;

    reportDate.textContent =
        currentDate.toLocaleString();

    reportProcess.textContent =
        data.process || "Unknown Sample";

    reportLabel.textContent =
        String(
            data.label !== undefined
                ? data.label
                : "Unknown"
        );

    reportHash.textContent =
        getSafeHash(data);

    reportRiskScore.textContent =
        (Number(data.score) || 0) + "/100";

    reportConfidence.textContent =
        (Number(data.confidence) || 0) + "%";

    reportRiskLevel.textContent =
        getRiskLevel(
            data.score,
            data.riskLevel
        );

    reportVerdict.textContent =
        data.verdict ||
        (
            data.malwareDetected
                ? "MALWARE BEHAVIOUR DETECTED"
                : "LOW-RISK BEHAVIOUR"
        );

    reportVerdict.style.color =
        data.malwareDetected
            ? "#d23f5d"
            : "#16705a";

    reportDescription.textContent =
        data.description ||
        "Behavioural analysis completed.";

    buildReportTimeline(
        Array.isArray(data.timeline)
            ? data.timeline
            : []
    );

    reportModal.classList.remove("hidden");
    document.body.style.overflow = "hidden";

    addTerminalLine(
        "> Forensic investigation report generated."
    );
}

function closeReport() {
    reportModal.classList.add("hidden");
    document.body.style.overflow = "";
}

function buildReportTimeline(events) {
    reportTimeline.innerHTML = "";

    if (events.length === 0) {
        const emptyMessage =
            document.createElement("p");

        emptyMessage.textContent =
            "No behavioural timeline was returned.";

        reportTimeline.appendChild(emptyMessage);
        return;
    }

    events.forEach((event) => {
        const item =
            document.createElement("div");

        item.className =
            "report-timeline-item";

        const time =
            document.createElement("span");

        time.textContent =
            event.time || "00:00";

        const title =
            document.createElement("strong");

        title.textContent =
            event.title ||
            "Behaviour detected";

        const description =
            document.createElement("p");

        description.textContent =
            event.description ||
            "API activity recorded.";

        item.appendChild(time);
        item.appendChild(title);
        item.appendChild(description);

        reportTimeline.appendChild(item);
    });
}

function displayCasePreview(data) {
    const safeHash = getSafeHash(data);

    processName.textContent =
        data.process || "Unknown Sample";

    processHash.textContent =
        data.hash ||
        "SHA256: " + safeHash;

    caseIdValue.textContent =
        generateCaseId(safeHash);

    startButton.textContent =
        "Investigate Selected Case";

    verdictStatus.textContent =
        "Evidence acquired";

    verdictText.textContent =
        "CASE READY";

    verdictText.style.color =
        "#72ffd2";

    verdictDescription.textContent =
        "The selected API-call sequence is ready for behavioural reconstruction.";
}

function getSafeHash(data) {
    if (
        data.rawHash !== undefined &&
        data.rawHash !== null &&
        String(data.rawHash).trim() !== ""
    ) {
        return String(data.rawHash)
            .replace(/^SHA256:\s*/i, "")
            .trim();
    }

    if (
        data.hash !== undefined &&
        data.hash !== null &&
        String(data.hash).trim() !== ""
    ) {
        return String(data.hash)
            .replace(/^SHA256:\s*/i, "")
            .trim();
    }

    return "UNKNOWN-HASH";
}

function getRiskLevel(score, backendRiskLevel) {
    if (
        backendRiskLevel !== undefined &&
        backendRiskLevel !== null &&
        String(backendRiskLevel).trim() !== ""
    ) {
        return String(backendRiskLevel)
            .trim()
            .toUpperCase();
    }

    const numericScore =
        Number(score) || 0;

    if (numericScore >= 80) {
        return "CRITICAL";
    }

    if (numericScore >= 60) {
        return "HIGH";
    }

    if (numericScore >= 40) {
        return "MODERATE";
    }

    return "LOW";
}

function resetCasePreview() {
    processName.textContent =
        "Acquiring Evidence...";

    processHash.textContent =
        "Searching the malware API-call dataset.";

    caseIdValue.textContent =
        "#SB-PENDING";

    verdictText.textContent =
        "SEARCHING";

    verdictText.style.color =
        "#ffc857";

    verdictDescription.textContent =
        "ShadowBox is locating behavioural evidence.";

    verdictStatus.textContent =
        "Case acquisition in progress";

    startButton.textContent =
        "Start Investigation";
}

function resetInvestigation() {
    if (riskAnimationTimer !== null) {
        clearInterval(riskAnimationTimer);
        riskAnimationTimer = null;
    }

    riskScore.textContent = "00";

    verdictText.textContent =
        "ANALYZING";

    verdictText.style.color =
        "#ffc857";

    verdictDescription.textContent =
        "ShadowBox is reconstructing the behavioural sequence.";

    verdictStatus.textContent =
        "Analysis in progress";

    confidenceProgress.style.width =
        "0%";

    confidenceValue.textContent =
        "0%";

    riskRing.style.background = `
        radial-gradient(
            circle,
            rgba(114, 255, 210, 0.08),
            transparent 58%
        ),
        conic-gradient(
            #72ffd2 0deg,
            rgba(255, 255, 255, 0.06) 0deg
        )
    `;

    timeline.innerHTML = `
        <div class="empty-state">
            Reconstructing suspicious activity...
        </div>
    `;

    terminalOutput.innerHTML =
        "<p>&gt; Investigation request accepted.</p>";

    evidenceNodes.forEach((node) => {
        node.classList.remove("active");
    });
}

function showSearchMessage(message, type) {
    searchMessage.textContent = message;

    searchMessage.classList.remove(
        "success",
        "error"
    );

    if (type !== "") {
        searchMessage.classList.add(type);
    }
}

function addTerminalLine(text) {
    const line =
        document.createElement("p");

    line.textContent = text;

    terminalOutput.appendChild(line);

    terminalOutput.scrollTop =
        terminalOutput.scrollHeight;
}

function showTimeline(events) {
    timeline.innerHTML = "";

    if (events.length === 0) {
        timeline.innerHTML = `
            <div class="empty-state">
                No timeline events were returned.
            </div>
        `;

        return;
    }

    events.forEach((event, index) => {
        setTimeout(() => {
            const item =
                document.createElement("div");

            item.className =
                "timeline-item";

            const time =
                document.createElement("span");

            time.className =
                "timeline-time";

            time.textContent =
                event.time || "00:00";

            const title =
                document.createElement("h4");

            title.textContent =
                event.title ||
                "Behaviour detected";

            const description =
                document.createElement("p");

            description.textContent =
                event.description ||
                "API activity recorded.";

            item.appendChild(time);
            item.appendChild(title);
            item.appendChild(description);

            timeline.appendChild(item);

            timeline.scrollTop =
                timeline.scrollHeight;
        }, index * 220);
    });
}

function animateRiskScore(finalScore) {
    let currentScore = 0;

    finalScore = Math.max(
        0,
        Math.min(
            100,
            Number(finalScore) || 0
        )
    );

    if (finalScore === 0) {
        riskScore.textContent = "00";
        return;
    }

    const ringColor =
        finalScore >= 50
            ? "#ff5c7a"
            : "#72ffd2";

    riskAnimationTimer =
        setInterval(() => {
            currentScore++;

            riskScore.textContent =
                String(currentScore)
                    .padStart(2, "0");

            const degrees =
                currentScore * 3.6;

            const glowColor =
                finalScore >= 50
                    ? "rgba(255, 92, 122, 0.09)"
                    : "rgba(114, 255, 210, 0.09)";

            riskRing.style.background = `
                radial-gradient(
                    circle,
                    ${glowColor},
                    transparent 58%
                ),
                conic-gradient(
                    ${ringColor} ${degrees}deg,
                    rgba(255, 255, 255, 0.06)
                    ${degrees}deg
                )
            `;

            if (currentScore >= finalScore) {
                clearInterval(
                    riskAnimationTimer
                );

                riskAnimationTimer = null;
            }
        }, 22);
}

function generateCaseId(hash) {
    const safeHash =
        String(hash || "UNKNOWN");

    const cleanHash =
        safeHash.replace(
            /[^a-zA-Z0-9]/g,
            ""
        );

    const caseFragment =
        cleanHash
            .substring(0, 6)
            .toUpperCase();

    return "#SB-" +
        (caseFragment || "UNKNOWN");
}

function setControlsDisabled(disabled) {
    searchCaseButton.disabled = disabled;
    randomCaseButton.disabled = disabled;
    startButton.disabled = disabled;
    hashInput.disabled = disabled;
}