// AI-Based Analyzer for Cybersecurity Threat Detection Frontend Logic

document.addEventListener('DOMContentLoaded', () => {
    // DOM Elements - Shared
    const dropzone = document.getElementById('dropzone');
    const fileInput = document.getElementById('fileInput');
    const progressContainer = document.getElementById('uploadProgressContainer');
    const progressBar = document.getElementById('uploadProgressBar');
    const percentageText = document.getElementById('uploadPercentage');
    const statusText = document.getElementById('uploadStatusText');
    const stageText = document.getElementById('extractionStageText');

    // Tab buttons & containers
    const btnTabNetwork = document.getElementById('btnTabNetwork');
    const btnTabSystem = document.getElementById('btnTabSystem');
    const networkDashboard = document.getElementById('networkDashboard');
    const systemDashboard = document.getElementById('systemDashboard');
    const networkPlaceholder = document.getElementById('networkPlaceholder');
    const networkContent = document.getElementById('networkContent');
    const systemPlaceholder = document.getElementById('systemPlaceholder');
    const systemContent = document.getElementById('systemContent');

    // DOM Elements - Network
    const overallSeverityText = document.getElementById('overallSeverityText');
    const statusBadgeBg = document.getElementById('statusBadgeBg');
    const statTotalFlows = document.getElementById('statTotalFlows');
    const statAnomalies = document.getElementById('statAnomalies');
    const statAvgRisk = document.getElementById('statAvgRisk');
    const tableSearch = document.getElementById('tableSearch');
    const flowTableBody = document.getElementById('flowTableBody');
    const paginationCounter = document.getElementById('paginationCounter');
    const prevPageBtn = document.getElementById('prevPageBtn');
    const nextPageBtn = document.getElementById('nextPageBtn');
    const exportCsvBtn = document.getElementById('exportCsvBtn');

    // DOM Elements - System
    const systemOverallSeverityText = document.getElementById('systemOverallSeverityText');
    const systemStatusBadgeBg = document.getElementById('systemStatusBadgeBg');
    const statTotalSystemLogs = document.getElementById('statTotalSystemLogs');
    const statSystemAlerts = document.getElementById('statSystemAlerts');
    const statSystemAvgRisk = document.getElementById('statSystemAvgRisk');
    const systemTableSearch = document.getElementById('systemTableSearch');
    const systemTableBody = document.getElementById('systemTableBody');
    const systemPaginationCounter = document.getElementById('systemPaginationCounter');
    const systemPrevPageBtn = document.getElementById('systemPrevPageBtn');
    const systemNextPageBtn = document.getElementById('systemNextPageBtn');
    const systemExportCsvBtn = document.getElementById('systemExportCsvBtn');

    // Sliders (Shared)
    const thresholdMed = document.getElementById('thresholdMed');
    const thresholdHigh = document.getElementById('thresholdHigh');
    const thresholdCrit = document.getElementById('thresholdCrit');
    const medVal = document.getElementById('medVal');
    const highVal = document.getElementById('highVal');
    const critVal = document.getElementById('critVal');

    // Theme Toggle Elements
    const themeToggleBtn = document.getElementById('themeToggle');
    const sunIcon = document.getElementById('sunIcon');
    const moonIcon = document.getElementById('moonIcon');

    // Global State variables
    let rawResults = null; // Store network flows
    let systemResults = null; // Store system logs
    let activeTab = 'network';

    let filteredFlows = [];
    let filteredLogs = [];
    
    let currentPage = 1;
    let currentLogsPage = 1;
    const rowsPerPage = 15;
    
    // Chart references
    let categoryChart = null;
    let protocolChart = null;
    let systemCategoryChart = null;
    let systemServiceChart = null;

    // Threshold values
    let thresholds = {
        medium: parseInt(thresholdMed.value),
        high: parseInt(thresholdHigh.value),
        critical: parseInt(thresholdCrit.value)
    };

    // --- SETUP THEME TOGGLING ---
    function syncThemeUI() {
        const isDark = document.documentElement.classList.contains('dark');
        if (isDark) {
            sunIcon.classList.remove('hidden');
            moonIcon.classList.add('hidden');
        } else {
            sunIcon.classList.add('hidden');
            moonIcon.classList.remove('hidden');
        }
    }
    
    syncThemeUI();

    themeToggleBtn.addEventListener('click', () => {
        const isDark = document.documentElement.classList.toggle('dark');
        localStorage.setItem('theme', isDark ? 'dark' : 'light');
        syncThemeUI();
        // Re-render whichever charts are visible
        if (rawResults && activeTab === 'network') {
            renderCharts();
        }
        if (systemResults && activeTab === 'system') {
            renderSystemCharts();
        }
    });

    // --- TAB NAVIGATION WORKFLOW ---
    function switchTab(tab) {
        activeTab = tab;
        if (tab === 'network') {
            // Apply active styles to Network button, reset System button
            btnTabNetwork.className = "px-5 py-3 text-sm font-bold border-b-2 border-brand-500 text-brand-600 dark:text-brand-500 transition-all duration-200 flex items-center space-x-2";
            btnTabSystem.className = "px-5 py-3 text-sm font-medium border-b-2 border-transparent text-slate-500 hover:text-slate-700 dark:text-slate-400 dark:hover:text-slate-200 transition-all duration-200 flex items-center space-x-2";
            
            networkDashboard.classList.remove('hidden');
            systemDashboard.classList.add('hidden');
            
            if (rawResults) {
                networkPlaceholder.classList.add('hidden');
                networkContent.classList.remove('hidden');
                // Force Chart.js size adaptation inside layout flexbox
                setTimeout(() => renderCharts(), 50);
            } else {
                networkPlaceholder.classList.remove('hidden');
                networkContent.classList.add('hidden');
            }
        } else {
            // Apply active styles to System button, reset Network button
            btnTabSystem.className = "px-5 py-3 text-sm font-bold border-b-2 border-brand-500 text-brand-600 dark:text-brand-500 transition-all duration-200 flex items-center space-x-2";
            btnTabNetwork.className = "px-5 py-3 text-sm font-medium border-b-2 border-transparent text-slate-500 hover:text-slate-700 dark:text-slate-400 dark:hover:text-slate-200 transition-all duration-200 flex items-center space-x-2";
            
            systemDashboard.classList.remove('hidden');
            networkDashboard.classList.add('hidden');
            
            if (systemResults) {
                systemPlaceholder.classList.add('hidden');
                systemContent.classList.remove('hidden');
                setTimeout(() => renderSystemCharts(), 50);
            } else {
                systemPlaceholder.classList.remove('hidden');
                systemContent.classList.add('hidden');
            }
        }
    }

    btnTabNetwork.addEventListener('click', () => switchTab('network'));
    btnTabSystem.addEventListener('click', () => switchTab('system'));

    // --- SETUP FILE UPLOAD DRAG & DROP ---
    dropzone.addEventListener('click', () => fileInput.click());
    
    dropzone.addEventListener('dragover', (e) => {
        e.preventDefault();
        dropzone.classList.add('border-brand-500', 'bg-brand-500/10', 'dark:bg-brand-950/10');
    });

    dropzone.addEventListener('dragleave', () => {
        dropzone.classList.remove('border-brand-500', 'bg-brand-500/10', 'dark:bg-brand-950/10');
    });

    dropzone.addEventListener('drop', (e) => {
        e.preventDefault();
        dropzone.classList.remove('border-brand-500', 'bg-brand-500/10', 'dark:bg-brand-950/10');
        const files = e.dataTransfer.files;
        if (files.length > 0) {
            handleFileUpload(files[0]);
        }
    });

    fileInput.addEventListener('change', (e) => {
        if (e.target.files.length > 0) {
            handleFileUpload(e.target.files[0]);
        }
    });

    // --- FILE UPLOAD PROCESSING ---
    function handleFileUpload(file) {
        // Show progress overlay
        progressContainer.classList.remove('hidden');
        progressBar.style.width = '0%';
        percentageText.textContent = '0%';
        statusText.innerHTML = `
            <svg class="animate-spin -ml-1 mr-3 h-5 w-5 text-sky-500 dark:text-sky-400 inline-block" fill="none" viewBox="0 0 24 24">
                <circle class="opacity-25" cx="12" cy="12" r="10" stroke="currentColor" stroke-width="4"></circle>
                <path class="opacity-75" fill="currentColor" d="M4 12a8 8 0 018-8V0C5.373 0 0 5.373 0 12h4zm2 5.291A7.962 7.962 0 014 12H0c0 3.042 1.135 5.824 3 7.938l3-2.647z"></path>
            </svg>
            Uploading file...
        `;
        stageText.textContent = 'Stage 1: Transporting file payloads to Flask dev server';

        const formData = new FormData();
        formData.append('file', file);

        const xhr = new XMLHttpRequest();
        xhr.open('POST', '/upload', true);

        // Track upload progress
        xhr.upload.onprogress = (e) => {
            if (e.lengthComputable) {
                const percentComplete = Math.round((e.loaded / e.total) * 100);
                progressBar.style.width = percentComplete + '%';
                percentageText.textContent = percentComplete + '%';
                if (percentComplete === 100) {
                    statusText.innerHTML = `
                        <svg class="animate-spin -ml-1 mr-3 h-5 w-5 text-purple-500 inline-block" fill="none" viewBox="0 0 24 24">
                            <circle class="opacity-25" cx="12" cy="12" r="10" stroke="currentColor" stroke-width="4"></circle>
                            <path class="opacity-75" fill="currentColor" d="M4 12a8 8 0 018-8V0C5.373 0 0 5.373 0 12h4zm2 5.291A7.962 7.962 0 014 12H0c0 3.042 1.135 5.824 3 7.938l3-2.647z"></path>
                        </svg>
                        Parsing & Analyzing Threats...
                    `;
                    stageText.textContent = 'Stage 2: Processing log files and executing anomaly detection algorithms...';
                }
            }
        };

        xhr.onload = () => {
            progressContainer.classList.add('hidden');
            if (xhr.status === 200) {
                try {
                    const response = JSON.parse(xhr.responseText);
                    if (response.log_type === 'system') {
                        systemResults = response;
                        switchTab('system');
                        processAndDisplaySystemData();
                    } else {
                        rawResults = response;
                        switchTab('network');
                        processAndDisplayNetworkData();
                    }
                } catch (e) {
                    alert('Error parsing server response: ' + e.message);
                }
            } else {
                try {
                    const err = JSON.parse(xhr.responseText);
                    alert(err.error || 'Upload failed');
                } catch (e) {
                    alert('An error occurred during log analysis.');
                }
            }
        };

        xhr.onerror = () => {
            progressContainer.classList.add('hidden');
            alert('Network connection error during upload.');
        };

        xhr.send(formData);
    }

    // --- NETWORK FLOW LOG RENDERING ---
    function processAndDisplayNetworkData() {
        if (!rawResults) return;

        // Dynamic thresholds reclassification
        rawResults.flows.forEach(flow => {
            flow.severity = getSeverityForScore(flow.risk_score);
        });

        let anomaliesCount = 0;
        let maxRisk = 0.0;
        let totalRisk = 0.0;

        rawResults.flows.forEach(flow => {
            if (flow.label !== 'BENIGN') {
                anomaliesCount++;
            }
            maxRisk = Math.max(maxRisk, flow.risk_score);
            totalRisk += flow.risk_score;
        });

        const totalFlows = rawResults.flows.length;
        const avgRisk = totalFlows > 0 ? (totalRisk / totalFlows) : 0.0;
        const overallSeverity = getSeverityForScore(maxRisk);

        // Update Text metrics
        statTotalFlows.textContent = totalFlows.toLocaleString();
        statAnomalies.textContent = anomaliesCount.toLocaleString();
        statAvgRisk.textContent = avgRisk.toFixed(1) + '%';
        overallSeverityText.textContent = overallSeverity + ' Threat';

        // Update styling
        statusBadgeBg.className = 'p-3.5 rounded-xl text-white shadow-lg ' + getBadgeBgClass(overallSeverity);
        overallSeverityText.className = 'text-2xl font-black ' + getSeverityTextClass(overallSeverity);

        filteredFlows = [...rawResults.flows];
        currentPage = 1;
        applySearchAndRender();
        renderCharts();

        networkPlaceholder.classList.add('hidden');
        networkContent.classList.remove('hidden');
        
        networkDashboard.scrollIntoView({ behavior: 'smooth' });
    }

    // --- SYSTEM LOGS RENDERING ---
    function processAndDisplaySystemData() {
        if (!systemResults) return;

        // Dynamic thresholds reclassification
        systemResults.logs.forEach(log => {
            log.severity = getSeverityForScore(log.risk_score);
        });

        let alertsCount = 0;
        let maxRisk = 0.0;
        let totalRisk = 0.0;

        systemResults.logs.forEach(log => {
            if (log.risk_score >= thresholds.medium) {
                alertsCount++;
            }
            maxRisk = Math.max(maxRisk, log.risk_score);
            totalRisk += log.risk_score;
        });

        const totalLogs = systemResults.logs.length;
        const avgRisk = totalLogs > 0 ? (totalRisk / totalLogs) : 0.0;
        const overallSeverity = getSeverityForScore(maxRisk);

        // Update DOM elements
        statTotalSystemLogs.textContent = totalLogs.toLocaleString();
        statSystemAlerts.textContent = alertsCount.toLocaleString();
        statSystemAvgRisk.textContent = avgRisk.toFixed(1) + '%';
        systemOverallSeverityText.textContent = overallSeverity + ' Threat';

        // Update styling
        systemStatusBadgeBg.className = 'p-3.5 rounded-xl text-white shadow-lg ' + getBadgeBgClass(overallSeverity);
        systemOverallSeverityText.className = 'text-2xl font-black ' + getSeverityTextClass(overallSeverity);

        filteredLogs = [...systemResults.logs];
        currentLogsPage = 1;
        applySystemSearchAndRender();
        renderSystemCharts();

        systemPlaceholder.classList.add('hidden');
        systemContent.classList.remove('hidden');

        systemDashboard.scrollIntoView({ behavior: 'smooth' });
    }

    // Process all loaded datasets when sliders are updated
    function processAllData() {
        if (rawResults) {
            processAndDisplayNetworkData();
        }
        if (systemResults) {
            processAndDisplaySystemData();
        }
    }

    // Determine severity from risk score
    function getSeverityForScore(score) {
        if (score >= thresholds.critical) return 'Critical';
        if (score >= thresholds.high) return 'High';
        if (score >= thresholds.medium) return 'Medium';
        return 'Low';
    }

    function getBadgeBgClass(severity) {
        switch (severity) {
            case 'Critical': return 'bg-purple-600 shadow-purple-500/20 animate-pulse';
            case 'High': return 'bg-rose-500 shadow-rose-500/20';
            case 'Medium': return 'bg-amber-500 shadow-amber-500/20';
            default: return 'bg-emerald-500 shadow-emerald-500/20';
        }
    }

    function getSeverityTextClass(severity) {
        switch (severity) {
            case 'Critical': return 'text-purple-600 dark:text-purple-400';
            case 'High': return 'text-rose-600 dark:text-rose-500';
            case 'Medium': return 'text-amber-600 dark:text-amber-550';
            default: return 'text-emerald-600 dark:text-emerald-400';
        }
    }

    function getSeverityBadgeClass(severity) {
        switch (severity) {
            case 'Critical': return 'bg-purple-100 border border-purple-300 text-purple-700 dark:bg-purple-950/80 dark:border-purple-800 dark:text-purple-405';
            case 'High': return 'bg-rose-100 border border-rose-300 text-rose-700 dark:bg-rose-950/80 dark:border-rose-800 dark:text-rose-400';
            case 'Medium': return 'bg-amber-100 border border-amber-300 text-amber-700 dark:bg-amber-950/80 dark:border-amber-800 dark:text-amber-400';
            default: return 'bg-emerald-100 border border-emerald-300 text-emerald-700 dark:bg-emerald-950/80 dark:border-emerald-800 dark:text-emerald-400';
        }
    }

    // --- DYNAMIC THRESHOLD SLIDER ACTIONS ---
    thresholdMed.addEventListener('input', (e) => {
        const val = parseInt(e.target.value);
        if (val >= thresholds.high) {
            thresholdMed.value = thresholds.high - 1;
            return;
        }
        thresholds.medium = val;
        medVal.textContent = val + '%';
        processAllData();
    });

    thresholdHigh.addEventListener('input', (e) => {
        const val = parseInt(e.target.value);
        if (val <= thresholds.medium) {
            thresholdHigh.value = thresholds.medium + 1;
            return;
        }
        if (val >= thresholds.critical) {
            thresholdHigh.value = thresholds.critical - 1;
            return;
        }
        thresholds.high = val;
        highVal.textContent = val + '%';
        processAllData();
    });

    thresholdCrit.addEventListener('input', (e) => {
        const val = parseInt(e.target.value);
        if (val <= thresholds.high) {
            thresholdCrit.value = thresholds.high + 1;
            return;
        }
        thresholds.critical = val;
        critVal.textContent = val + '%';
        processAllData();
    });

    // --- NETWORK TABLE SEARCH & PAGINATION ---
    tableSearch.addEventListener('input', () => {
        currentPage = 1;
        applySearchAndRender();
    });

    function applySearchAndRender() {
        const query = tableSearch.value.toLowerCase().trim();
        
        if (!query) {
            filteredFlows = [...rawResults.flows];
        } else {
            filteredFlows = rawResults.flows.filter(flow => {
                return (
                    flow.src_ip.toLowerCase().includes(query) ||
                    flow.dst_ip.toLowerCase().includes(query) ||
                    flow.label.toLowerCase().includes(query) ||
                    flow.severity.toLowerCase().includes(query) ||
                    flow.protocol_name.toLowerCase().includes(query)
                );
            });
        }
        renderTable();
    }

    function renderTable() {
        flowTableBody.innerHTML = '';
        
        const totalEntries = filteredFlows.length;
        const startIndex = (currentPage - 1) * rowsPerPage;
        const endIndex = Math.min(startIndex + rowsPerPage, totalEntries);
        
        const paginatedData = filteredFlows.slice(startIndex, endIndex);
        
        if (paginatedData.length === 0) {
            flowTableBody.innerHTML = `
                <tr>
                    <td colspan="8" class="text-center py-8 text-slate-500 font-medium">
                        No matching flow records found.
                    </td>
                </tr>
            `;
            paginationCounter.textContent = 'Showing 0 to 0 of 0 entries';
            prevPageBtn.disabled = true;
            nextPageBtn.disabled = true;
            return;
        }

        paginatedData.forEach(flow => {
            const tr = document.createElement('tr');
            tr.className = 'hover:bg-slate-200/50 dark:hover:bg-slate-900/40 transition-colors border-b border-slate-200 dark:border-slate-900/40';
            
            const isMalicious = flow.label !== 'BENIGN';
            const riskBarColor = isMalicious ? 'bg-rose-500' : 'bg-emerald-500';
            
            tr.innerHTML = `
                <td class="px-6 py-3 font-semibold text-slate-800 dark:text-white whitespace-nowrap">${flow.src_ip}:${flow.sport}</td>
                <td class="px-6 py-3 font-semibold text-slate-800 dark:text-white whitespace-nowrap">${flow.dst_ip}:${flow.dport}</td>
                <td class="px-6 py-3 whitespace-nowrap"><span class="bg-slate-200 dark:bg-slate-900 px-2 py-1 rounded text-slate-605 dark:text-slate-400 font-bold">${flow.protocol_name}</span></td>
                <td class="px-6 py-3 font-medium whitespace-nowrap">${flow.flow_duration.toLocaleString()}</td>
                <td class="px-6 py-3 whitespace-nowrap">${flow.total_fwd_pkts} / ${flow.total_bwd_pkts}</td>
                <td class="px-6 py-3 whitespace-nowrap">
                    <span class="px-2.5 py-1 rounded-full font-bold text-[10px] tracking-wide uppercase ${
                        isMalicious ? 'bg-rose-100 border border-rose-200 text-rose-700 dark:bg-rose-950/60 dark:border-rose-800 dark:text-rose-400' : 'bg-emerald-100 border border-emerald-200 text-emerald-700 dark:bg-emerald-950/60 dark:border-emerald-800 dark:text-emerald-400'
                    }">${flow.label}</span>
                </td>
                <td class="px-6 py-3 whitespace-nowrap">
                    <div class="flex items-center space-x-2 w-28">
                        <span class="font-bold">${flow.risk_score}%</span>
                        <div class="flex-1 bg-slate-200 dark:bg-slate-800 rounded-full h-1.5 overflow-hidden">
                            <div class="${riskBarColor} h-1.5 rounded-full" style="width: ${flow.risk_score}%"></div>
                        </div>
                    </div>
                </td>
                <td class="px-6 py-3 whitespace-nowrap">
                    <span class="px-2 py-0.5 rounded text-[10px] font-bold uppercase tracking-wider ${getSeverityBadgeClass(flow.severity)}">
                        ${flow.severity}
                    </span>
                </td>
            `;
            flowTableBody.appendChild(tr);
        });

        paginationCounter.textContent = `Showing ${totalEntries === 0 ? 0 : startIndex + 1} to ${endIndex} of ${totalEntries} entries`;
        prevPageBtn.disabled = currentPage === 1;
        nextPageBtn.disabled = endIndex >= totalEntries;
    }

    prevPageBtn.addEventListener('click', () => {
        if (currentPage > 1) {
            currentPage--;
            renderTable();
        }
    });

    nextPageBtn.addEventListener('click', () => {
        const totalEntries = filteredFlows.length;
        if (currentPage * rowsPerPage < totalEntries) {
            currentPage++;
            renderTable();
        }
    });

    // --- SYSTEM TABLE SEARCH & PAGINATION ---
    systemTableSearch.addEventListener('input', () => {
        currentLogsPage = 1;
        applySystemSearchAndRender();
    });

    function applySystemSearchAndRender() {
        const query = systemTableSearch.value.toLowerCase().trim();
        
        if (!query) {
            filteredLogs = [...systemResults.logs];
        } else {
            filteredLogs = systemResults.logs.filter(log => {
                return (
                    log.timestamp.toLowerCase().includes(query) ||
                    log.hostname.toLowerCase().includes(query) ||
                    log.process.toLowerCase().includes(query) ||
                    log.event_type.toLowerCase().includes(query) ||
                    log.message.toLowerCase().includes(query) ||
                    log.severity.toLowerCase().includes(query)
                );
            });
        }
        renderSystemTable();
    }

    function renderSystemTable() {
        systemTableBody.innerHTML = '';
        
        const totalEntries = filteredLogs.length;
        const startIndex = (currentLogsPage - 1) * rowsPerPage;
        const endIndex = Math.min(startIndex + rowsPerPage, totalEntries);
        
        const paginatedData = filteredLogs.slice(startIndex, endIndex);
        
        if (paginatedData.length === 0) {
            systemTableBody.innerHTML = `
                <tr>
                    <td colspan="7" class="text-center py-8 text-slate-500 font-medium">
                        No matching log records found.
                    </td>
                </tr>
            `;
            systemPaginationCounter.textContent = 'Showing 0 to 0 of 0 entries';
            systemPrevPageBtn.disabled = true;
            systemNextPageBtn.disabled = true;
            return;
        }

        paginatedData.forEach(log => {
            const tr = document.createElement('tr');
            tr.className = 'hover:bg-slate-200/50 dark:hover:bg-slate-900/40 transition-colors border-b border-slate-200 dark:border-slate-900/40';
            
            const isAlert = log.risk_score >= thresholds.medium;
            const riskBarColor = isAlert ? 'bg-rose-500' : 'bg-emerald-500';
            const procPid = log.pid !== 'N/A' ? `${log.process}[${log.pid}]` : log.process;
            
            tr.innerHTML = `
                <td class="px-6 py-3 font-semibold text-slate-800 dark:text-slate-300 whitespace-nowrap">${log.timestamp}</td>
                <td class="px-6 py-3 font-semibold text-slate-800 dark:text-white whitespace-nowrap">${log.hostname}</td>
                <td class="px-6 py-3 whitespace-nowrap"><span class="bg-slate-200 dark:bg-slate-900 px-2 py-1 rounded text-slate-605 dark:text-slate-400 font-bold">${procPid}</span></td>
                <td class="px-6 py-3 whitespace-nowrap">
                    <span class="px-2.5 py-1 rounded-full font-bold text-[10px] tracking-wide uppercase ${
                        isAlert ? 'bg-rose-100 border border-rose-200 text-rose-700 dark:bg-rose-950/60 dark:border-rose-800 dark:text-rose-400' : 'bg-emerald-100 border border-emerald-200 text-emerald-700 dark:bg-emerald-950/60 dark:border-emerald-800 dark:text-emerald-400'
                    }">${log.event_type}</span>
                </td>
                <td class="px-6 py-3 font-medium text-slate-600 dark:text-slate-350 max-w-sm truncate" title="${log.message}">${log.message}</td>
                <td class="px-6 py-3 whitespace-nowrap">
                    <div class="flex items-center space-x-2 w-24">
                        <span class="font-bold">${log.risk_score}%</span>
                        <div class="flex-1 bg-slate-200 dark:bg-slate-800 rounded-full h-1.5 overflow-hidden">
                            <div class="${riskBarColor} h-1.5 rounded-full" style="width: ${log.risk_score}%"></div>
                        </div>
                    </div>
                </td>
                <td class="px-6 py-3 whitespace-nowrap">
                    <span class="px-2 py-0.5 rounded text-[10px] font-bold uppercase tracking-wider ${getSeverityBadgeClass(log.severity)}">
                        ${log.severity}
                    </span>
                </td>
            `;
            systemTableBody.appendChild(tr);
        });

        systemPaginationCounter.textContent = `Showing ${totalEntries === 0 ? 0 : startIndex + 1} to ${endIndex} of ${totalEntries} entries`;
        systemPrevPageBtn.disabled = currentLogsPage === 1;
        systemNextPageBtn.disabled = endIndex >= totalEntries;
    }

    systemPrevPageBtn.addEventListener('click', () => {
        if (currentLogsPage > 1) {
            currentLogsPage--;
            renderSystemTable();
        }
    });

    systemNextPageBtn.addEventListener('click', () => {
        const totalEntries = filteredLogs.length;
        if (currentLogsPage * rowsPerPage < totalEntries) {
            currentLogsPage++;
            renderSystemTable();
        }
    });

    // --- NETWORK CHART GENERATION ---
    function renderCharts() {
        if (!rawResults) return;

        const isDark = document.documentElement.classList.contains('dark');
        const gridColor = isDark ? '#1e293b' : '#e2e8f0';
        const labelColor = isDark ? '#94a3b8' : '#475569';

        // 1. Doughnut: Intrusion Categories
        const catCounts = {
            'BENIGN': 0, 'DoS': 0, 'DDoS': 0, 'PortScan': 0, 'Botnet': 0, 'Web Attack': 0
        };
        
        rawResults.flows.forEach(flow => {
            catCounts[flow.label] = (catCounts[flow.label] || 0) + 1;
        });

        const categoryLabels = Object.keys(catCounts);
        const categoryData = Object.values(catCounts);

        const COLOR_MAP = {
            'BENIGN': '#10b981',     // Benign - Emerald Green
            'DoS': '#0ea5e9',        // DoS - Sky Blue
            'DDoS': '#6366f1',       // DDoS - Indigo Blue
            'PortScan': '#f59e0b',   // PortScan - Amber
            'Botnet': '#8b5cf6',     // Botnet - Violet
            'Web Attack': '#f43f5e'  // Web Attack - Rose
        };
        const bgColors = categoryLabels.map(cat => COLOR_MAP[cat] || '#64748b');

        if (categoryChart) categoryChart.destroy();
        
        const catCtx = document.getElementById('categoryChart').getContext('2d');
        categoryChart = new Chart(catCtx, {
            type: 'doughnut',
            data: {
                labels: categoryLabels,
                datasets: [{
                    data: categoryData,
                    backgroundColor: bgColors,
                    borderWidth: 0,
                    hoverOffset: 4
                }]
            },
            options: {
                plugins: { legend: { display: false } },
                cutout: '75%',
                responsive: true,
                maintainAspectRatio: false
            }
        });

        // 2. Bar Chart: Protocols vs Threat Severities
        const protocolStats = {
            'TCP': { 'Low': 0, 'Medium': 0, 'High': 0, 'Critical': 0 },
            'UDP': { 'Low': 0, 'Medium': 0, 'High': 0, 'Critical': 0 },
            'Other': { 'Low': 0, 'Medium': 0, 'High': 0, 'Critical': 0 }
        };

        rawResults.flows.forEach(flow => {
            const proto = flow.protocol_name;
            const sev = flow.severity;
            if (protocolStats[proto]) {
                protocolStats[proto][sev]++;
            } else {
                protocolStats['Other'][sev]++;
            }
        });

        const datasets = [
            { label: 'Low Severity', data: [protocolStats['TCP']['Low'], protocolStats['UDP']['Low'], protocolStats['Other']['Low']], backgroundColor: '#10b981' },
            { label: 'Medium Severity', data: [protocolStats['TCP']['Medium'], protocolStats['UDP']['Medium'], protocolStats['Other']['Medium']], backgroundColor: '#f59e0b' },
            { label: 'High Severity', data: [protocolStats['TCP']['High'], protocolStats['UDP']['High'], protocolStats['Other']['High']], backgroundColor: '#f43f5e' },
            { label: 'Critical Severity', data: [protocolStats['TCP']['Critical'], protocolStats['UDP']['Critical'], protocolStats['Other']['Critical']], backgroundColor: '#8b5cf6' }
        ];

        if (protocolChart) protocolChart.destroy();

        const protoCtx = document.getElementById('protocolChart').getContext('2d');
        protocolChart = new Chart(protoCtx, {
            type: 'bar',
            data: {
                labels: ['TCP', 'UDP', 'Other Protocol'],
                datasets: datasets
            },
            options: {
                responsive: true,
                maintainAspectRatio: false,
                plugins: {
                    legend: {
                        position: 'top',
                        labels: { color: labelColor, font: { family: 'Inter', size: 10, weight: 'bold' } }
                    }
                },
                scales: {
                    x: {
                        stacked: true,
                        grid: { display: false },
                        ticks: { color: labelColor, font: { family: 'Inter', size: 10, weight: 'bold' } }
                    },
                    y: {
                        stacked: true,
                        grid: { color: gridColor },
                        ticks: { color: labelColor, font: { family: 'Inter', size: 10 } }
                    }
                }
            }
        });
    }

    // --- SYSTEM CHART GENERATION ---
    function renderSystemCharts() {
        if (!systemResults) return;

        const isDark = document.documentElement.classList.contains('dark');
        const gridColor = isDark ? '#1e293b' : '#e2e8f0';
        const labelColor = isDark ? '#94a3b8' : '#475569';

        // 1. Doughnut: Event Categories
        const catCounts = {};
        systemResults.logs.forEach(log => {
            catCounts[log.event_type] = (catCounts[log.event_type] || 0) + 1;
        });

        const catLabels = Object.keys(catCounts);
        const catData = Object.values(catCounts);

        if (systemCategoryChart) systemCategoryChart.destroy();

        const catCtx = document.getElementById('systemCategoryChart').getContext('2d');
        systemCategoryChart = new Chart(catCtx, {
            type: 'doughnut',
            data: {
                labels: catLabels,
                datasets: [{
                    data: catData,
                    backgroundColor: [
                        '#10b981', // System Info - Emerald
                        '#f59e0b', // Brute Force - Amber
                        '#ef4444', // Privilege Esc. - Red
                        '#ea580c', // Service Crash - Orange
                        '#8b5cf6', // Suspicious Act. - Purple
                        '#0ea5e9', // Auth Event - Sky
                        '#6366f1', // System Error - Indigo
                        '#a855f7'  // System Warning - Purple lighter
                    ],
                    borderWidth: 0,
                    hoverOffset: 4
                }]
            },
            options: {
                plugins: { legend: { display: false } },
                cutout: '75%',
                responsive: true,
                maintainAspectRatio: false
            }
        });

        // 2. Dual Axis Bar-Line Chart: Log Volume & Max Risk Score per Service
        const serviceStats = {};
        systemResults.logs.forEach(log => {
            const svc = log.process;
            if (!serviceStats[svc]) {
                serviceStats[svc] = { count: 0, maxRisk: 0 };
            }
            serviceStats[svc].count++;
            serviceStats[svc].maxRisk = Math.max(serviceStats[svc].maxRisk, log.risk_score);
        });

        // Sort processes by count and take top 8
        const sortedServices = Object.keys(serviceStats)
            .sort((a, b) => serviceStats[b].count - serviceStats[a].count)
            .slice(0, 8);

        const svcCounts = sortedServices.map(s => serviceStats[s].count);
        const svcMaxRisks = sortedServices.map(s => serviceStats[s].maxRisk);

        if (systemServiceChart) systemServiceChart.destroy();

        const svcCtx = document.getElementById('systemServiceChart').getContext('2d');
        systemServiceChart = new Chart(svcCtx, {
            type: 'bar',
            data: {
                labels: sortedServices,
                datasets: [
                    {
                        label: 'Log Count',
                        data: svcCounts,
                        backgroundColor: '#0ea5e9',
                        yAxisID: 'y',
                        order: 2
                    },
                    {
                        label: 'Max Risk Score (%)',
                        data: svcMaxRisks,
                        borderColor: '#f43f5e',
                        backgroundColor: '#ef4444',
                        borderWidth: 2,
                        pointBackgroundColor: '#ef4444',
                        type: 'line',
                        fill: false,
                        yAxisID: 'yRisk',
                        order: 1
                    }
                ]
            },
            options: {
                responsive: true,
                maintainAspectRatio: false,
                plugins: {
                    legend: {
                        position: 'top',
                        labels: { color: labelColor, font: { family: 'Inter', size: 10, weight: 'bold' } }
                    }
                },
                scales: {
                    x: {
                        grid: { display: false },
                        ticks: { color: labelColor, font: { family: 'Inter', size: 10, weight: 'bold' } }
                    },
                    y: {
                        position: 'left',
                        grid: { color: gridColor },
                        ticks: { color: labelColor, font: { family: 'Inter', size: 10 } },
                        title: { display: true, text: 'Log Volume', color: labelColor }
                    },
                    yRisk: {
                        position: 'right',
                        grid: { display: false },
                        ticks: { color: labelColor, font: { family: 'Inter', size: 10 } },
                        title: { display: true, text: 'Max Risk %', color: labelColor },
                        min: 0,
                        max: 100
                    }
                }
            }
        });
    }

    // --- CSV EXPORTS ---
    exportCsvBtn.addEventListener('click', () => {
        if (!filteredFlows.length) return;
        
        let csvContent = "data:text/csv;charset=utf-8,";
        csvContent += "Source IP,Source Port,Destination IP,Destination Port,Protocol,Duration (us),Fwd Packets,Bwd Packets,Classification,Risk Score,Severity\n";
        
        filteredFlows.forEach(flow => {
            const row = [
                flow.src_ip,
                flow.sport,
                flow.dst_ip,
                flow.dport,
                flow.protocol_name,
                flow.flow_duration,
                flow.total_fwd_pkts,
                flow.total_bwd_pkts,
                flow.label,
                flow.risk_score,
                flow.severity
            ].map(val => `"${val}"`).join(",");
            csvContent += row + "\n";
        });
        
        const encodedUri = encodeURI(csvContent);
        const link = document.createElement("a");
        link.setAttribute("href", encodedUri);
        
        const fileBase = rawResults.filename ? rawResults.filename.split('.').slice(0, -1).join('.') : 'AI-Based Analyzer for Cybersecurity Threat Detection_report';
        link.setAttribute("download", `${fileBase || 'AI-Based Analyzer for Cybersecurity Threat Detection_report'}_analysis.csv`);
        document.body.appendChild(link);
        
        link.click();
        document.body.removeChild(link);
    });

    systemExportCsvBtn.addEventListener('click', () => {
        if (!filteredLogs.length) return;
        
        let csvContent = "data:text/csv;charset=utf-8,";
        csvContent += "Timestamp,Hostname,Service/Process,PID,Event Type,Message,Risk Score,Severity\n";
        
        filteredLogs.forEach(log => {
            const row = [
                log.timestamp,
                log.hostname,
                log.process,
                log.pid,
                log.event_type,
                log.message,
                log.risk_score,
                log.severity
            ].map(val => `"${val}"`).join(",");
            csvContent += row + "\n";
        });
        
        const encodedUri = encodeURI(csvContent);
        const link = document.createElement("a");
        link.setAttribute("href", encodedUri);
        
        const fileBase = systemResults.filename ? systemResults.filename.split('.').slice(0, -1).join('.') : 'AI-Based Analyzer for Cybersecurity Threat Detection_system_report';
        link.setAttribute("download", `${fileBase || 'AI-Based Analyzer for Cybersecurity Threat Detection_system_report'}_analysis.csv`);
        document.body.appendChild(link);
        
        link.click();
        document.body.removeChild(link);
    });

    // Default initialization
    switchTab('network');

    // Mobile Sidebar Toggle Support
    const sidebar = document.getElementById('sidebar');
    const sidebarToggle = document.getElementById('sidebarToggle');
    const sidebarClose = document.getElementById('sidebarClose');
    const sidebarBackdrop = document.getElementById('sidebarBackdrop');

    if (sidebarToggle && sidebarClose && sidebarBackdrop && sidebar) {
        function openSidebar() {
            sidebar.classList.remove('-translate-x-full');
            sidebar.classList.add('translate-x-0');
            sidebarBackdrop.classList.remove('hidden');
        }
        
        function closeSidebar() {
            sidebar.classList.remove('translate-x-0');
            sidebar.classList.add('-translate-x-full');
            sidebarBackdrop.classList.add('hidden');
        }
        
        sidebarToggle.addEventListener('click', openSidebar);
        sidebarClose.addEventListener('click', closeSidebar);
        sidebarBackdrop.addEventListener('click', closeSidebar);
        
        // Close sidebar drawer automatically when switching tabs
        document.getElementById('btnTabNetwork').addEventListener('click', closeSidebar);
        document.getElementById('btnTabSystem').addEventListener('click', closeSidebar);
    }

});
