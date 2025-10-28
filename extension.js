// const vscode = require('vscode');
// const { runSemgrep } = require('./scanner/semgrepRunner'); // Your Semgrep runner module
// const path = require('path');
// const { exec } = require('child_process');

// function activate(context) {
//   const disposable = vscode.commands.registerCommand('secure.scanCode', async () => {
//     const folder = vscode.workspace.workspaceFolders?.[0]?.uri.fsPath;

//     if (!folder) {
//       vscode.window.showErrorMessage('❌ No folder is open. Please open a workspace.');
//       return;
//     }

//     vscode.window.showInformationMessage('🔍 Running Semgrep scan...');

//     try {
//       const results = await runSemgrep(folder);
//       const findings = results.results || [];

//       if (findings.length > 0) {
//         vscode.window.showWarningMessage(
//           `⚠️ Found ${findings.length} vulnerabilities in your code.`,
//           'View Details'
//         ).then(selection => {
//           if (selection === 'View Details') {
//             showVulnerabilityWebview(findings);
//           }
//         });
//       } else {
//         vscode.window.showInformationMessage('✅ No vulnerabilities found!');
//       }
//     } catch (err) {
//       vscode.window.showErrorMessage(`❌ Scan failed: ${err.message}`);
//     }
//   });

//   context.subscriptions.push(disposable);
// }

// function mapSeverity(rawSeverity) {
//   switch (rawSeverity.toUpperCase()) {
//     case 'ERROR': return 'High';
//     case 'WARNING': return 'Medium';
//     case 'INFO': return 'Info';
//     default: return 'Unknown';
//   }
// }

// function showVulnerabilityWebview(findings) {
//   const panel = vscode.window.createWebviewPanel(
//     'vulnerabilityReport',
//     '🛡️ Vulnerability Report',
//     vscode.ViewColumn.One,
//     { enableScripts: true }
//   );

//   const content = findings.map((item, index) => {
//     const severity = mapSeverity(item.extra?.severity || 'INFO');
//     const line = item.start?.line || 0;
//     const filePath = item.path.replace(/\\/g, '\\\\'); // Escape backslashes for JS string
//     const checkId = item.check_id;
//     const message = item.extra?.message || 'No message.';

//     return `
//       <div style="padding: 10px; border-bottom: 1px solid #ccc;">
//         <h3>#${index + 1}: ${checkId}</h3>
//         <p><strong>Severity:</strong> <span style="color: ${severity === 'High' ? 'red' : severity === 'Medium' ? 'orange' : 'blue'}">${severity}</span></p>
//         <p><strong>Message:</strong> ${message}</p>
//         <p><strong>File:</strong> ${filePath}</p>
//         <p><strong>Line:</strong> ${line}</p>
//         <button onclick="handleAutoFix('${filePath}', ${line})">🛠️ Auto Fix</button>
//       </div>
//     `;
//   }).join('');

//   panel.webview.html = `
//     <!DOCTYPE html>
//     <html lang="en">
//     <head><meta charset="UTF-8"><title>Vulnerabilities</title></head>
//     <body style="font-family: Arial, sans-serif; padding: 10px;">
//       <h2>🔎 Detailed Vulnerabilities</h2>
//       ${content}
//       <script>
//         const vscode = acquireVsCodeApi();
//         function handleAutoFix(filePath, line) {
//           vscode.postMessage({ command: 'autoFix', filePath, line });
//         }
//       </script>
//     </body>
//     </html>
//   `;

//   panel.webview.onDidReceiveMessage(
//     (message) => {
//       if (message.command === 'autoFix') {
//         const { filePath, line } = message;
//         vscode.window.showInformationMessage(`🔧 Running Auto-Fix on ${filePath} (line ${line})...`);

//         const fixerScript = path.join(__dirname, 'fixer', 'autoFixer.js');
//         exec(`node "${fixerScript}" "${filePath}" ${line}`, (error, stdout, stderr) => {
//           if (error) {
//             vscode.window.showErrorMessage(`❌ Fix failed: ${stderr || error.message}`);
//           } else {
//             vscode.window.showInformationMessage(`✅ Fix applied.`);
//             // Optionally reload or refresh file in editor here
//           }
//         });
//       }
//     },
//     undefined,
//     []
//   );
// }

// function deactivate() {
//   // Cleanup if needed
// }

// module.exports = {
//   activate,
//   deactivate
// };



const vscode = require('vscode');
const fs = require('fs');

const path = require('path');
const { exec } = require('child_process');
const { runSemgrep } = require('./scanner/semgrepRunner');

let diagnosticsCollection;
let saveListener;

function activate(context) {
  diagnosticsCollection = vscode.languages.createDiagnosticCollection('securityScan');
  context.subscriptions.push(diagnosticsCollection);

  // Read initial autoScan setting
  const config = vscode.workspace.getConfiguration('secure');
  let autoScanEnabled = config.get('autoScan', true);

  // Command to toggle auto scan on save
  const toggleAutoScanCmd = vscode.commands.registerCommand('secure.toggleAutoScan', async () => {
    autoScanEnabled = !autoScanEnabled;
    await config.update('autoScan', autoScanEnabled, vscode.ConfigurationTarget.Global);
    vscode.window.showInformationMessage(`Auto Scan on Save: ${autoScanEnabled ? 'Enabled' : 'Disabled'}`);
  });
  context.subscriptions.push(toggleAutoScanCmd);

  // Command to manually run scan
  const manualScanCmd = vscode.commands.registerCommand('secure.scanCode', async () => {
    const folder = vscode.workspace.workspaceFolders?.[0]?.uri.fsPath;
    if (!folder) {
      vscode.window.showErrorMessage('❌ No folder is open. Please open a workspace.');
      return;
    }
    await runScanAndReport(folder);
  });
  context.subscriptions.push(manualScanCmd);

  // Run scan automatically on save, if enabled
  saveListener = vscode.workspace.onDidSaveTextDocument(async (document) => {
    if (!autoScanEnabled) return;

    const folder = vscode.workspace.workspaceFolders?.[0]?.uri.fsPath;
    if (!folder) return;

    // Optionally filter by language
    if (!['python', 'javascript', 'typescript'].includes(document.languageId)) return;

    await runScanAndReport(folder);
  });
  context.subscriptions.push(saveListener);

  // Optionally listen to config changes to update autoScanEnabled live
  vscode.workspace.onDidChangeConfiguration(event => {
    if (event.affectsConfiguration('secure.autoScan')) {
      autoScanEnabled = vscode.workspace.getConfiguration('secure').get('autoScan', true);
      vscode.window.showInformationMessage(`Auto Scan on Save is now ${autoScanEnabled ? 'Enabled' : 'Disabled'}`);
    }
  });
}

async function runScanAndReport(folder) {
  vscode.window.showInformationMessage('🔍 Running SecurePush scan...');
  try {
    const results = await runSemgrep(folder);
    const findings = results.results || [];

    // Save findings to vuln-report.json in the root of the workspace
  const reportPath = 'E:\\sbi_hack_ai_thon 24\\AK\\public\\vuln-report.json';
  fs.writeFileSync(reportPath, JSON.stringify({
    vulnerabilitiesFound: findings.length > 0,
    findings: findings
  }, null, 2));

    // Update diagnostics and show webview if findings exist
    updateDiagnostics(findings);

    if (findings.length > 0) {
      vscode.window.showWarningMessage(
        `⚠️ Found ${findings.length} vulnerabilities in your code.`,
        'View Details'
      ).then(selection => {
        if (selection === 'View Details') {
          showVulnerabilityWebview(findings);
        }
      });
    } else {
      vscode.window.showInformationMessage('✅ No vulnerabilities found!');
    }
  } catch (err) {
    vscode.window.showErrorMessage(`❌ Scan failed: ${err.message}`);
  }
}

function updateDiagnostics(findings) {
  diagnosticsCollection.clear();

  const fileDiagnosticsMap = new Map();

  findings.forEach(item => {
    const fileUri = vscode.Uri.file(item.path);
    const startLine = (item.start?.line || 1) - 1; // VSCode lines are 0-based
    const severity = mapSeverityToDiagnosticSeverity(item.extra?.severity);
    const message = item.extra?.message || 'No message.';

    const diagnostic = new vscode.Diagnostic(
      new vscode.Range(startLine, 0, startLine, Number.MAX_SAFE_INTEGER),
      message,
      severity
    );
    diagnostic.source = 'Semgrep';
    diagnostic.code = item.check_id;

    if (!fileDiagnosticsMap.has(fileUri.toString())) {
      fileDiagnosticsMap.set(fileUri.toString(), []);
    }
    fileDiagnosticsMap.get(fileUri.toString()).push(diagnostic);
  });

  for (const [file, diagnostics] of fileDiagnosticsMap.entries()) {
    diagnosticsCollection.set(vscode.Uri.parse(file), diagnostics);
  }
}

function mapSeverityToDiagnosticSeverity(sev) {
  switch ((sev || '').toUpperCase()) {
    case 'ERROR': return vscode.DiagnosticSeverity.Error;
    case 'WARNING': return vscode.DiagnosticSeverity.Warning;
    case 'INFO': return vscode.DiagnosticSeverity.Information;
    default: return vscode.DiagnosticSeverity.Hint;
  }
}

function mapSeverity(rawSeverity) {
  switch (rawSeverity.toUpperCase()) {
    case 'ERROR': return 'High';
    case 'WARNING': return 'Medium';
    case 'INFO': return 'Info';
    default: return 'Unknown';
  }
}

function showVulnerabilityWebview(findings) {
  const panel = vscode.window.createWebviewPanel(
    'vulnerabilityReport',
    '🛡️ Vulnerability Report',
    vscode.ViewColumn.One,
    { enableScripts: true }
  );

  const content = findings.map((item, index) => {
    const severity = mapSeverity(item.extra?.severity || 'INFO');
    const line = item.start?.line || 0;
    const filePath = item.path.replace(/\\/g, '\\\\'); // Escape backslashes for JS string
    const checkId = item.check_id;
    const message = item.extra?.message || 'No message.';

    return `
      <div style="padding: 10px; border-bottom: 1px solid #ccc;">
        <h3>#${index + 1}: ${checkId}</h3>
        <p><strong>Severity:</strong> <span style="color: ${severity === 'High' ? 'red' : severity === 'Medium' ? 'orange' : 'blue'}">${severity}</span></p>
        <p><strong>Message:</strong> ${message}</p>
        <p><strong>File:</strong> ${filePath}</p>
        <p><strong>Line:</strong> ${line}</p>
        <button onclick="handleAutoFix('${filePath}', ${line})">🛠️ Auto Fix</button>
      </div>
    `;
  }).join('');

  const allFixButton = `<button id="fixAllBtn" style="margin: 10px 0; padding: 8px 12px;">🛠️ Fix All</button>`;

  panel.webview.html = `
    <!DOCTYPE html>
    <html lang="en">
    <head><meta charset="UTF-8"><title>Vulnerabilities</title></head>
    <body style="font-family: Arial, sans-serif; padding: 10px;">
      <h2>🔎 Detailed Vulnerabilities</h2>
      ${allFixButton}
      ${content}
      <script>
        const vscode = acquireVsCodeApi();
        function handleAutoFix(filePath, line) {
          vscode.postMessage({ command: 'autoFix', filePath, line });
        }
        document.getElementById('fixAllBtn').addEventListener('click', () => {
          vscode.postMessage({ command: 'fixAll' });
        });
      </script>
    </body>
    </html>
  `;

  panel.webview.onDidReceiveMessage(
    async (message) => {
      if (message.command === 'autoFix') {
        const { filePath, line } = message;
        vscode.window.showInformationMessage(`🔧 Running Auto-Fix on ${filePath} (line ${line})...`);

        const fixerScript = path.join(__dirname, 'fixer', 'autoFixer.js');
        exec(`node "${fixerScript}" "${filePath}" ${line}`, (error, stdout, stderr) => {
          if (error) {
            vscode.window.showErrorMessage(`❌ Fix failed: ${stderr || error.message}`);
          } else {
            vscode.window.showInformationMessage(`✅ Fix applied.`);
            // Optionally reload or refresh file in editor here
          }
        });
      } else if (message.command === 'fixAll') {
  const fixerScript = path.join(__dirname, 'fixer', 'autoFixer.js');
const folder = vscode.workspace.workspaceFolders?.[0]?.uri.fsPath;

exec(`node "${fixerScript}" --fix-all "${folder}"`, (error, stdout, stderr) => {
  if (error) {
    vscode.window.showErrorMessage(`❌ Fix All failed: ${stderr || error.message}`);
  } else {
    vscode.window.showInformationMessage(`✅ All vulnerabilities fixed.`);
  }
});
}

    },
    undefined,
    []
  );
}

function deactivate() {
  if (diagnosticsCollection) {
    diagnosticsCollection.dispose();
  }
  if (saveListener) {
    saveListener.dispose();
  }
}

module.exports = {
  activate,
  deactivate
};
