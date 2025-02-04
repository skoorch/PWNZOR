// Focus specifically on paths that could potentially be backdoored
const securityChecks = {
  exposedFiles: [
    // Development files that could enable backdoors
    '/.git/config',
    '/.svn/entries',
    '/.env',
    '/.env.local',
    '/.env.development',
    '/config.php',
    '/wp-config.php',
    '/configuration.php',
    
    // Upload functionality
    '/upload.php',
    '/upload/',
    '/uploads/',
    '/filemanager/',
    '/connector.php',
    
    // Admin interfaces
    '/wp-admin',
    '/administrator',
    '/admin',
    '/phpmyadmin',
    '/myadmin',
    
    // Development tools
    '/phpinfo.php',
    '/test.php',
    '/dev.php',
    '/development.php',
    '/staging/',
    
    // Backup files
    '/backup/',
    '/backups/',
    '/bak/',
    '/.bak',
    '/backup.zip',
    '/backup.sql',
    
    // Shell access
    '/shell.php',
    '/cmd.php',
    '/command.php',
    '/c99.php',
    '/r57.php',
    
    // Log files
    '/error_log',
    '/error.log',
    '/debug.log',
    '/access.log',
    
    // Common vulnerable components
    '/setup/',
    '/install/',
    '/install.php',
    '/web.config',
    '/.htaccess',
    '/cgi-bin/',
    
    // Additional backdoorable vectors
    '/xmlrpc.php',
    '/api/',
    '/graphql',
    '/api/v1',
    '/api/v2',
    '/api/swagger',
    '/swagger-ui.html',
    '/v1/api-docs',
    '/composer.json',
    '/package.json',
    '/yarn.lock',
    '/npm-debug.log',
    
    // CMS specific
    '/includes/',
    '/vendor/',
    '/node_modules/',
    '/plugins/',
    '/modules/',
    '/themes/',
    '/templates/',
    '/assets/plugins/',
    '/assets/uploads/',
    
    // Legacy and backup files
    '/.old',
    '/.orig',
    '/.backup',
    '/.save',
    '/.swp',
    '/.swap',
    '/.copy',
    '~',
    '.tmp',
    
    // Config files
    '/config/',
    '/conf/',
    '/settings/',
    '/settings.php',
    '/options.php',
    '/database.php',
    '/db.php',
    
    // Debug endpoints
    '/debug/',
    '/trace',
    '/status',
    '/server-status',
    '/server-info',
    
    // Common CMS admin paths
    '/administrator/index.php',
    '/admin/login.php',
    '/admin/admin.php',
    '/admin/config.php',
    '/admin/includes/',
    '/cms/admin/',
    '/backend/',
    '/manage/',
    
    // Development files
    '/dev/',
    '/development/',
    '/test/',
    '/testing/',
    '/staging/',
    '/beta/',
    
    // File managers
    '/elfinder/',
    '/tinymce/',
    '/kcfinder/',
    '/ckeditor/',
    '/resources/',
    
    // Common vulnerable scripts
    '/cgi-bin/test-cgi',
    '/cgi-sys/defaultwebpage.cgi',
    '/cgi-mod/',
    '/cgi-bin/php',
    '/cgi-bin/php5',
    '/cgi-bin/bash',
    
    // Server configuration
    '/.htpasswd',
    '/web.config.txt',
    '/.user.ini',
    '/php.ini',
    '/nginx.conf',
    
    // Logs and reports
    '/logs/',
    '/log/',
    '/reports/',
    '/errors/',
    '/tmp/',
    '/temp/',
    
    // Additional uncommon backdoor vectors
    
    // Development artifacts
    '/.vscode/settings.json',
    '/.idea/workspace.xml', 
    '/nbproject/private/',
    '/.project',
    '/.buildpath',
    '/.settings/',
    
    // Build tools and CI/CD
    '/.gitlab-ci.yml',
    '/.github/workflows/',
    '/Jenkinsfile',
    '/.drone.yml',
    '/bamboo-specs/',
    
    // Framework specific
    '/artisan',
    '/craft',
    '/console',
    '/yii',
    '/app_dev.php',
    '/index_dev.php',
    '/core/install.php',
    
    // Cache and temp files
    '/.sass-cache/',
    '/.cache/',
    '/var/cache/',
    '/var/log/',
    '/var/session/',
    
    // Config management
    '/puppet/',
    '/chef/',
    '/ansible/',
    '/terraform/',
    '/.terraform/',
    
    // Container files
    '/docker-compose.yml',
    '/Dockerfile',
    '/.dockerignore',
    '/kubernetes/',
    '/helm/',
    
    // Service configs
    '/.aws/',
    '/.azure/',
    '/.gcp/',
    '/.ssh/',
    '/.gnupg/',
    
    // VCS alternate
    '/.bzr/',
    '/.hg/',
    '/CVS/',
    '/.svnignore',
    
    // Package managers
    '/bower_components/',
    '/jspm_packages/',
    '/yarn-error.log',
    '/poetry.lock',
    '/Gemfile.lock',
    
    // IDE and editor files
    '*.swp',
    '*.swo',
    '*.swn',
    '*.bak',
    '*~.nib',
    
    // Database files
    '/*.sqlite',
    '/*.sqlite3',
    '/*.db',
    '/*.sql',
    '/*.mysql',
    
    // Config management 
    '/salt/',
    '/pillar/',
    '/group_vars/',
    '/host_vars/',
    '/inventory/',
    
    // Service workers
    '/sw.js',
    '/worker.js',
    '/service-worker.js',
    '/workbox-*.js',
    
    // Debug endpoints
    '/_profiler/',
    '/_wdt/',
    '/_errors/',
    '/debug/default/',
    '/debug/toolbar/',
    
    // Alternative admin paths
    '/management/',
    '/console/',
    '/supervisor/',
    '/control/',
    '/master/',
    
    // Monitoring
    '/monitor/',
    '/munin/',
    '/nagios/',
    '/zabbix/',
    
    // Alternative upload paths
    '/files/',
    '/download/',
    '/dl/',
    '/file/',
    '/storage/',
    
    // Task runners
    '/cron.php',
    '/scheduled.php',
    '/tasks.php',
    '/jobs.php',
    '/queue.php',
    
    // Alternative shells
    '/remote.php',
    '/gate.php',
    '/tunnel.php',
    '/proxy.php',
    '/bridge.php',
    
    // Less common file extensions
    '/*.jsp',
    '/*.aspx',
    '/*.jspx',
    '/*.cshtml',
    '/*.vbhtml',
    
    // Framework debug modes
    '/app_dev.php',
    '/index_dev.php',
    '/debug.php',
    '/dev.php',
    '/development.php',
    
    // Memory dumps and core files
    '/core',
    '/core.*',
    '/*.core',
    '/dump',
    '/memory.dmp',
    
    // Alternative web shells
    '*.php.jpg',
    '*.php.png',
    '*.php.gif',
    '*.asp.jpg',
    '*.aspx.jpg',
    '/images/*.php',
    '/img/*.php',
    '/media/*.php',
    
    // Obfuscated names
    '/x.php',
    '/xx.php',
    '/1.php',
    '/2.php',
    '/a.php',
    '/z.php',
    '/cmd.aspx',
    '/c.asp',
    
    // Hidden directories
    '/.hidden/',
    '/.secret/',
    '/.private/',
    '/.admin/',
    '/.config/',
    
    // Server-side includes
    '/*.shtml',
    '/*.shtm',
    '/*.stm',
    '/*.inc',
    
    // Alternative file extensions
    '/*.php3',
    '/*.php4',
    '/*.php5',
    '/*.php7',
    '/*.phtml',
    '/*.shtml',
    '/*.cgi',
    '/*.pl',
    '/*.py',
    '/*.rb',
    
    // Framework backdoors
    '/routes.php',
    '/router.php',
    '/config.routes.php',
    '/middleware.php',
    '/filters.php',
    '/handlers.php',
    '/processors.php',
    
    // Plugin/module backdoors
    '/modules/*/includes/',
    '/plugins/*/includes/',
    '/extensions/*/includes/',
    '/add-ons/*/includes/',
    
    // Hidden functionality
    '/_admin',
    '/_administrator',
    '/_manage',
    '/_management',
    '/_debug',
    
    // Reverse shells
    '/reverse.php',
    '/connect.php',
    '/connector.php',
    '/tunnel.php',
    '/gate.php',
    
    // Alternative admin panels
    '/moderator/',
    '/webmaster/',
    '/controlpanel/',
    '/cpanel/',
    '/dashboard/',
    
    // Service endpoints
    '/soap/',
    '/api/soap/',
    '/api/rest/',
    '/api/v3/',
    '/api/debug/',
    
    // Development endpoints
    '/dev/console/',
    '/dev/debug/',
    '/dev/null/',
    '/dev/random/',
    
    // Temporary files
    '/*.tmp',
    '/*.temp',
    '/*.bak',
    '/*.old',
    '/*.backup',
    
    // Alternative data stores
    '/*.sqlite',
    '/*.db',
    '/*.mdb',
    '/*.accdb',
    
    // Application specific
    '/wp-content/upgrade/',
    '/wp-content/backup-db/',
    '/wp-content/uploads/backups/',
    '/wp-snapshots/',
    
    // CMS specific paths
    '/administrator/backups/',
    '/administrator/components/',
    '/administrator/modules/',
    '/administrator/templates/',
    
    // Framework debug
    '/application/logs/',
    '/application/cache/',
    '/application/config/',
    '/application/third_party/',
    
    // Cloud storage
    '/.s3cfg',
    '/.boto',
    '/.gsutil/',
    
    // CI/CD artifacts
    '/builds/',
    '/releases/',
    '/artifacts/',
    '/pipelines/',
    
    // Custom frameworks
    '/custom/',
    '/customizations/',
    '/modifications/',
    '/overrides/',
    
    // Unusual file types
    '/*.war',
    '/*.jar',
    '/*.class',
    '/*.dll',
    '/*.so',
    
    // Remote management
    '/remote/',
    '/remote.php',
    '/remote.aspx',
    '/remote.jsp'
  ]
};

const riskLevels = {
  CRITICAL: { color: '#ff0000', label: 'Critical Risk' },
  HIGH: { color: '#ff4444', label: 'High Risk' },
  MEDIUM: { color: '#ffbb33', label: 'Medium Risk' },
  LOW: { color: '#00C851', label: 'Low Risk' }
};

const vulnerabilityDescriptions = {
  '/.git/config': {
    risk: 'CRITICAL',
    title: 'Git Repository Exposure',
    description: 'Git repository files are publicly accessible',
    impact: 'Enables source code access and potential backdoor insertion through deployment process manipulation',
    recommendation: 'Remove .git directory from public access and implement proper deployment security controls'
  },
  '/upload.php': {
    risk: 'CRITICAL',
    title: 'Unrestricted File Upload',
    description: 'File upload functionality potentially accessible',
    impact: 'Could allow upload of malicious files enabling system compromise',
    recommendation: 'Implement strict file upload validation, authentication, and access controls'
  },
  '/phpinfo.php': {
    risk: 'HIGH',
    title: 'PHP Information Exposure',
    description: 'Server configuration information exposed',
    impact: 'Reveals system details that could aid in backdoor placement',
    recommendation: 'Remove or restrict access to sensitive configuration files'
  },
  '/.env': {
    risk: 'CRITICAL',
    title: 'Environment File Exposure',
    description: 'Configuration file containing sensitive credentials exposed',
    impact: 'Direct access to database and system credentials enabling full compromise',
    recommendation: 'Move all .env files outside web root and implement proper access controls'
  },
  '/shell.php': {
    risk: 'CRITICAL',
    title: 'Web Shell Detection',
    description: 'Potential command execution interface detected',
    impact: 'Allows direct system command execution and persistent access',
    recommendation: 'Remove unauthorized shell scripts and implement file monitoring'
  },
  '/backup': {
    risk: 'HIGH',
    title: 'Backup Files Exposed',
    description: 'System backup files potentially accessible',
    impact: 'Could contain sensitive data and configuration enabling system compromise',
    recommendation: 'Move backups to secure offline storage and implement access controls'
  },
  '/wp-config.php': {
    risk: 'CRITICAL',
    title: 'WordPress Configuration Exposed',
    description: 'WordPress configuration file potentially accessible',
    impact: 'Contains database credentials and security keys enabling system compromise',
    recommendation: 'Move configuration file outside web root and implement proper permissions'
  },
  '/xmlrpc.php': {
    risk: 'HIGH',
    title: 'XML-RPC Interface Exposed',
    description: 'XML-RPC interface potentially accessible for exploitation',
    impact: 'Could enable brute force attacks and remote code execution',
    recommendation: 'Disable XML-RPC if not needed or implement strict access controls'
  },
  '/graphql': {
    risk: 'HIGH',
    title: 'GraphQL Endpoint Exposed',
    description: 'GraphQL API endpoint potentially accessible',
    impact: 'Could enable data extraction and injection attacks',
    recommendation: 'Implement proper authentication and query depth limiting'
  },
  '/vendor/': {
    risk: 'MEDIUM',
    title: 'Vendor Directory Exposed',
    description: 'Third-party component directory accessible',
    impact: 'Could reveal vulnerable dependencies for exploitation',
    recommendation: 'Move vendor directory outside web root'
  },
  '/nginx.conf': {
    risk: 'CRITICAL',
    title: 'Server Configuration Exposed',
    description: 'Web server configuration file accessible',
    impact: 'Reveals server structure and potential security controls',
    recommendation: 'Remove configuration files from public access'
  },
  '/cgi-bin/': {
    risk: 'CRITICAL',
    title: 'CGI Scripts Exposed',
    description: 'Common Gateway Interface scripts accessible',
    impact: 'Potential for remote code execution through CGI vulnerabilities',
    recommendation: 'Disable unnecessary CGI scripts and implement access controls'
  }
};

Object.assign(vulnerabilityDescriptions, {
  '/.vscode/settings.json': {
    risk: 'HIGH',
    title: 'IDE Configuration Exposed',
    description: 'VSCode configuration files accessible',
    impact: 'Could reveal project structure and sensitive paths',
    recommendation: 'Remove IDE configuration files from production'
  },
  '/docker-compose.yml': {
    risk: 'CRITICAL',
    title: 'Container Configuration Exposed',
    description: 'Docker composition file accessible',
    impact: 'Reveals service structure and potential entry points',
    recommendation: 'Remove container configuration from public access'
  },
  '/.aws/': {
    risk: 'CRITICAL',
    title: 'Cloud Credentials Exposed',
    description: 'AWS configuration directory accessible',
    impact: 'Could expose cloud service credentials',
    recommendation: 'Never store cloud credentials in web root'
  },
  '/debug/': {
    risk: 'HIGH',
    title: 'Debug Endpoint Exposed',
    description: 'Application debug interface accessible',
    impact: 'Could enable system introspection and code execution',
    recommendation: 'Disable debug endpoints in production'
  }
});

// Initialize the paths list with descriptions
window.onload = () => {
  const pathsList = document.getElementById('paths-list');
  securityChecks.exposedFiles.forEach(path => {
    const li = document.createElement('li');
    const vuln = vulnerabilityDescriptions[path] || {
      risk: 'HIGH',
      title: 'Potential Backdoor Vector',
      description: 'This path could potentially be used for unauthorized access',
      impact: 'Could enable system compromise or backdoor placement',
      recommendation: 'Review access controls and remove if unnecessary'
    };
    
    li.innerHTML = `
      <span class="path-text">${path}</span>
      <span class="risk-level" style="color: ${riskLevels[vuln.risk].color}">${riskLevels[vuln.risk].label}</span>
      <span class="path-description">${vuln.description}</span>
    `;
    pathsList.appendChild(li);
  });
};

async function checkPath(baseUrl, path) {
  const checks = [
    { method: 'HEAD' },
    { method: 'GET' },
    { method: 'OPTIONS' },
    { 
      method: 'GET',
      headers: { 'X-Requested-With': 'XMLHttpRequest' }
    },
    {
      method: 'GET',
      headers: { 'Accept': 'application/json' }
    }
  ];

  for (const check of checks) {
    try {
      const response = await fetch(baseUrl + path, {
        method: check.method,
        mode: 'cors',
        headers: {
          ...check.headers,
          'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8'
        }
      });

      if (response.ok || response.status === 403) {  // 403 might indicate protected resource
        return {
          exists: true,
          status: response.status,
          method: check.method
        };
      }
    } catch (error) {
      console.debug(`${check.method} check failed for ${path}:`, error);
    }
  }

  // Fallback to proxy-based checking
  try {
    const proxyUrl = `https://api.allorigins.win/get?url=${encodeURIComponent(baseUrl + path)}`;
    const proxyResponse = await fetch(proxyUrl);
    const data = await proxyResponse.json();
    
    return {
      exists: data.status.http_code < 400 || data.status.http_code === 403,
      status: data.status.http_code,
      method: 'PROXY'
    };
  } catch (error) {
    console.debug(`Proxy check failed for ${path}:`, error);
    return {
      exists: false,
      status: 0,
      error: error.message
    };
  }
}

function addFinding(findings, vuln) {
  const finding = document.createElement('div');
  finding.className = 'finding';
  finding.style.borderLeftColor = riskLevels[vuln.risk].color;
  
  finding.innerHTML = `
    <div class="finding-header">
      <span class="finding-title">${vuln.title}</span>
      <span class="risk-badge" style="background: ${riskLevels[vuln.risk].color}">${riskLevels[vuln.risk].label}</span>
    </div>
    <div class="finding-description">${vuln.description}</div>
    <div class="finding-impact">Backdoor Risk: ${vuln.impact}</div>
    <div class="finding-recommendation">Recommendation: ${vuln.recommendation}</div>
  `;
  
  findings.appendChild(finding);
}

async function startScan() {
  const urlInput = document.getElementById('target-url');
  const progress = document.getElementById('scan-progress');
  const status = document.getElementById('status');
  const findings = document.getElementById('findings');
  const scanBtn = document.getElementById('scan-btn');
  const disclaimer = document.getElementById('disclaimer');
  const totalVectorsElement = document.getElementById('total-vectors');
  const foundVectorsElement = document.getElementById('found-vectors');
  const riskScoreElement = document.getElementById('risk-score');
  
  disclaimer.style.display = 'block';
  findings.innerHTML = '';
  
  let targetUrl = urlInput.value.trim();
  if (!targetUrl.startsWith('http')) {
    targetUrl = 'https://' + targetUrl;
  }
  
  // Validate URL
  try {
    new URL(targetUrl);
  } catch {
    status.textContent = 'Invalid URL provided';
    return;
  }

  // Validate domain
  const urlObj = new URL(targetUrl);
  if (!urlObj.hostname.includes('.')) {
    status.textContent = 'Invalid domain provided';
    return;
  }

  progress.style.width = '0%';
  scanBtn.disabled = true;
  status.textContent = 'Scanning for potential backdoor vectors...';
  
  const vulnerabilities = [];
  const totalChecks = securityChecks.exposedFiles.length;
  let completedChecks = 0;
  let riskScore = 0;

  // Update total vectors immediately
  totalVectorsElement.textContent = totalChecks;
  foundVectorsElement.textContent = '0';
  riskScoreElement.textContent = '0';

  // Batch process checks to avoid overwhelming the server
  const BATCH_SIZE = 5;
  for (let i = 0; i < securityChecks.exposedFiles.length; i += BATCH_SIZE) {
    const batch = securityChecks.exposedFiles.slice(i, i + BATCH_SIZE);
    const batchResults = await Promise.all(
      batch.map(async path => {
        const result = await checkPath(targetUrl, path);
        completedChecks++;
        progress.style.width = `${(completedChecks / totalChecks) * 100}%`;
        return { path, result };
      })
    );

    // Process batch results
    for (const { path, result } of batchResults) {
      if (result.exists) {
        const vuln = vulnerabilityDescriptions[path] || {
          risk: 'HIGH',
          title: `Potential Backdoor Vector: ${path}`,
          description: `Path ${path} is accessible (Status: ${result.status})`,
          impact: 'Could enable unauthorized system access or backdoor placement',
          recommendation: 'Review access controls and remove if unnecessary'
        };
        vulnerabilities.push(path);
        
        // Calculate risk score based on vulnerability risk level
        switch(vuln.risk) {
          case 'CRITICAL':
            riskScore += 10;
            break;
          case 'HIGH':
            riskScore += 7;
            break;
          case 'MEDIUM':
            riskScore += 4;
            break;
          case 'LOW':
            riskScore += 1;
            break;
        }
        
        // Update found vectors and risk score in real-time
        foundVectorsElement.textContent = vulnerabilities.length;
        riskScoreElement.textContent = Math.min(100, riskScore);
        
        addFinding(findings, vuln);
      }
    }

    // Add small delay between batches to be nice to servers
    await new Promise(resolve => setTimeout(resolve, 500));
  }

  progress.style.width = '100%';
  scanBtn.disabled = false;
  
  if (vulnerabilities.length === 0) {
    status.textContent = 'Scan complete. No obvious backdoor vectors found.';
    findings.innerHTML += '<div class="secure-message">No common backdoor vectors detected. Continue monitoring for unauthorized changes.</div>';
  } else {
    status.textContent = `Scan complete. Found ${vulnerabilities.length} potential backdoor vectors to review.`;
  }
  
  // Final stats update
  totalVectorsElement.textContent = totalChecks;
  foundVectorsElement.textContent = vulnerabilities.length;
  riskScoreElement.textContent = Math.min(100, riskScore);
}

// Add error handling for the entire script
window.onerror = function(msg, url, lineNo, columnNo, error) {
  const status = document.getElementById('status');
  status.textContent = 'An error occurred during scanning. Please try again.';
  console.error('Error: ', msg, url, lineNo, columnNo, error);
  return false;
};
