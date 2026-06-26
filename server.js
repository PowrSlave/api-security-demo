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

const express    = require('express');
const jwt        = require('jsonwebtoken');
const mongoose   = require('mongoose');
const crypto     = require('crypto');
const path       = require('path');
const fs         = require('fs');
const { exec }   = require('child_process');
const axios      = require('axios');
const serialize  = require('node-serialize');
const _          = require('lodash');
const bodyParser = require('body-parser');
const cors       = require('cors');

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
