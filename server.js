
const http = require('node:http');
const fs = require('node:fs/promises');
const path = require('node:path');
const { randomUUID, randomBytes } = require('node:crypto');

const HOST = '0.0.0.0';
const PORT = Number(process.env.PORT) || 3000;

const ROOT = __dirname;
const DATA_FILE = path.join(ROOT, 'responses.json');
const MAX_BODY_BYTES = 20_000;

const FRONTEND_ORIGIN =
  'https://garhishyampurfeedbackform.netlify.app';

const ADMIN_USERNAME = 'Admin';
const ADMIN_PASSWORD = 'Admin';

const SESSION_LIFETIME_MS = 8 * 60 * 60 * 1000;

const validBranches = new Set([
  'Computer Science Engineering',
  'Civil Engineering',
  'Electrical Engineering'
]);

const ratingTopics = [
  'Classroom cleanliness',
  'Computer lab facilities',
  'Library resources',
  'Internet connectivity',
  'Drinking water and washrooms',
  'Canteen facilities',
  'Overall College Experience',
  'Overall satisfaction rating',
  'Academic support',
  'Campus environment',
  'Extracurricular activities',
  'Student-teacher interaction'
];

const sessions = new Map();
let mutations = Promise.resolve();

function serializeMutation(work) {
  const result = mutations.then(work, work);
  mutations = result.catch(() => {});
  return result;
}

async function readResponses() {
  try {
    const contents = await fs.readFile(DATA_FILE, 'utf8');
    const data = JSON.parse(contents);
    return Array.isArray(data) ? data : [];
  } catch (error) {
    if (error.code === 'ENOENT') return [];
    throw error;
  }
}

async function writeResponses(responses) {
  await fs.writeFile(
    DATA_FILE,
    JSON.stringify(responses, null, 2) + '\n',
    'utf8'
  );
}

function sendJson(response, statusCode, payload) {
  response.writeHead(statusCode, {
    'Content-Type': 'application/json; charset=utf-8',
    'Cache-Control': 'no-store',
    'X-Content-Type-Options': 'nosniff'
  });

  response.end(JSON.stringify(payload));
}

function setCorsHeaders(request, response) {
  const origin = request.headers.origin;

  if (origin === FRONTEND_ORIGIN) {
    response.setHeader('Access-Control-Allow-Origin', origin);
    response.setHeader('Access-Control-Allow-Credentials', 'true');
    response.setHeader(
      'Access-Control-Allow-Methods',
      'GET, POST, DELETE, OPTIONS'
    );
    response.setHeader(
      'Access-Control-Allow-Headers',
      'Content-Type'
    );
    response.setHeader('Vary', 'Origin');
  }
}

function getSessionId(request) {
  const cookies = request.headers.cookie || '';

  const cookie = cookies
    .split(';')
    .map(item => item.trim())
    .find(item => item.startsWith('feedback_admin_session='));

  if (!cookie) return '';

  try {
    return decodeURIComponent(
      cookie.slice('feedback_admin_session='.length)
    );
  } catch {
    return '';
  }
}

function isAdminAuthenticated(request) {
  const sessionId = getSessionId(request);
  const expiresAt = sessions.get(sessionId);

  if (!expiresAt) return false;

  if (expiresAt <= Date.now()) {
    sessions.delete(sessionId);
    return false;
  }

  return true;
}

function requireAdmin(request, response) {
  if (isAdminAuthenticated(request)) return true;

  sendJson(response, 401, {
    error: 'Please sign in as admin to manage responses.'
  });

  return false;
}

function readRequestBody(request) {
  return new Promise((resolve, reject) => {
    let body = '';
    let size = 0;
    let finished = false;

    request.on('data', chunk => {
      if (finished) return;

      size += chunk.length;

      if (size > MAX_BODY_BYTES) {
        finished = true;
        reject(new Error('Request is too large.'));
        request.resume();
        return;
      }

      body += chunk.toString('utf8');
    });

    request.on('end', () => {
      if (finished) return;

      try {
        resolve(JSON.parse(body));
      } catch {
        reject(new Error('Request must contain valid JSON.'));
      }
    });

    request.on('error', error => {
      if (!finished) reject(error);
    });
  });
}

function validateResponse(data) {
  if (!data || typeof data !== 'object' || Array.isArray(data)) {
    return 'Invalid feedback data.';
  }

  const requiredText = [
    'studentName',
    'email',
    'dob',
    'rollNumber'
  ];

  if (
    requiredText.some(
      key =>
        typeof data[key] !== 'string' ||
        !data[key].trim()
    )
  ) {
    return 'Please complete every required field.';
  }

  if (data.studentName.trim().length > 120) {
    return 'The name is too long.';
  }

  if (
    !data.ratings ||
    typeof data.ratings !== 'object' ||
    Array.isArray(data.ratings) ||
    ratingTopics.some(
      topic =>
        !Number.isInteger(data.ratings[topic]) ||
        data.ratings[topic] < 1 ||
        data.ratings[topic] > 5
    )
  ) {
    return 'Please provide a rating from 1 to 5 for every feedback item.';
  }

  if (
    !/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(data.email.trim())
  ) {
    return 'Enter a valid email address.';
  }

  if (!/^\d{11}$/.test(data.rollNumber)) {
    return 'Roll number must contain exactly 11 digits.';
  }

  if (!validBranches.has(data.branch)) {
    return 'Choose a valid branch.';
  }

  if (!['1', '2', '3', '4', '5', '6'].includes(String(data.semester))) {
    return 'Choose a valid semester.';
  }

  if (!['1st year', '2nd year', '3rd year'].includes(data.collegeYear)) {
    return 'Choose a valid college year.';
  }

  const dob = data.dob;
  const parsedDob = new Date(`${dob}T00:00:00.000Z`);

  if (
    !/^\d{4}-\d{2}-\d{2}$/.test(dob) ||
    Number.isNaN(parsedDob.valueOf()) ||
    parsedDob.toISOString().slice(0, 10) !== dob
  ) {
    return 'Enter a valid date of birth.';
  }

  if (dob > new Date().toISOString().slice(0, 10)) {
    return 'Date of birth cannot be in the future.';
  }

  return null;
}

function sendSessionCookie(response, sessionId, maxAge) {
  response.setHeader(
    'Set-Cookie',
    `feedback_admin_session=${encodeURIComponent(sessionId)}; HttpOnly; Secure; SameSite=None; Path=/; Max-Age=${maxAge}`
  );
}

async function serveFile(response, fileName, contentType) {
  try {
    const contents = await fs.readFile(path.join(ROOT, fileName));

    response.writeHead(200, {
      'Content-Type': contentType,
      'Cache-Control': 'no-store',
      'X-Content-Type-Options': 'nosniff'
    });

    response.end(contents);
  } catch {
    sendJson(response, 404, { error: 'Page not found.' });
  }
}

const server = http.createServer(async (request, response) => {
  setCorsHeaders(request, response);

  const origin = request.headers.origin;

  if (origin && origin !== FRONTEND_ORIGIN) {
    return sendJson(response, 403, {
      error: 'Origin not allowed.'
    });
  }

  if (request.method === 'OPTIONS') {
    if (origin !== FRONTEND_ORIGIN) {
      return sendJson(response, 403, {
        error: 'Origin not allowed.'
      });
    }

    response.writeHead(204);
    return response.end();
  }

  let pathname;

  try {
    pathname = decodeURIComponent(
      new URL(request.url, 'http://localhost').pathname
    );
  } catch {
    return sendJson(response, 400, { error: 'Invalid URL.' });
  }

  try {
    // Check admin login status
    if (pathname === '/api/auth' && request.method === 'GET') {
      return sendJson(response, 200, {
        authenticated: isAdminAuthenticated(request)
      });
    }

    // Admin login
    if (pathname === '/api/auth/login' && request.method === 'POST') {
      const credentials = await readRequestBody(request);

      if (
        !credentials ||
        credentials.username !== ADMIN_USERNAME ||
        credentials.password !== ADMIN_PASSWORD
      ) {
        return sendJson(response, 401, {
          error: 'Incorrect username or password.'
        });
      }

      const sessionId = randomBytes(32).toString('hex');

      sessions.set(
        sessionId,
        Date.now() + SESSION_LIFETIME_MS
      );

      sendSessionCookie(
        response,
        sessionId,
        SESSION_LIFETIME_MS / 1000
      );

      return sendJson(response, 200, {
        authenticated: true
      });
    }

    // Admin logout
    if (pathname === '/api/auth/logout' && request.method === 'POST') {
      sessions.delete(getSessionId(request));

      sendSessionCookie(response, '', 0);

      return sendJson(response, 200, {
        authenticated: false
      });
    }

    // Retrieve all feedback (admin only)
    if (pathname === '/api/responses' && request.method === 'GET') {
      if (!requireAdmin(request, response)) return;

      return sendJson(response, 200, await readResponses());
    }

    // Retrieve one feedback record (admin only)
    const responseMatch = pathname.match(
      /^\/api\/responses\/([0-9a-f-]+)$/i
    );

    if (responseMatch && request.method === 'GET') {
      if (!requireAdmin(request, response)) return;

      const record = (await readResponses()).find(
        item => item.id === responseMatch[1]
      );

      if (!record) {
        return sendJson(response, 404, {
          error: 'Response not found.'
        });
      }

      return sendJson(response, 200, record);
    }

    // Submit new feedback
    if (pathname === '/api/responses' && request.method === 'POST') {
      const data = await readRequestBody(request);
      const validationError = validateResponse(data);

      if (validationError) {
        return sendJson(response, 400, {
          error: validationError
        });
      }

      const record = {
        id: randomUUID(),
        studentName: data.studentName.trim(),
        branch: data.branch,
        semester: String(data.semester),
        collegeYear: data.collegeYear,
        email: data.email.trim(),
        dob: data.dob,
        rollNumber: data.rollNumber,
        ratings: data.ratings,
        submittedAt: new Date().toISOString()
      };

      await serializeMutation(async () => {
        const responses = await readResponses();
        responses.push(record);
        await writeResponses(responses);
      });

      return sendJson(response, 201, {
        message: 'Feedback saved.',
        id: record.id
      });
    }

    // Delete all feedback (admin only)
    if (pathname === '/api/responses' && request.method === 'DELETE') {
      if (!requireAdmin(request, response)) return;

      await serializeMutation(() => writeResponses([]));

      return sendJson(response, 200, {
        message: 'All feedback was deleted.'
      });
    }

    // Delete one feedback record (admin only)
    const deleteMatch = pathname.match(
      /^\/api\/responses\/([0-9a-f-]+)$/i
    );

    if (deleteMatch && request.method === 'DELETE') {
      if (!requireAdmin(request, response)) return;

      let deleted = false;

      await serializeMutation(async () => {
        const responses = await readResponses();

        const remaining = responses.filter(
          item => item.id !== deleteMatch[1]
        );

        deleted = remaining.length !== responses.length;

        if (deleted) {
          await writeResponses(remaining);
        }
      });

      return sendJson(response, deleted ? 200 : 404, {
        message: deleted
          ? 'Feedback deleted.'
          : 'Response not found.'
      });
    }

    // Optional pages if hosted alongside server.js
    if (request.method === 'GET') {
      const staticFiles = {
        '/': ['index.html', 'text/html; charset=utf-8'],
        '/index.html': ['index.html', 'text/html; charset=utf-8'],
        '/admin': ['admin.html', 'text/html; charset=utf-8'],
        '/admin.html': ['admin.html', 'text/html; charset=utf-8'],
        '/pdf-preview': ['pdf-preview.html', 'text/html; charset=utf-8'],
        '/pdf-preview.html': ['pdf-preview.html', 'text/html; charset=utf-8'],
        '/remark-preview': ['remark-preview.html', 'text/html; charset=utf-8'],
        '/remark-preview.html': ['remark-preview.html', 'text/html; charset=utf-8'],
        '/Logo.jpg': ['Logo.jpg', 'image/jpeg'],
        '/Background.jpeg': ['Background.jpeg', 'image/jpeg']
      };

      if (staticFiles[pathname]) {
        const [fileName, contentType] = staticFiles[pathname];
        return serveFile(response, fileName, contentType);
      }
    }

    return sendJson(response, 404, { error: 'Not found.' });
  } catch (error) {
    console.error('Request error:', error);

    if (!response.headersSent) {
      const status = error.message === 'Request is too large.' ? 413 : 400;

      return sendJson(response, status, {
        error: status === 413
          ? 'Request is too large.'
          : 'The request could not be processed.'
      });
    }

    response.end();
  }
});

server.listen(PORT, HOST, () => {
  console.log(`Feedback backend listening on port ${PORT}`);
  console.log(`Allowed frontend: ${FRONTEND_ORIGIN}`);
});
