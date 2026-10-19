const http = require('node:http');
const fs = require('node:fs/promises');
const path = require('node:path');
const { randomUUID, randomBytes } = require('node:crypto');

const HOST = '127.0.0.1';
const PORT = Number(process.env.PORT) || 3000;
const ROOT = __dirname;
const DATA_FILE = path.join(ROOT, 'responses.json');
const MAX_BODY_BYTES = 20_000;
const validBranches = new Set([
  'Computer Science Engineering',
  'Civil Engineering',
  'Electrical Engineering'
]);
const sessions = new Map();
const SESSION_LIFETIME_MS = 8 * 60 * 60 * 1000;

let mutations = Promise.resolve();

function serializeMutation(work) {
  const result = mutations.then(work, work);
  mutations = result.catch(() => {});
  return result;
}

async function readResponses() {
  try {
    const contents = await fs.readFile(DATA_FILE, 'utf8');
    const responses = JSON.parse(contents);
    return Array.isArray(responses) ? responses : [];
  } catch (error) {
    if (error.code === 'ENOENT') return [];
    throw error;
  }
}

async function writeResponses(responses) {
  await fs.writeFile(DATA_FILE, `${JSON.stringify(responses, null, 2)}\n`, 'utf8');
}

function sendJson(response, statusCode, payload) {
  response.writeHead(statusCode, {
    'Content-Type': 'application/json; charset=utf-8',
    'Cache-Control': 'no-store',
    'X-Content-Type-Options': 'nosniff'
  });
  response.end(JSON.stringify(payload));
}

function getSessionId(request) {
  const cookieHeader = request.headers.cookie || '';
  const sessionCookie = cookieHeader.split(';').map((item) => item.trim()).find((item) => item.startsWith('feedback_admin_session='));
  return sessionCookie ? decodeURIComponent(sessionCookie.slice('feedback_admin_session='.length)) : '';
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
  sendJson(response, 401, { error: 'Please sign in as admin to manage responses.' });
  return false;
}

function readRequestBody(request) {
  return new Promise((resolve, reject) => {
    let body = '';
    request.on('data', (chunk) => {
      body += chunk;
      if (Buffer.byteLength(body, 'utf8') > MAX_BODY_BYTES) {
        reject(new Error('Request is too large.'));
        request.destroy();
      }
    });
    request.on('end', () => {
      try {
        resolve(JSON.parse(body));
      } catch {
        reject(new Error('Request must contain valid JSON.'));
      }
    });
    request.on('error', reject);
  });
}

function validateResponse(data) {
  if (!data || typeof data !== 'object' || Array.isArray(data)) return 'Invalid feedback data.';
  const ratingTopics = [
    'Classroom cleanliness', 'Computer lab facilities', 'Library resources',
    'Internet connectivity', 'Drinking water and washrooms', 'Canteen facilities',
    'Overall College Experience', 'Overall satisfaction rating', 'Academic support',
    'Campus environment', 'Extracurricular activities', 'Student-teacher interaction'
  ];
  const requiredText = ['studentName', 'email', 'dob', 'rollNumber'];
  if (requiredText.some((key) => typeof data[key] !== 'string' || !data[key].trim())) {
    return 'Please complete every required field.';
  }
  if (data.studentName.trim().length > 120) return 'The name is too long.';
  if (!data.ratings || typeof data.ratings !== 'object' || Array.isArray(data.ratings)
    || ratingTopics.some((topic) => !Number.isInteger(data.ratings[topic]) || data.ratings[topic] < 1 || data.ratings[topic] > 5)) {
    return 'Please provide a star rating from 1 to 5 for every college feedback item.';
  }
  if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(data.email.trim())) return 'Enter a valid email address.';
  if (!/^\d{11}$/.test(data.rollNumber)) return 'Roll number must contain exactly 11 digits.';
  if (!validBranches.has(data.branch)) return 'Choose a valid branch.';
  if (!['1', '2', '3', '4', '5', '6'].includes(String(data.semester))) return 'Choose a valid semester.';
  if (!['1st year', '2nd year', '3rd year'].includes(String(data.collegeYear))) return 'Choose a valid college year.';
  const parsedDob = new Date(`${data.dob}T00:00:00.000Z`);
  if (!/^\d{4}-\d{2}-\d{2}$/.test(data.dob) || Number.isNaN(parsedDob.valueOf()) || parsedDob.toISOString().slice(0, 10) !== data.dob) {
    return 'Enter a valid date of birth.';
  }
  if (data.dob > new Date().toISOString().slice(0, 10)) return 'Date of birth cannot be in the future.';
  return null;
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
  const url = new URL(request.url, `http://${HOST}:${PORT}`);
  const pathname = decodeURIComponent(url.pathname);

  try {
    if (pathname === '/api/auth' && request.method === 'GET') {
      return sendJson(response, 200, { authenticated: isAdminAuthenticated(request) });
    }

    if (pathname === '/api/auth/login' && request.method === 'POST') {
      const credentials = await readRequestBody(request);
      if (credentials.username !== 'Admin' || credentials.password !== 'Admin') {
        return sendJson(response, 401, { error: 'Incorrect username or password.' });
      }
      const sessionId = randomBytes(32).toString('hex');
      sessions.set(sessionId, Date.now() + SESSION_LIFETIME_MS);
      response.writeHead(200, {
        'Content-Type': 'application/json; charset=utf-8',
        'Cache-Control': 'no-store',
        'Set-Cookie': `feedback_admin_session=${sessionId}; HttpOnly; SameSite=Strict; Path=/; Max-Age=${SESSION_LIFETIME_MS / 1000}`,
        'X-Content-Type-Options': 'nosniff'
      });
      return response.end(JSON.stringify({ authenticated: true }));
    }

    if (pathname === '/api/auth/logout' && request.method === 'POST') {
      sessions.delete(getSessionId(request));
      response.writeHead(200, {
        'Content-Type': 'application/json; charset=utf-8',
        'Cache-Control': 'no-store',
        'Set-Cookie': 'feedback_admin_session=; HttpOnly; SameSite=Strict; Path=/; Max-Age=0',
        'X-Content-Type-Options': 'nosniff'
      });
      return response.end(JSON.stringify({ authenticated: false }));
    }

    if (request.method === 'GET' && pathname === '/api/responses') {
      if (!requireAdmin(request, response)) return;
      return sendJson(response, 200, await readResponses());
    }

    const responseMatch = pathname.match(/^\/api\/responses\/([0-9a-f-]+)$/i);
    if (request.method === 'GET' && responseMatch) {
      if (!requireAdmin(request, response)) return;
      const record = (await readResponses()).find((item) => item.id === responseMatch[1]);
      return record
        ? sendJson(response, 200, record)
        : sendJson(response, 404, { error: 'Response not found.' });
    }

    if (request.method === 'POST' && pathname === '/api/responses') {
      const data = await readRequestBody(request);
      const validationError = validateResponse(data);
      if (validationError) return sendJson(response, 400, { error: validationError });
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
      return sendJson(response, 201, { message: 'Feedback saved.', id: record.id });
    }

    if (request.method === 'DELETE' && pathname === '/api/responses') {
      if (!requireAdmin(request, response)) return;
      await serializeMutation(() => writeResponses([]));
      return sendJson(response, 200, { message: 'All feedback was deleted.' });
    }

    const deleteMatch = pathname.match(/^\/api\/responses\/([0-9a-f-]+)$/i);
    if (request.method === 'DELETE' && deleteMatch) {
      if (!requireAdmin(request, response)) return;
      let deleted = false;
      await serializeMutation(async () => {
        const responses = await readResponses();
        const remaining = responses.filter((record) => record.id !== deleteMatch[1]);
        deleted = remaining.length !== responses.length;
        if (deleted) await writeResponses(remaining);
      });
      return sendJson(response, deleted ? 200 : 404, { message: deleted ? 'Feedback deleted.' : 'Response not found.' });
    }

    if (request.method === 'GET' && (pathname === '/' || pathname === '/index.html')) {
      return serveFile(response, 'index.html', 'text/html; charset=utf-8');
    }
    if (request.method === 'GET' && (pathname === '/admin' || pathname === '/admin.html')) {
      return serveFile(response, 'admin.html', 'text/html; charset=utf-8');
    }
    if (request.method === 'GET' && (pathname === '/pdf-preview' || pathname === '/pdf-preview.html')) {
      return serveFile(response, 'pdf-preview.html', 'text/html; charset=utf-8');
    }
    if (request.method === 'GET' && (pathname === '/remark-preview' || pathname === '/remark-preview.html')) {
      return serveFile(response, 'remark-preview.html', 'text/html; charset=utf-8');
    }
    if (request.method === 'GET' && pathname === '/Logo.jpg') {
      return serveFile(response, 'Logo.jpg', 'image/jpeg');
    }
    if (request.method === 'GET' && pathname === '/Background.jpeg') {
      return serveFile(response, 'Background.jpeg', 'image/jpeg');
    }

    sendJson(response, 404, { error: 'Not found.' });
  } catch (error) {
    if (!response.headersSent) sendJson(response, 500, { error: error.message || 'Server error.' });
    else response.end();
  }
});

server.listen(PORT, HOST, () => {
  console.log(`Feedback form: http://${HOST}:${PORT}`);
  console.log(`Admin responses: http://${HOST}:${PORT}/admin`);
  console.log(`Saved data file: ${DATA_FILE}`);
  console.log('Local-only server: it is not accessible from other computers on the network.');
});
