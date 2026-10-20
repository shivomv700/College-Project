
"use strict";

const http = require("http");
const fs = require("fs");
const path = require("path");
const crypto = require("crypto");

// ---------- Configuration ----------

const PORT = Number(process.env.PORT) || 3000;
const HOST = "0.0.0.0";

const ALLOWED_ORIGIN =
  "https://garhishyampurfeedbackform.netlify.app";

const ADMIN_USERNAME = process.env.ADMIN_USERNAME || "Admin";
const ADMIN_PASSWORD = process.env.ADMIN_PASSWORD || "Admin";

const DATA_FILE = path.join(__dirname, "responses.json");

const SESSION_COOKIE = "feedback_admin_session";
const SESSION_DURATION = 8 * 60 * 60 * 1000; // 8 hours
const MAX_BODY_SIZE = 1024 * 1024; // 1 MB

// In-memory sessions. Sessions are cleared when the server restarts.
const sessions = new Map();

// ---------- JSON and response helpers ----------

function sendJSON(res, statusCode, data) {
  res.writeHead(statusCode, {
    "Content-Type": "application/json; charset=utf-8",
    "Cache-Control": "no-store"
  });

  res.end(JSON.stringify(data));
}

function sendText(res, statusCode, message) {
  res.writeHead(statusCode, {
    "Content-Type": "text/plain; charset=utf-8",
    "Cache-Control": "no-store"
  });

  res.end(message);
}

// ---------- CORS ----------

function applyCors(req, res) {
  const origin = req.headers.origin;

  if (origin && origin !== ALLOWED_ORIGIN) {
    return false;
  }

  if (origin === ALLOWED_ORIGIN) {
    res.setHeader("Access-Control-Allow-Origin", ALLOWED_ORIGIN);
    res.setHeader("Access-Control-Allow-Credentials", "true");
    res.setHeader(
      "Access-Control-Allow-Methods",
      "GET, POST, DELETE, OPTIONS"
    );
    res.setHeader(
      "Access-Control-Allow-Headers",
      "Content-Type"
    );
    res.setHeader("Vary", "Origin");
  }

  return true;
}

// ---------- Request body ----------

function readJSON(req) {
  return new Promise((resolve, reject) => {
    let body = "";
    let tooLarge = false;

    req.on("data", chunk => {
      if (tooLarge) return;

      body += chunk.toString();

      if (Buffer.byteLength(body, "utf8") > MAX_BODY_SIZE) {
        tooLarge = true;
        reject(new Error("BODY_TOO_LARGE"));
        req.destroy();
      }
    });

    req.on("end", () => {
      if (tooLarge) return;

      if (!body.trim()) {
        resolve({});
        return;
      }

      try {
        resolve(JSON.parse(body));
      } catch {
        reject(new Error("INVALID_JSON"));
      }
    });

    req.on("error", reject);
  });
}

// ---------- Response storage ----------

function readResponses() {
  try {
    if (!fs.existsSync(DATA_FILE)) {
      fs.writeFileSync(DATA_FILE, "[]", "utf8");
    }

    const contents = fs.readFileSync(DATA_FILE, "utf8");
    const responses = JSON.parse(contents || "[]");

    if (!Array.isArray(responses)) {
      throw new Error("Response data must be an array.");
    }

    return responses;
  } catch (error) {
    console.error("Could not read responses.json:", error.message);
    throw error;
  }
}

function saveResponses(responses) {
  const temporaryFile = DATA_FILE + ".tmp";

  fs.writeFileSync(
    temporaryFile,
    JSON.stringify(responses, null, 2),
    "utf8"
  );

  fs.renameSync(temporaryFile, DATA_FILE);
}

// ---------- Session management ----------

function getCookie(req, cookieName) {
  const cookieHeader = req.headers.cookie || "";

  for (const part of cookieHeader.split(";")) {
    const separator = part.indexOf("=");

    if (separator === -1) continue;

    const name = part.slice(0, separator).trim();
    const value = part.slice(separator + 1).trim();

    if (name === cookieName) {
      return value;
    }
  }

  return null;
}

function getAuthenticatedSession(req) {
  const token = getCookie(req, SESSION_COOKIE);

  if (!token) return false;

  const expiresAt = sessions.get(token);

  if (!expiresAt || expiresAt < Date.now()) {
    sessions.delete(token);
    return false;
  }

  return true;
}

function setSessionCookie(res, token) {
  res.setHeader(
    "Set-Cookie",
    `${SESSION_COOKIE}=${token}; HttpOnly; Secure; SameSite=None; Path=/; Max-Age=${SESSION_DURATION / 1000}`
  );
}

function clearSessionCookie(res) {
  res.setHeader(
    "Set-Cookie",
    `${SESSION_COOKIE}=; HttpOnly; Secure; SameSite=None; Path=/; Max-Age=0`
  );
}

function requireAdmin(req, res) {
  if (!getAuthenticatedSession(req)) {
    sendJSON(res, 401, {
      error: "Unauthorized. Please log in again."
    });

    return false;
  }

  return true;
}

// ---------- Static admin page ----------

function serveAdminPage(res) {
  const filePath = path.join(__dirname, "admin.html");

  if (!fs.existsSync(filePath)) {
    sendText(
      res,
      404,
      "admin.html was not found on the backend. Open the Netlify admin page instead."
    );

    return;
  }

  res.writeHead(200, {
    "Content-Type": "text/html; charset=utf-8",
    "Cache-Control": "no-store"
  });

  fs.createReadStream(filePath).pipe(res);
}

// ---------- API routes ----------

async function handleRequest(req, res) {
  // Apply CORS before processing every route, including errors.
  if (!applyCors(req, res)) {
    sendJSON(res, 403, {
      error: "Origin not allowed."
    });

    return;
  }

  // Browser preflight requests must be handled before API routes.
  if (req.method === "OPTIONS") {
    res.writeHead(204);
    res.end();
    return;
  }

  const requestURL = new URL(
    req.url,
    `http://${req.headers.host || "localhost"}`
  );

  const pathname = decodeURIComponent(requestURL.pathname);

  // Health check
  if (req.method === "GET" && pathname === "/api/health") {
    sendJSON(res, 200, {
      status: "ok",
      message: "College feedback API is running."
    });

    return;
  }

  // Optional backend admin page
  if (req.method === "GET" && pathname === "/admin.html") {
    serveAdminPage(res);
    return;
  }

  // Check whether the current session is authenticated
  if (req.method === "GET" && pathname === "/api/auth") {
    sendJSON(res, 200, {
      authenticated: getAuthenticatedSession(req)
    });

    return;
  }

  // Admin login
  if (req.method === "POST" && pathname === "/api/auth/login") {
    let body;

    try {
      body = await readJSON(req);
    } catch (error) {
      sendJSON(
        res,
        error.message === "BODY_TOO_LARGE" ? 413 : 400,
        {
          error:
            error.message === "BODY_TOO_LARGE"
              ? "Request body is too large."
              : "Invalid JSON request."
        }
      );

      return;
    }

    const username = String(body.username || "");
    const password = String(body.password || "");

    if (
      username !== ADMIN_USERNAME ||
      password !== ADMIN_PASSWORD
    ) {
      sendJSON(res, 401, {
        authenticated: false,
        error: "Invalid username or password."
      });

      return;
    }

    const token = crypto.randomBytes(32).toString("hex");

    sessions.set(token, Date.now() + SESSION_DURATION);
    setSessionCookie(res, token);

    sendJSON(res, 200, {
      authenticated: true,
      message: "Login successful."
    });

    return;
  }

  // Admin logout
  if (req.method === "POST" && pathname === "/api/auth/logout") {
    const token = getCookie(req, SESSION_COOKIE);

    if (token) {
      sessions.delete(token);
    }

    clearSessionCookie(res);

    sendJSON(res, 200, {
      authenticated: false,
      message: "Logged out successfully."
    });

    return;
  }

  // List all feedback responses
  if (req.method === "GET" && pathname === "/api/responses") {
    if (!requireAdmin(req, res)) return;

    try {
      sendJSON(res, 200, readResponses());
    } catch {
      sendJSON(res, 500, {
        error: "Could not read feedback responses."
      });
    }

    return;
  }

  // Submit new feedback
  if (req.method === "POST" && pathname === "/api/responses") {
    let body;

    try {
      body = await readJSON(req);
    } catch (error) {
      sendJSON(
        res,
        error.message === "BODY_TOO_LARGE" ? 413 : 400,
        {
          error:
            error.message === "BODY_TOO_LARGE"
              ? "Feedback submission is too large."
              : "Invalid JSON request."
        }
      );

      return;
    }

    if (
      !body ||
      typeof body !== "object" ||
      Array.isArray(body)
    ) {
      sendJSON(res, 400, {
        error: "Feedback must be a JSON object."
      });

      return;
    }

    try {
      const responses = readResponses();

      const newResponse = {
        ...body,
        id: crypto.randomUUID(),
        submittedAt: new Date().toISOString()
      };

      responses.push(newResponse);
      saveResponses(responses);

      sendJSON(res, 201, {
        success: true,
        message: "Feedback submitted successfully.",
        id: newResponse.id
      });
    } catch (error) {
      console.error("Feedback save failed:", error.message);

      sendJSON(res, 500, {
        error: "Could not save feedback. Please try again."
      });
    }

    return;
  }

  // Delete all feedback responses
  if (req.method === "DELETE" && pathname === "/api/responses") {
    if (!requireAdmin(req, res)) return;

    try {
      saveResponses([]);

      sendJSON(res, 200, {
        success: true,
        message: "All responses deleted."
      });
    } catch {
      sendJSON(res, 500, {
        error: "Could not delete responses."
      });
    }

    return;
  }

  // Get or delete a single response by ID
  const responseMatch = pathname.match(/^\/api\/responses\/([^/]+)$/);

  if (responseMatch) {
    if (!requireAdmin(req, res)) return;

    const responseId = responseMatch[1];

    try {
      const responses = readResponses();
      const index = responses.findIndex(
        item => String(item.id) === responseId
      );

      if (index === -1) {
        sendJSON(res, 404, {
          error: "Feedback response not found."
        });

        return;
      }

      if (req.method === "GET") {
        sendJSON(res, 200, responses[index]);
        return;
      }

      if (req.method === "DELETE") {
        responses.splice(index, 1);
        saveResponses(responses);

        sendJSON(res, 200, {
          success: true,
          message: "Response deleted successfully."
        });

        return;
      }
    } catch {
      sendJSON(res, 500, {
        error: "Could not process the response."
      });

      return;
    }
  }

  sendJSON(res, 404, {
    error: "API route not found."
  });
}

// ---------- Start server ----------

const server = http.createServer((req, res) => {
  handleRequest(req, res).catch(error => {
    console.error("Request failed:", error);

    if (!res.headersSent) {
      sendJSON(res, 500, {
        error: "Internal server error."
      });
    } else if (!res.writableEnded) {
      res.end();
    }
  });
});

server.listen(PORT, HOST, () => {
  console.log(`College feedback API listening on ${HOST}:${PORT}`);
});
