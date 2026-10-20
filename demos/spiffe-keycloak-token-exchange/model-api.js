const http = require("http");
const https = require("https");
const fs = require("fs");

const PORT = 8080;
const JWKS_URI = process.env.JWKS_URI || "";
const EXPECTED_AUDIENCE = process.env.EXPECTED_AUDIENCE || "model-api";
const JWKS_CA_FILE = process.env.JWKS_CA_FILE || "";

function b64urlDecode(v) {
  return Buffer.from(v.replace(/-/g, "+").replace(/_/g, "/") + "=".repeat((4 - v.length % 4) % 4), "base64");
}

function decodeJwt(token) {
  const parts = token.split(".");
  if (parts.length !== 3) throw new Error("invalid JWT");
  return {
    header: JSON.parse(b64urlDecode(parts[0])),
    payload: JSON.parse(b64urlDecode(parts[1]))
  };
}

const server = http.createServer((req, res) => {
  if (req.url === "/healthz") { res.writeHead(200); res.end("ok"); return; }

  if (req.method === "POST" && req.url === "/v1/completions") {
    const auth = req.headers.authorization;
    if (!auth || !auth.startsWith("Bearer ")) {
      res.writeHead(401, {"Content-Type": "application/json"});
      res.end(JSON.stringify({error: "missing Authorization: Bearer token"}));
      return;
    }

    let claims;
    try {
      const decoded = decodeJwt(auth.slice(7));
      claims = decoded.payload;
      const aud = Array.isArray(claims.aud) ? claims.aud : [claims.aud];
      if (!aud.includes(EXPECTED_AUDIENCE)) {
        res.writeHead(403, {"Content-Type": "application/json"});
        res.end(JSON.stringify({error: "audience mismatch", expected: EXPECTED_AUDIENCE, got: claims.aud}));
        return;
      }
    } catch (err) {
      res.writeHead(403, {"Content-Type": "application/json"});
      res.end(JSON.stringify({error: "token validation failed", detail: err.message}));
      return;
    }

    let body = "";
    req.on("data", c => body += c);
    req.on("end", () => {
      let prompt = "no prompt";
      try { prompt = JSON.parse(body).prompt || "no prompt"; } catch {}
      res.writeHead(200, {"Content-Type": "application/json"});
      res.end(JSON.stringify({
        id: "mock-completion-001",
        object: "text_completion",
        model: "mock-gpt-spiffe",
        choices: [{
          text: "This is a mock completion from a SPIFFE-protected model endpoint. Your prompt was: \"" + prompt + "\"",
          index: 0,
          finish_reason: "stop"
        }],
        identity: {
          user: claims.sub || "unknown",
          sandbox: claims.azp || "unknown",
          audience: claims.aud,
          scopes: claims.scope || "none",
          issuer: claims.iss
        }
      }, null, 2));
    });
    return;
  }

  res.writeHead(404); res.end("not found");
});

server.listen(PORT, () => console.log("model-api listening on " + PORT));
