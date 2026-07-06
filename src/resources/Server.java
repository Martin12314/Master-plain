import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.sun.net.httpserver.Filter;
import com.sun.net.httpserver.Headers;
import com.sun.net.httpserver.HttpContext;
import com.sun.net.httpserver.HttpExchange;
import com.sun.net.httpserver.HttpServer;
import org.jose4j.jwe.ContentEncryptionAlgorithmIdentifiers;
import org.jose4j.jwe.JsonWebEncryption;
import org.jose4j.jwe.KeyManagementAlgorithmIdentifiers;
import org.jose4j.jwk.JsonWebKey;
import org.jose4j.jwk.RsaJsonWebKey;
import org.jose4j.jwk.RsaJwkGenerator;
import org.jose4j.lang.JoseException;

import java.io.File;
import java.io.IOException;
import java.io.OutputStream;
import java.net.InetSocketAddress;
import java.net.URLDecoder;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.security.KeyPairGenerator;
import java.security.MessageDigest;
import java.security.PrivateKey;
import java.security.Signature;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.MGF1ParameterSpec;
import java.security.spec.PSSParameterSpec;
import java.time.ZoneOffset;
import java.time.ZonedDateTime;
import java.time.format.DateTimeFormatter;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Base64;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

public class Server {

    private static final ObjectMapper MAPPER = new ObjectMapper();
    private static final Map<String, RSAPublicKey> CLIENT_REQ_PUBS = new ConcurrentHashMap<>();

    private static RSAPublicKey WRONG_CLIENT_REQ_VERIFY_PUB;
    private static RSAPublicKey JWE_PUB;
    private static RSAPrivateKey JWE_PRIV;
    private static RSAPrivateKey SIG_PRIV;

    private static final String JWE_KID = "host-jwe-key-1";
    private static final String SIG_KID = "sig-key-1";

    public static void main(String[] args) throws Exception {
        rotateJweKeypair();

        String jwkJson = Files.readString(Paths.get("sig-key.jwk.json"), StandardCharsets.UTF_8);
        RsaJsonWebKey sigJwk = (RsaJsonWebKey) JsonWebKey.Factory.newJwk(jwkJson);
        SIG_PRIV = (RSAPrivateKey) sigJwk.getPrivateKey();

        System.out.println("== Host starting ==");
        System.out.println("JWE key: " + JWE_KID);
        System.out.println("SIG key: " + sigJwk.getKeyId());

        HttpServer http = HttpServer.create(new InetSocketAddress("0.0.0.0", 8080), 0);
        List<HttpContext> contexts = new ArrayList<>();

        contexts.add(http.createContext("/", Server::handleFile));
        contexts.add(http.createContext("/login.html", Server::handleFile));
        contexts.add(http.createContext("/index.html", Server::handleFile));
        contexts.add(http.createContext("/styles.css", Server::handleFile));
        contexts.add(http.createContext("/key-exchange", Server::handleKeyExchange));
        contexts.add(http.createContext("/req-key/register", Server::handleReqKeyRegister));
        contexts.add(http.createContext("/api/login", Server::handleLogin));

        HttpContext echoContext = http.createContext("/api/echo", Server::handleEcho);
        HttpContext securedContext = http.createContext("/secured/index.html", Server::handleFile);

        SessionFilter sessionFilter = new SessionFilter();
        echoContext.getFilters().add(sessionFilter);
        securedContext.getFilters().add(sessionFilter);

        contexts.add(echoContext);
        contexts.add(securedContext);

        for (HttpContext ctx : contexts) {
            ctx.getFilters().add(new ResponseSignerFilter());
        }

        http.setExecutor(null);
        http.start();
        System.out.println("HTTP server running on http://0.0.0.0:8080");
    }

    private static void handleFile(HttpExchange ex) {
        try {
            String path = ex.getRequestURI().getPath();
            if ("/".equals(path)) {
                path = "/login.html";
            }

            File file = new File("www" + path);
            if (!file.exists() || file.isDirectory()) {
                ex.setAttribute("handlerResult", HandlerResult.text(404, "Not Found"));
                return;
            }

            if (path.startsWith("/unsigned/")) {
                ex.setAttribute("disableSigning", Boolean.TRUE);
            }

            byte[] data = Files.readAllBytes(file.toPath());
            ex.setAttribute("handlerResult", HandlerResult.bytes(200, contentType(path), data));
        } catch (Exception e) {
            ex.setAttribute("handlerResult", HandlerResult.error(e.toString()));
        }
    }

    private static void handleKeyExchange(HttpExchange ex) {
        try {
            String n = b64urlUnsigned(JWE_PUB.getModulus().toByteArray());
            String e = b64urlUnsigned(JWE_PUB.getPublicExponent().toByteArray());
            String body = "{\"kty\":\"RSA\",\"kid\":\"" + JWE_KID + "\",\"n\":\"" + n + "\",\"e\":\"" + e + "\"}";
            ex.setAttribute("handlerResult", HandlerResult.json(body));
        } catch (Exception e) {
            ex.setAttribute("handlerResult", HandlerResult.error(e.toString()));
        }
    }

    private static void handleReqKeyRegister(HttpExchange ex) {
        try {
            if (!"POST".equalsIgnoreCase(ex.getRequestMethod())) {
                ex.setAttribute("handlerResult", HandlerResult.text(405, "Method Not Allowed"));
                return;
            }

            String demo = normalizeDemo(getQueryParam(ex.getRequestURI().getRawQuery(), "demo"));
            String body = new String(ex.getRequestBody().readAllBytes(), StandardCharsets.UTF_8);
            Map<String, Object> req = tryParseJsonMap(body);

            String kid = stringValue(req.get("kid"));
            String suppliedThumbprint = stringValue(req.get("jwkThumbprint"));
            String proofB64 = stringValue(req.get("proof"));
            Object jwkObj = req.get("jwk");

            if (kid == null || kid.isBlank()
                    || suppliedThumbprint == null || suppliedThumbprint.isBlank()
                    || proofB64 == null || proofB64.isBlank()
                    || jwkObj == null) {
                ex.setAttribute("handlerResult", HandlerResult.text(400, "Missing kid/jwk/jwkThumbprint/proof"));
                return;
            }

            String jwkJson = MAPPER.writeValueAsString(jwkObj);
            RsaJsonWebKey clientJwk = (RsaJsonWebKey) JsonWebKey.Factory.newJwk(jwkJson);
            RSAPublicKey clientPub = (RSAPublicKey) clientJwk.getPublicKey();

            String computedThumbprint = computeReqSignJwkThumbprint(clientPub);
            if (!computedThumbprint.equals(suppliedThumbprint)) {
                ex.setAttribute("handlerResult", HandlerResult.text(400, "JWK thumbprint mismatch"));
                return;
            }

            String proofBase = buildReqKeyRegistrationProofBase(kid, computedThumbprint);
            if (!verifyReqKeyRegistrationProof(clientPub, proofBase, proofB64)) {
                ex.setAttribute("handlerResult", HandlerResult.text(401, "Bad registration proof"));
                return;
            }

            RSAPublicKey storedPub = clientPub;
            String acceptedThumbprint = computedThumbprint;

            if ("host-wrong-client-key".equals(demo)) {
                storedPub = wrongClientReqVerifyPublicKey();
                acceptedThumbprint = computeReqSignJwkThumbprint(storedPub);

                System.out.println("[REQ-KEY-REGISTER] DEMO wrong host key active");
                System.out.println("[REQ-KEY-REGISTER] client kid             = " + kid);
                System.out.println("[REQ-KEY-REGISTER] client thumbprint      = " + computedThumbprint);
                System.out.println("[REQ-KEY-REGISTER] host stored thumbprint = " + acceptedThumbprint);
            } else {
                System.out.println("[REQ-KEY-REGISTER] normal");
                System.out.println("[REQ-KEY-REGISTER] client kid          = " + kid);
                System.out.println("[REQ-KEY-REGISTER] accepted thumbprint = " + acceptedThumbprint);
            }

            CLIENT_REQ_PUBS.put(kid, storedPub);

            String resp =
                    "{"
                            + "\"ok\":true,"
                            + "\"acceptedKid\":\"" + json(kid) + "\","
                            + "\"acceptedThumbprint\":\"" + json(acceptedThumbprint) + "\""
                            + "}";

            ex.setAttribute("handlerResult", HandlerResult.json(resp));
        } catch (Exception e) {
            ex.setAttribute("handlerResult", HandlerResult.error(e.toString()));
        }
    }

    private static void handleLogin(HttpExchange ex) {
        try {
            if (!"POST".equalsIgnoreCase(ex.getRequestMethod())) {
                ex.setAttribute("handlerResult", HandlerResult.text(405, "Method Not Allowed"));
                return;
            }

            byte[] bodyBytes = ex.getRequestBody().readAllBytes();
            String body = new String(bodyBytes, StandardCharsets.UTF_8);

            logReqSigningHeaders(ex, "/api/login");

            if (!verifyClientSignedRequest(ex, bodyBytes)) {
                ex.setAttribute("handlerResult", HandlerResult.text(401, "Bad client request signature"));
                return;
            }

            String usernameEnc = jsonField(body, "username");
            String passwordEnc = jsonField(body, "password");

            String user = tryDecryptAndValidate(usernameEnc);
            String pass = tryDecryptAndValidate(passwordEnc);

            boolean success = "alice".equals(user) && "secret".equals(pass);

            if (success) {
                long now = System.currentTimeMillis() / 1000L;
                long exp = now + 1800;
                String session = "{\"u\":\"" + json(user) + "\",\"role\":\"admin\",\"iat\":" + now + ",\"exp\":" + exp + "}";
                setCookie(ex, "sess", jweEncrypt(session), CookieOptions.defaultSession(1800));
                ex.setAttribute("handlerResult", HandlerResult.json("{\"ok\":true}"));
            } else {
                ex.setAttribute("handlerResult", HandlerResult.json("{\"ok\":false}"));
            }
        } catch (Exception e) {
            ex.setAttribute("handlerResult", HandlerResult.error(e.toString()));
        }
    }

    private static void handleEcho(HttpExchange ex) {
        try {
            byte[] rawBytes = ex.getRequestBody().readAllBytes();
            String rawBody = new String(rawBytes, StandardCharsets.UTF_8);

            logReqSigningHeaders(ex, "/api/echo");

            if (!verifyClientSignedRequest(ex, rawBytes)) {
                ex.setAttribute("handlerResult", HandlerResult.text(401, "Bad client request signature"));
                return;
            }

            Map<String, Object> resp = new LinkedHashMap<>();

            Map<String, Object> req = new LinkedHashMap<>();
            req.put("method", ex.getRequestMethod());
            req.put("path", ex.getRequestURI().toString());
            resp.put("request", req);

            Map<String, Object> session = new LinkedHashMap<>();
            session.put("user", ex.getAttribute("session.user"));
            resp.put("session", session);

            Map<String, Object> client = new LinkedHashMap<>();
            client.put("origin", headerFirst(ex, "Origin"));
            client.put("referer", headerFirst(ex, "Referer"));
            client.put("userAgent", headerFirst(ex, "User-agent"));
            client.put("xForwardedFor", headerFirst(ex, "X-forwarded-for"));
            client.put("xForwardedProto", headerFirst(ex, "X-forwarded-proto"));
            client.put("xForwardedHost", headerFirst(ex, "X-forwarded-host"));
            client.put("xForwardedServer", headerFirst(ex, "X-forwarded-server"));
            resp.put("client", client);

            Map<String, Object> headers = new LinkedHashMap<>();
            headers.put("interesting", pickInterestingHeaders(ex));
            headers.put("all", flattenHeaders(ex.getRequestHeaders()));
            resp.put("headers", headers);

            Object parsedBody = tryParseJson(rawBody);
            resp.put("body", parsedBody);

            Map<String, Object> decrypted = new LinkedHashMap<>();
            List<String> notes = new ArrayList<>();

            if (parsedBody instanceof Map) {
                @SuppressWarnings("unchecked")
                Map<String, Object> bodyMap = (Map<String, Object>) parsedBody;
                decryptIfJweString(bodyMap, "name", decrypted, notes);
                decryptIfJweString(bodyMap, "message", decrypted, notes);
                decryptIfJweString(bodyMap, "username", decrypted, notes);
                decryptIfJweString(bodyMap, "password", decrypted, notes);
            } else {
                notes.add("Body is not a JSON object; cannot field-decrypt.");
            }

            String encHdr = headerFirst(ex, "X-Enc-X-Custom");
            if (encHdr != null) {
                String dec = tryDecryptAndValidate("JWE: " + encHdr);
                if (dec != null) {
                    decrypted.put("X-Enc-X-Custom", dec);
                } else {
                    notes.add("Failed to decrypt header X-Enc-X-Custom");
                }
            }

            if (!decrypted.isEmpty()) {
                resp.put("decrypted", decrypted);
            }
            if (!notes.isEmpty()) {
                resp.put("notes", notes);
            }

            ex.setAttribute("handlerResult", HandlerResult.json(MAPPER.writerWithDefaultPrettyPrinter().writeValueAsString(resp)));
        } catch (Exception e) {
            ex.setAttribute("handlerResult", HandlerResult.error(e.toString()));
        }
    }

    private static boolean verifyClientSignedRequest(HttpExchange ex, byte[] bodyBytes) {
        try {
            String kid = headerFirst(ex, "X-Client-Key-Id");
            String created = headerFirst(ex, "X-Req-Created");
            String contentDigest = headerFirst(ex, "X-Req-Content-Digest");
            String sigB64 = headerFirst(ex, "X-Req-Signature");

            System.out.println("[REQ-VERIFY] endpoint=" + ex.getRequestURI());

            if (kid == null || created == null || contentDigest == null || sigB64 == null) {
                System.out.println("[REQ-VERIFY] FAIL missing signing headers");
                return false;
            }

            long createdSec;
            try {
                createdSec = Long.parseLong(created);
            } catch (Exception e) {
                System.out.println("[REQ-VERIFY] FAIL bad X-Req-Created");
                return false;
            }

            long nowSec = System.currentTimeMillis() / 1000L;
            if (Math.abs(nowSec - createdSec) > 300) {
                System.out.println("[REQ-VERIFY] FAIL X-Req-Created outside allowed window");
                return false;
            }

            RSAPublicKey pub = CLIENT_REQ_PUBS.get(kid);
            if (pub == null) {
                System.out.println("[REQ-VERIFY] FAIL unknown client key id: " + kid);
                return false;
            }

            String expectedDigest = "sha-256=:" + Base64.getEncoder().encodeToString(sha256(bodyBytes)) + ":";

            System.out.println("[REQ-VERIFY] received digest = " + contentDigest);
            System.out.println("[REQ-VERIFY] expected digest = " + expectedDigest);

            if (!expectedDigest.equals(contentDigest)) {
                System.out.println("[REQ-VERIFY] FAIL request content digest mismatch");
                return false;
            }

            String base = buildRequestSignatureBase(
                    ex.getRequestMethod().toLowerCase(Locale.ROOT),
                    ex.getRequestURI().toString(),
                    created,
                    contentDigest,
                    kid
            );

            Signature verifier = Signature.getInstance("RSASSA-PSS");
            verifier.setParameter(new PSSParameterSpec("SHA-256", "MGF1", MGF1ParameterSpec.SHA256, 32, 1));
            verifier.initVerify(pub);
            verifier.update(base.getBytes(StandardCharsets.UTF_8));

            boolean ok = verifier.verify(Base64.getDecoder().decode(sigB64));

            System.out.println("[REQ-VERIFY] signature base:");
            System.out.println(base);
            System.out.println("[REQ-VERIFY] signature valid = " + ok);
            System.out.println(ok ? "[REQ-VERIFY] OK" : "[REQ-VERIFY] FAIL request signature verification failed");

            return ok;
        } catch (Exception e) {
            System.out.println("[REQ-VERIFY] FAIL exception: " + e.getMessage());
            return false;
        }
    }

    static class ResponseSignerFilter extends Filter {
        @Override
        public String description() {
            return "Signs responses";
        }

        @Override
        public void doFilter(HttpExchange ex, Chain chain) throws IOException {
            chain.doFilter(ex);

            HandlerResult result = (HandlerResult) ex.getAttribute("handlerResult");
            if (result == null) {
                result = HandlerResult.text(500, "Missing response");
            }

            boolean disableSigning = Boolean.TRUE.equals(ex.getAttribute("disableSigning"))
                    || ex.getRequestURI().getPath().startsWith("/unsigned/");

            Headers headers = ex.getResponseHeaders();

            if (disableSigning) {
                headers.set("Content-Type", result.contentType);
                headers.set("Connection", "close");

                ex.sendResponseHeaders(result.status, result.body.length);
                try (OutputStream os = ex.getResponseBody()) {
                    os.write(result.body);
                }
                return;
            }

            String demo = "";
            String path = ex.getRequestURI().getPath();
            if ("/api/login".equals(path) || "/api/echo".equals(path)) {
                demo = normalizeDemo(getQueryParam(ex.getRequestURI().getRawQuery(), "demo"));
            }

            byte[] body = result.body;
            String correctDigest = "sha-256=:" + Base64.getEncoder().encodeToString(sha256(body)) + ":";
            String sendDigest = correctDigest;

            if ("resp-bad-digest".equals(demo)) {
                sendDigest = "sha-256=:" + Base64.getEncoder().encodeToString(new byte[32]) + ":";
                System.out.println("[RESP-SEND] demo wrong response digest active");
                System.out.println("[RESP-SEND] actual digest = " + correctDigest);
                System.out.println("[RESP-SEND] sent   digest = " + sendDigest);
            } else {
                System.out.println("[RESP-SEND] normal response digest = " + correctDigest);
            }

            long created = System.currentTimeMillis() / 1000L;
            String method = ex.getRequestMethod().toLowerCase(Locale.ROOT);
            String target = ex.getRequestURI().toString();
            int status = result.status;

            String sigInput =
                    "(\"@method\" \"@target-uri\" \"@status\" \"content-digest\");"
                            + "created=" + created + ";"
                            + "keyid=\"" + SIG_KID + "\";"
                            + "alg=\"rsa-pss-sha256\"";

            String signatureBase =
                    "\"@method\": \"" + method + "\"\n"
                            + "\"@target-uri\": \"" + target + "\"\n"
                            + "\"@status\": " + status + "\n"
                            + "content-digest: " + sendDigest + "\n"
                            + "\"@signature-params\": " + sigInput;

            String sigB64;
            try {
                byte[] sig = signPss(signatureBase.getBytes(StandardCharsets.US_ASCII), SIG_PRIV);
                sigB64 = Base64.getEncoder().encodeToString(sig);
            } catch (Exception e) {
                throw new RuntimeException(e);
            }

            headers.set("Content-Type", result.contentType);
            headers.set("Connection", "close");
            headers.set("Content-Digest", sendDigest);
            headers.set("Signature-Input", "sig1=" + sigInput);
            headers.set("Signature", "sig1=:" + sigB64 + ":");

            ex.sendResponseHeaders(status, body.length);
            try (OutputStream os = ex.getResponseBody()) {
                os.write(body);
            }
        }
    }

    static class SessionFilter extends Filter {
        @Override
        public String description() {
            return "sess";
        }

        @Override
        public void doFilter(HttpExchange ex, Chain chain) throws IOException {
            String s = getCookie(ex, "sess");
            if (s != null) {
                String payload = jweDecrypt(s);
                if (payload != null) {
                    ex.setAttribute("session.user", jsonField(payload, "u"));
                }
            }
            chain.doFilter(ex);
        }
    }

    static class CookieOptions {
        String path = "/";
        boolean httpOnly = true;
        boolean secure = true;
        Long maxAgeSeconds = null;

        static CookieOptions defaultSession(long secs) {
            CookieOptions options = new CookieOptions();
            options.maxAgeSeconds = secs;
            return options;
        }
    }

    static void setCookie(HttpExchange ex, String name, String value, CookieOptions options) {
        StringBuilder sb = new StringBuilder();
        sb.append(name).append("=").append(value != null ? value : "");
        if (options.path != null) {
            sb.append("; Path=").append(options.path);
        }
        if (options.maxAgeSeconds != null) {
            sb.append("; Max-Age=").append(options.maxAgeSeconds);
            ZonedDateTime exp = ZonedDateTime.now(ZoneOffset.UTC).plusSeconds(options.maxAgeSeconds);
            sb.append("; Expires=").append(DateTimeFormatter.RFC_1123_DATE_TIME.format(exp));
        }
        if (options.secure) {
            sb.append("; Secure");
        }
        if (options.httpOnly) {
            sb.append("; HttpOnly");
        }
        ex.getResponseHeaders().add("Set-Cookie", sb.toString());
    }

    static String getCookie(HttpExchange ex, String name) {
        List<String> headers = ex.getRequestHeaders().get("Cookie");
        if (headers == null) {
            return null;
        }
        for (String h : headers) {
            for (String part : h.split(";")) {
                String[] nv = part.trim().split("=", 2);
                if (nv.length == 2 && nv[0].trim().equals(name)) {
                    return nv[1].trim();
                }
            }
        }
        return null;
    }

    private static void rotateJweKeypair() throws Exception {
        RsaJsonWebKey jwk = RsaJwkGenerator.generateJwk(2048);
        JWE_PUB = (RSAPublicKey) jwk.getPublicKey();
        JWE_PRIV = (RSAPrivateKey) jwk.getPrivateKey();
    }

    private static String jweEncrypt(String json) throws JoseException {
        JsonWebEncryption jwe = new JsonWebEncryption();
        jwe.setPayload(json);
        jwe.setAlgorithmHeaderValue(KeyManagementAlgorithmIdentifiers.RSA_OAEP_256);
        jwe.setEncryptionMethodHeaderParameter(ContentEncryptionAlgorithmIdentifiers.AES_256_GCM);
        jwe.setKey(JWE_PUB);
        jwe.setKeyIdHeaderValue(JWE_KID);
        return jwe.getCompactSerialization();
    }

    private static String jweDecrypt(String compact) {
        try {
            JsonWebEncryption jwe = new JsonWebEncryption();
            jwe.setCompactSerialization(compact);
            jwe.setKey(JWE_PRIV);
            return jwe.getPayload();
        } catch (Exception e) {
            return null;
        }
    }

    private static byte[] sha256(byte[] in) {
        try {
            return MessageDigest.getInstance("SHA-256").digest(in);
        } catch (Exception e) {
            return new byte[0];
        }
    }

    private static byte[] signPss(byte[] input, PrivateKey key) throws Exception {
        Signature signer = Signature.getInstance("RSASSA-PSS");
        signer.setParameter(new PSSParameterSpec("SHA-256", "MGF1", MGF1ParameterSpec.SHA256, 32, 1));
        signer.initSign(key);
        signer.update(input);
        return signer.sign();
    }

    private static String b64urlUnsigned(byte[] in) {
        if (in.length > 1 && in[0] == 0) {
            in = Arrays.copyOfRange(in, 1, in.length);
        }
        return Base64.getUrlEncoder().withoutPadding().encodeToString(in);
    }

    private static String buildReqKeyRegistrationProofBase(String kid, String thumbprint) {
        return "\"kid\": \"" + kid + "\"\n"
                + "\"thumbprint\": \"" + thumbprint + "\"";
    }

    private static String buildRequestSignatureBase(
            String methodLower,
            String target,
            String created,
            String contentDigest,
            String kid
    ) {
        return "\"@method\": \"" + methodLower + "\"\n"
                + "\"@target-uri\": \"" + target + "\"\n"
                + "\"x-req-created\": " + created + "\n"
                + "\"x-req-content-digest\": " + contentDigest + "\n"
                + "\"x-client-key-id\": " + kid;
    }

    private static String computeReqSignJwkThumbprint(RSAPublicKey pub) throws Exception {
        String n = b64urlUnsigned(pub.getModulus().toByteArray());
        String e = b64urlUnsigned(pub.getPublicExponent().toByteArray());
        String canonical = "{\"e\":\"" + e + "\",\"kty\":\"RSA\",\"n\":\"" + n + "\"}";
        byte[] digest = MessageDigest.getInstance("SHA-256").digest(canonical.getBytes(StandardCharsets.UTF_8));
        return Base64.getUrlEncoder().withoutPadding().encodeToString(digest);
    }

    private static synchronized RSAPublicKey wrongClientReqVerifyPublicKey() throws Exception {
        if (WRONG_CLIENT_REQ_VERIFY_PUB == null) {
            KeyPairGenerator kpg = KeyPairGenerator.getInstance("RSA");
            kpg.initialize(2048);
            WRONG_CLIENT_REQ_VERIFY_PUB = (RSAPublicKey) kpg.generateKeyPair().getPublic();
        }
        return WRONG_CLIENT_REQ_VERIFY_PUB;
    }

    private static boolean verifyReqKeyRegistrationProof(RSAPublicKey pub, String proofBase, String proofB64) {
        try {
            Signature verifier = Signature.getInstance("RSASSA-PSS");
            verifier.setParameter(new PSSParameterSpec("SHA-256", "MGF1", MGF1ParameterSpec.SHA256, 32, 1));
            verifier.initVerify(pub);
            verifier.update(proofBase.getBytes(StandardCharsets.UTF_8));
            return verifier.verify(Base64.getDecoder().decode(proofB64));
        } catch (Exception e) {
            return false;
        }
    }

    private static String jsonField(String json, String key) {
        Matcher m = Pattern.compile("\"" + key + "\"\\s*:\\s*\"(.*?)\"", Pattern.DOTALL).matcher(json);
        return m.find() ? m.group(1) : null;
    }

    private static String tryDecryptAndValidate(String enc) {
        if (enc == null) {
            return null;
        }
        if (enc.startsWith("JWE: ")) {
            enc = enc.substring(5).trim();
        }
        String payload = jweDecrypt(enc);
        return payload != null && isSafeString(payload) ? payload : null;
    }

    private static boolean isSafeString(String input) {
        if (input == null || input.length() > 10000) {
            return false;
        }
        String lower = input.toLowerCase(Locale.ROOT);
        String[] sql = {"select", "insert", "update", "delete", "--", ";drop ", "xp_"};
        for (String token : sql) {
            if (lower.contains(token)) {
                return false;
            }
        }
        String[] xss = {"<script", "javascript:", "onerror", "onload", "<img", "<iframe"};
        for (String token : xss) {
            if (lower.contains(token)) {
                return false;
            }
        }
        return true;
    }

    private static String json(String s) {
        return s == null ? "" : s.replace("\\", "\\\\").replace("\"", "\\\"").replace("\n", "\\n");
    }

    private static String contentType(String path) {
        if (path.endsWith(".html")) return "text/html; charset=utf-8";
        if (path.endsWith(".css")) return "text/css; charset=utf-8";
        if (path.endsWith(".js")) return "application/javascript; charset=utf-8";
        if (path.endsWith(".json")) return "application/json; charset=utf-8";
        if (path.endsWith(".png")) return "image/png";
        if (path.endsWith(".jpg") || path.endsWith(".jpeg")) return "image/jpeg";
        if (path.endsWith(".webp")) return "image/webp";
        if (path.endsWith(".svg")) return "image/svg+xml";
        return "application/octet-stream";
    }

    private static Map<String, Object> tryParseJsonMap(String raw) throws IOException {
        return MAPPER.readValue(raw, new TypeReference<Map<String, Object>>() {});
    }

    private static Object tryParseJson(String raw) {
        try {
            return MAPPER.readValue(raw, Object.class);
        } catch (Exception ignored) {
            return raw;
        }
    }

    private static void decryptIfJweString(
            Map<String, Object> bodyMap,
            String field,
            Map<String, Object> decryptedOut,
            List<String> notes
    ) {
        Object v = bodyMap.get(field);
        if (!(v instanceof String)) {
            return;
        }

        String s = (String) v;
        if (!s.startsWith("JWE: ")) {
            return;
        }

        String dec = tryDecryptAndValidate(s);
        if (dec != null) {
            decryptedOut.put(field, dec);
        } else {
            decryptedOut.put(field, "[decrypt failed]");
            notes.add("Failed to decrypt field: " + field);
        }
    }

    private static String headerFirst(HttpExchange ex, String name) {
        List<String> values = ex.getRequestHeaders().get(name);
        return (values == null || values.isEmpty()) ? null : values.get(0);
    }

    private static Map<String, Object> flattenHeaders(Headers headers) {
        Map<String, Object> out = new LinkedHashMap<>();
        for (Map.Entry<String, List<String>> e : headers.entrySet()) {
            if (e.getValue() == null) {
                continue;
            }
            if ("Cookie".equalsIgnoreCase(e.getKey())) {
                out.put("Cookie", "[redacted]");
                continue;
            }
            out.put(e.getKey(), e.getValue().size() == 1 ? e.getValue().get(0) : e.getValue());
        }
        return out;
    }

    private static Map<String, Object> pickInterestingHeaders(HttpExchange ex) {
        Map<String, Object> out = new LinkedHashMap<>();
        String[] keys = {
                "Host", "Origin", "Referer",
                "X-forwarded-for", "X-forwarded-proto", "X-forwarded-host", "X-forwarded-server",
                "Content-type", "Content-length",
                "X-custom", "X-Enc-X-Custom",
                "X-Client-Key-Id", "X-Req-Created", "X-Req-Content-Digest", "X-Req-Signature"
        };
        for (String key : keys) {
            String value = headerFirst(ex, key);
            if (value != null) {
                out.put(key, value);
            }
        }
        return out;
    }

    private static String getQueryParam(String rawQuery, String key) {
        if (rawQuery == null) {
            return null;
        }
        for (String part : rawQuery.split("&")) {
            String[] kv = part.split("=", 2);
            if (kv.length >= 1 && kv[0].equals(key)) {
                return kv.length == 2 ? urlDecode(kv[1]) : "";
            }
        }
        return null;
    }

    private static String urlDecode(String s) {
        try {
            return URLDecoder.decode(s, StandardCharsets.UTF_8);
        } catch (Exception e) {
            return s;
        }
    }

    private static String stringValue(Object v) {
        return v == null ? null : String.valueOf(v);
    }

    private static String normalizeDemo(String value) {
        return value == null ? "" : value.trim().toLowerCase(Locale.ROOT);
    }

    private static void logReqSigningHeaders(HttpExchange ex, String endpoint) {
        System.out.println("---- REQUEST SIGN HEADERS [" + endpoint + "] ----");
        System.out.println("method = " + ex.getRequestMethod());
        System.out.println("path   = " + ex.getRequestURI());
        System.out.println("X-Client-Key-Id      = " + headerFirst(ex, "X-Client-Key-Id"));
        System.out.println("X-Req-Created        = " + headerFirst(ex, "X-Req-Created"));
        System.out.println("X-Req-Content-Digest = " + headerFirst(ex, "X-Req-Content-Digest"));

        String sig = headerFirst(ex, "X-Req-Signature");
        if (sig == null) {
            System.out.println("X-Req-Signature      = null");
        } else {
            String shortSig = sig.length() <= 80 ? sig : sig.substring(0, 40) + " ... " + sig.substring(sig.length() - 24);
            System.out.println("X-Req-Signature      = " + shortSig + " (len=" + sig.length() + ")");
        }
        System.out.println("----------------------------------------------");
    }

    static class HandlerResult {
        int status;
        String contentType;
        byte[] body;

        static HandlerResult json(String body) {
            return new HandlerResult(200, "application/json; charset=utf-8", body.getBytes(StandardCharsets.UTF_8));
        }

        static HandlerResult text(int status, String msg) {
            return new HandlerResult(status, "text/plain; charset=utf-8", msg.getBytes(StandardCharsets.UTF_8));
        }

        static HandlerResult bytes(int status, String ct, byte[] b) {
            return new HandlerResult(status, ct, b);
        }

        static HandlerResult error(String msg) {
            return json("{\"error\":\"" + Server.json(msg) + "\"}");
        }

        HandlerResult(int status, String contentType, byte[] body) {
            this.status = status;
            this.contentType = contentType;
            this.body = body;
        }
    }
}
