package tests;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ArrayNode;
import com.fasterxml.jackson.databind.node.ObjectNode;
import cz.muni.fi.crocs.rcard.client.CardManager;
import cz.muni.fi.crocs.rcard.client.CardType;
import cz.muni.fi.crocs.rcard.client.RunConfig;
import org.bouncycastle.jce.ECNamedCurveTable;
import org.bouncycastle.jce.spec.ECParameterSpec;
import org.bouncycastle.math.ec.ECPoint;
import org.bouncycastle.util.encoders.Hex;
import org.eclipse.jetty.server.Request;
import org.eclipse.jetty.server.Server;
import org.eclipse.jetty.server.handler.AbstractHandler;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Base64;
import java.util.Iterator;

/**
 * HTTP server interface for JCMint operations.
 * Provides RESTful API endpoints for all minting protocol operations.
 */
public class CashuHttpServer extends AbstractHandler {
    private static final Logger logger = LoggerFactory.getLogger(CashuHttpServer.class);
    private static final ObjectMapper objectMapper = new ObjectMapper();
    private static final ECParameterSpec ecSpec = ECNamedCurveTable.getParameterSpec("secp256k1");

    private final ProtocolManager protocolManager;
    private final int port;

    private ECPoint mintKey;
    private final String KEYSET_ID = "009a1f293253e41e";
    private final String KEYSET_UNIT = "sat";

    public CashuHttpServer(int port, CardManager cardManager, byte cardIndex) {
        this.port = port;
        this.protocolManager = new ProtocolManager(cardManager, cardIndex);
    }

    public void startServer() throws Exception {
        setup();

        Server server = new Server(port);
        server.setHandler(this);
        server.start();
        logger.info("JCMint HTTP Server started on port {}", port);
        server.join();
    }

    private void setup() throws Exception {
        BigInteger[] secrets = new BigInteger[1];
        this.mintKey = protocolManager.setup(secrets);
    }

    @Override
    public void handle(String target, Request baseRequest, HttpServletRequest request,
                       HttpServletResponse response) throws IOException {

        baseRequest.setHandled(true);
        response.setContentType("application/json");
        response.setHeader("Access-Control-Allow-Origin", "*");
        response.setHeader("Access-Control-Allow-Methods", "GET, POST, PUT, DELETE, OPTIONS");
        response.setHeader("Access-Control-Allow-Headers", "Content-Type, Authorization");

        if ("OPTIONS".equals(request.getMethod())) {
            response.setStatus(HttpServletResponse.SC_OK);
            return;
        }

        try {
            String method = request.getMethod();
            String path = target;

            ObjectNode result = objectMapper.createObjectNode();

            if ("GET".equals(method)) {
                switch (path) {
                    case "/v1/info":
                        handleInfo(result);
                        break;
                    case "/v1/keysets":
                        handleKeysets(result);
                        break;
                    case "/v1/keys":
                        handleKeys(result);
                        break;
                    case "/v1/mint/quote/bolt11/fake":
                        handleMintRequest(null, result);
                        break;
                }
            } else if ("POST".equals(method)) {
                JsonNode requestBody = objectMapper.readTree(request.getReader());

                switch (path) {
                    case "/v1/mint/quote/bolt11":
                        handleMintRequest(requestBody, result);
                        break;
                    case "/v1/mint/bolt11":
                        handleMint(requestBody, result);
                        break;
                    case "/v1/swap":
                        handleSwap(requestBody, result);
                        break;
                    default:
                        response.setStatus(HttpServletResponse.SC_NOT_FOUND);
                        result.put("error", "Endpoint not found: " + path);
                }
            } else {
                response.setStatus(HttpServletResponse.SC_METHOD_NOT_ALLOWED);
                result.put("error", "Method not allowed: " + method);
            }

            if (!result.has("error")) {
                response.setStatus(HttpServletResponse.SC_OK);
                result.put("success", true);
            }

            response.getWriter().write(objectMapper.writeValueAsString(result));

        } catch (Exception e) {
            logger.error("Error handling request: " + target, e);
            response.setStatus(HttpServletResponse.SC_INTERNAL_SERVER_ERROR);
            ObjectNode errorResult = objectMapper.createObjectNode();
            errorResult.put("error", e.getMessage());
            errorResult.put("success", false);
            response.getWriter().write(objectMapper.writeValueAsString(errorResult));
        }
    }

    private void handleInfo(ObjectNode result) {
        result.put("name", "JCMint HTTP Server");
        result.put("version", "JCMint/0.0.1");
        result.put("description", "Experimental JavaCard mint");
        result.put("icon_url", "https://www.fi.muni.cz/jvs-2.1/images/apple-touch-icon.png");
        result.put("time", System.currentTimeMillis());
        ObjectNode nuts = objectMapper.createObjectNode();
        ObjectNode methods = objectMapper.createObjectNode();
        ArrayNode methodsArray = objectMapper.createArrayNode();
        ObjectNode method = objectMapper.createObjectNode();
        method.put("method", "bolt11");
        method.put("unit", KEYSET_UNIT);
        methodsArray.add(method);
        methods.set("methods", methodsArray);
        nuts.set("4", methods);
        ObjectNode supported = objectMapper.createObjectNode();
        supported.put("supported", true);
        nuts.set("12", supported);
        result.set("nuts", nuts);
    }

    private void handleKeysets(ObjectNode result) {
        ObjectNode defaultKeyset = objectMapper.createObjectNode();
        defaultKeyset.put("id", KEYSET_ID);
        defaultKeyset.put("unit", KEYSET_UNIT);
        defaultKeyset.put("active", true);
        ArrayNode keysets = objectMapper.createArrayNode();
        keysets.add(defaultKeyset);
        result.set("keysets", keysets);
    }

    private void handleKeys(ObjectNode result) {
        ObjectNode keys = objectMapper.createObjectNode();
        keys.put("1", Hex.toHexString(mintKey.getEncoded(true)));

        ObjectNode defaultKeyset = objectMapper.createObjectNode();
        defaultKeyset.put("id", KEYSET_ID);
        defaultKeyset.put("unit", KEYSET_UNIT);
        defaultKeyset.put("active", true);
        defaultKeyset.set("keys", keys);
        ArrayNode keysets = objectMapper.createArrayNode();
        keysets.add(defaultKeyset);
        result.set("keysets", keysets);
    }

    private void handleMintRequest(JsonNode request, ObjectNode result) throws Exception {
        int amount = request != null ? request.get("amount").asInt() : 1;
        result.put("amount", amount);
        result.put("quote", "fake");
        result.put("request", "fake");
        result.put("unit", KEYSET_UNIT);
        result.put("state", request != null ? "PAID" : "ISSUED");
        result.put("expiry", System.currentTimeMillis() + 1000000);
    }

    private void handleMint(JsonNode request, ObjectNode result) throws Exception {
        Iterator<JsonNode> outputs = request.withArray("outputs").elements();
        ArrayNode signaturesArray = objectMapper.createArrayNode();
        while (outputs.hasNext()) {
            ObjectNode output = outputs.next().deepCopy();

            byte[] challengeBytes = Hex.decode(output.get("B_").asText());
            ECPoint challenge = ecSpec.getCurve().decodePoint(challengeBytes);

            byte[] proof = protocolManager.issueSingleDLEQ(challenge);
            ECPoint signature = ecSpec.getCurve().decodePoint(Arrays.copyOfRange(proof, 0, 65));
            String C_ = Hex.toHexString(signature.getEncoded(true));

            String e = Hex.toHexString(Arrays.copyOfRange(proof, 65, 65 + 32));
            String s = Hex.toHexString(Arrays.copyOfRange(proof, 65 + 32, 65 + 32 + 32));
            ObjectNode dleqObj = objectMapper.createObjectNode();
            dleqObj.put("e", e);
            dleqObj.put("s", s);

            ObjectNode signatureObj = objectMapper.createObjectNode();
            signatureObj.put("id", output.get("id").asText());
            signatureObj.put("amount", output.get("amount").asInt());
            signatureObj.put("C_", C_);
            signatureObj.set("dleq", dleqObj);

            signaturesArray.add(signatureObj);
        }
        result.set("signatures", signaturesArray);
    }

    private void handleSwap(JsonNode request, ObjectNode result) throws Exception {

        Iterator<JsonNode> inputs = request.withArray("inputs").elements();
        Iterator<JsonNode> outputs = request.withArray("outputs").elements();
        ArrayNode signaturesArray = objectMapper.createArrayNode();
        while (outputs.hasNext()) {
            ObjectNode input = inputs.next().deepCopy();
            ObjectNode output = outputs.next().deepCopy();

            String secret = input.get("secret").asText();
            byte[] secretBytes = secret.getBytes(StandardCharsets.UTF_8);
            byte[] C = Hex.decode(input.get("C").asText());
            ECPoint token = ecSpec.getCurve().decodePoint(C);
            byte[] challengeBytes = Hex.decode(output.get("B_").asText());
            ECPoint challenge = ecSpec.getCurve().decodePoint(challengeBytes);

            ECPoint newToken = protocolManager.swapSingle(secretBytes, token, challenge, null);

            String C_ = Hex.toHexString(newToken.getEncoded(true));
            ObjectNode signatureObj = objectMapper.createObjectNode();
            signatureObj.put("id", output.get("id").asText());
            signatureObj.put("amount", output.get("amount").asInt());
            signatureObj.put("C_", C_);
            signaturesArray.add(signatureObj);
        }
        result.set("signatures", signaturesArray);
    }
}