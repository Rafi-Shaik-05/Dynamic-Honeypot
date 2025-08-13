package org.example;

import com.sun.net.httpserver.HttpExchange;
import com.sun.net.httpserver.HttpHandler;
import com.sun.net.httpserver.HttpsConfigurator;
import com.sun.net.httpserver.HttpsServer;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.cert.X509v3CertificateBuilder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.jsoup.Jsoup;
import org.jsoup.nodes.Document;
import org.jsoup.nodes.Element;
import picocli.CommandLine;
import picocli.CommandLine.Command;
import picocli.CommandLine.Option;

import javax.net.ssl.KeyManagerFactory;
import javax.net.ssl.SSLContext;
import javax.net.ssl.TrustManagerFactory;
import java.io.*;
import java.math.BigInteger;
import java.net.InetSocketAddress;
import java.net.URI;
import java.net.URLDecoder;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.*;
import java.security.cert.Certificate;
import java.security.cert.X509Certificate;
import java.time.Duration;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.*;
import java.util.concurrent.Callable;
import java.util.logging.*;

@Command(name = "HttpsHoneypot", mixinStandardHelpOptions = true,
        description = "Run a simple HTTPS server that clones a website.")
public class HttpsHoneypot implements Callable<Integer> {

    @Option(names = {"--host"}, description = "Host to bind the server to.", defaultValue = "0.0.0.0")
    private String host;

    @Option(names = {"-p", "--port"}, description = "Port to bind the server to.", defaultValue = "443")
    private int port;

    @Option(names = {"--url"}, description = "URL to download and serve HTML from.", required = true)
    private String url;

    @Option(names = {"--ssl_country"}, description = "SSL certificate country.", defaultValue = "US")
    private String sslCountry;

    @Option(names = {"--ssl_state"}, description = "SSL certificate state.", defaultValue = "CA")
    private String sslState;

    @Option(names = {"--ssl_locality"}, description = "SSL certificate locality.", defaultValue = "San Francisco")
    private String sslLocality;

    @Option(names = {"--ssl_org"}, description = "SSL certificate organization.", defaultValue = "MyOrganization")
    private String sslOrg;

    @Option(names = {"--domain_name"}, description = "SSL certificate domain name.", defaultValue = "localhost")
    private String domainName;

    private static final Logger logger = Logger.getLogger(HttpsHoneypot.class.getName());
    private static final Path SCRIPT_DIR = Paths.get(System.getProperty("user.dir"));
    private static final Path INDEX_FILE_PATH = SCRIPT_DIR.resolve("index.html");

    public static void main(String[] args) {
        // Add Bouncy Castle as a security provider for certificate generation
        Security.addProvider(new org.bouncycastle.jce.provider.BouncyCastleProvider());
        int exitCode = new CommandLine(new HttpsHoneypot()).execute(args);
        System.exit(exitCode);
    }

    @Override
    public Integer call() throws Exception {
        SimpleHttpsServer server = new SimpleHttpsServer(host, port, url, this);
        server.start();
        return 0;
    }

    // Inner class for the server logic
    static class SimpleHttpsServer {
        private final String host;
        private final int port;
        private String initialUrl;
        private final HttpsHoneypot config;
        private String serverBanner = "Apache/2.4.49"; // Default banner

        public SimpleHttpsServer(String host, int port, String url, HttpsHoneypot config) {
            this.host = host;
            this.port = port;
            this.initialUrl = url;
            this.config = config;
        }

        public void start() throws Exception {
            setupLogging();
            System.out.println("Please wait, downloading resources from " + initialUrl + " ...");

            this.serverBanner = PageCloner.clonePage(initialUrl);

            System.out.println("Generating self-signed SSL certificate...");
            Path keyStorePath = SCRIPT_DIR.resolve("keystore.jks");
            String keyStorePassword = "password";
            CertificateGenerator.generate(
                    keyStorePath, keyStorePassword, "honeypot",
                    config.domainName, config.sslOrg, config.sslLocality, config.sslState, config.sslCountry
            );

            SSLContext sslContext = SSLContext.getInstance("TLS");
            KeyStore keyStore = KeyStore.getInstance("JKS");
            try (InputStream is = Files.newInputStream(keyStorePath)) {
                keyStore.load(is, keyStorePassword.toCharArray());
            }

            KeyManagerFactory kmf = KeyManagerFactory.getInstance(KeyManagerFactory.getDefaultAlgorithm());
            kmf.init(keyStore, keyStorePassword.toCharArray());

            TrustManagerFactory tmf = TrustManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm());
            tmf.init(keyStore);

            sslContext.init(kmf.getKeyManagers(), tmf.getTrustManagers(), new SecureRandom());

            HttpsServer httpsServer = HttpsServer.create(new InetSocketAddress(host, port), 0);
            httpsServer.setHttpsConfigurator(new HttpsConfigurator(sslContext));
            httpsServer.createContext("/", new HoneypotHandler(this));
            httpsServer.setExecutor(null); // Use a default thread pool
            httpsServer.start();

            System.out.println("Server running on https://" + host + ":" + port);
            Thread.sleep(Long.MAX_VALUE);
        }

        private void setupLogging() throws IOException {
            Path logFilePath = SCRIPT_DIR.resolve("https_honeypot.log");
            System.out.println("All HTTP requests will be logged in: " + logFilePath);
            // Remove console handler to only log to file
            Logger rootLogger = Logger.getLogger("");
            Handler[] handlers = rootLogger.getHandlers();
            if (handlers.length > 0 && handlers[0] instanceof ConsoleHandler) {
                rootLogger.removeHandler(handlers[0]);
            }
            logger.setLevel(Level.INFO);
            FileHandler fileHandler = new FileHandler(logFilePath.toString(), true);
            fileHandler.setFormatter(new SimpleFormatter() {
                private static final String format = "[%1$tF %1$tT] [%2$-7s] %3$s %n";
                @Override
                public synchronized String format(LogRecord lr) {
                    return String.format(format, new Date(lr.getMillis()), lr.getLevel().getLocalizedName(), lr.getMessage());
                }
            });
            logger.addHandler(fileHandler);
        }
    }

    // Inner class for handling HTTP requests
    static class HoneypotHandler implements HttpHandler {
        private final SimpleHttpsServer server;

        public HoneypotHandler(SimpleHttpsServer server) {
            this.server = server;
        }

        @Override
        public void handle(HttpExchange exchange) throws IOException {
            String postData = "";
            if ("POST".equalsIgnoreCase(exchange.getRequestMethod())) {
                postData = parsePostData(exchange.getRequestBody());
            }
            logRequest(exchange, postData);

            try {
                // The original script re-clones on every request. Replicating that behavior.
                URI requestedUri = exchange.getRequestURI();
                String targetUrl = new URI(server.initialUrl).resolve(requestedUri).toString();

                System.out.println("Cloning resource for request: " + targetUrl);
                server.serverBanner = PageCloner.clonePage(targetUrl);
                server.initialUrl = targetUrl; // Update current URL

                byte[] response = Files.readAllBytes(INDEX_FILE_PATH);
                exchange.getResponseHeaders().set("Content-Type", "text/html; charset=utf-8");
                exchange.getResponseHeaders().set("Server", server.serverBanner);
                exchange.sendResponseHeaders(200, response.length);
                try (OutputStream os = exchange.getResponseBody()) {
                    os.write(response);
                }
            } catch (Exception e) {
                logger.log(Level.SEVERE, "Error handling request: " + e.getMessage(), e);
                String errorResponse = "<h1>500 Internal Server Error</h1>";
                exchange.sendResponseHeaders(500, errorResponse.length());
                try (OutputStream os = exchange.getResponseBody()) {
                    os.write(errorResponse.getBytes());
                }
            }
        }

        private void logRequest(HttpExchange exchange, String postData) {
            InetSocketAddress remote = exchange.getRemoteAddress();
            Map<String, List<String>> headers = exchange.getRequestHeaders();

            String logMessage = String.format(
                    "src_ip=%s, src_port=%d, user_agent='%s', language='%s', referer='%s', protocol_version='%s', path='%s'%s",
                    remote.getAddress().getHostAddress(),
                    remote.getPort(),
                    headers.getOrDefault("User-Agent", List.of("Unknown")).get(0),
                    headers.getOrDefault("Accept-Language", List.of("Unknown")).get(0),
                    headers.getOrDefault("Referer", List.of("Unknown")).get(0),
                    exchange.getProtocol(),
                    exchange.getRequestURI().getPath(),
                    postData.isEmpty() ? "" : ", post_data=" + postData
            );
            logger.info(logMessage);
        }

        private String parsePostData(InputStream is) throws IOException {
            String body = new String(is.readAllBytes(), StandardCharsets.UTF_8);
            if (body.isEmpty()) return "";

            Map<String, String> params = new LinkedHashMap<>();
            String[] pairs = body.split("&");
            for (String pair : pairs) {
                int idx = pair.indexOf("=");
                try {
                    String key = URLDecoder.decode(pair.substring(0, idx), StandardCharsets.UTF_8);
                    String value = URLDecoder.decode(pair.substring(idx + 1), StandardCharsets.UTF_8);
                    params.put(key, value);
                } catch (Exception e) {
                    // Ignore malformed pairs
                }
            }
            return params.toString();
        }
    }

    // Inner class for cloning the webpage
    static class PageCloner {
        private static final HttpClient httpClient = HttpClient.newBuilder()
                .version(HttpClient.Version.HTTP_2)
                .followRedirects(HttpClient.Redirect.NORMAL)
                .connectTimeout(Duration.ofSeconds(10))
                .build();

        public static String clonePage(String url) throws Exception {
            HttpRequest request = HttpRequest.newBuilder()
                    .uri(URI.create(url))
                    .header("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36")
                    .build();

            HttpResponse<String> response = httpClient.send(request, HttpResponse.BodyHandlers.ofString());
            String serverBanner = response.headers().firstValue("Server").orElse("Apache/2.4.49");

            Document doc = Jsoup.parse(response.body(), url);

            // Inline CSS
            for (Element css : doc.select("link[rel=stylesheet]")) {
                inlineResource(css.absUrl("href"), (ResourceConsumer<String>) content -> {
                    Element style = doc.createElement("style").text(content);
                    css.replaceWith(style);
                });
            }

            // Inline JavaScript
            for (Element js : doc.select("script[src]")) {
                inlineResource(js.absUrl("src"), (ResourceConsumer<String>) content -> {
                    js.removeAttr("src");
                    js.text(content);
                });
            }

            // Inline Images
            for (Element img : doc.select("img[src]")) {
                inlineResource(img.absUrl("src"), (ResourceConsumerBytes<byte[]>) contentBytes -> {
                    String mimeType = "image/jpeg";
                    try {
                        mimeType = Files.probeContentType(Paths.get(new URI(img.absUrl("src")).getPath()));
                    } catch (Exception ignored) {}
                    String base64 = Base64.getEncoder().encodeToString(contentBytes);
                    img.attr("src", "data:" + mimeType + ";base64," + base64);
                });
            }

            Files.writeString(INDEX_FILE_PATH, doc.outerHtml(), StandardCharsets.UTF_8);
            return serverBanner;
        }

        private static void inlineResource(String resourceUrl, ResourceConsumer<String> consumer) {
            try {
                HttpRequest request = HttpRequest.newBuilder().uri(URI.create(resourceUrl)).build();
                HttpResponse<String> response = httpClient.send(request, HttpResponse.BodyHandlers.ofString());
                if (response.statusCode() == 200) {
                    consumer.accept(response.body());
                }
            } catch (Exception e) {
                logger.warning("Failed to inline resource " + resourceUrl + ": " + e.getMessage());
            }
        }

        private static void inlineResource(String resourceUrl, ResourceConsumerBytes<byte[]> consumer) {
            try {
                HttpRequest request = HttpRequest.newBuilder().uri(URI.create(resourceUrl)).build();
                HttpResponse<byte[]> response = httpClient.send(request, HttpResponse.BodyHandlers.ofByteArray());
                if (response.statusCode() == 200) {
                    consumer.accept(response.body());
                }
            } catch (Exception e) {
                logger.warning("Failed to inline resource " + resourceUrl + ": " + e.getMessage());
            }
        }

        @FunctionalInterface interface ResourceConsumer<T> { void accept(T t) throws Exception; }
        @FunctionalInterface interface ResourceConsumerBytes<T> { void accept(T t) throws Exception; }
    }

    // Inner class for generating certificates
    static class CertificateGenerator {
        public static void generate(Path keyStorePath, String password, String alias, String domainName, String org, String locality, String state, String country) throws Exception {
            KeyPairGenerator keyGen = KeyPairGenerator.getInstance("RSA");
            keyGen.initialize(2048, new SecureRandom());
            KeyPair keyPair = keyGen.generateKeyPair();

            Instant now = Instant.now();
            Date notBefore = Date.from(now);
            Date notAfter = Date.from(now.plus(700, ChronoUnit.DAYS));

            X500Name issuer = new X500Name(String.format("CN=%s, O=%s, L=%s, ST=%s, C=%s", domainName, org, locality, state, country));
            BigInteger serial = new BigInteger(64, new SecureRandom());

            X509v3CertificateBuilder certBuilder = new X509v3CertificateBuilder(
                    issuer, serial, notBefore, notAfter, issuer,
                    SubjectPublicKeyInfo.getInstance(keyPair.getPublic().getEncoded())
            );

            ContentSigner signer = new JcaContentSignerBuilder("SHA256WithRSA").build(keyPair.getPrivate());
            X509Certificate cert = new JcaX509CertificateConverter().setProvider("BC").getCertificate(certBuilder.build(signer));

            KeyStore keyStore = KeyStore.getInstance("JKS");
            keyStore.load(null, null); // Initialize new keystore
            keyStore.setKeyEntry(alias, keyPair.getPrivate(), password.toCharArray(), new Certificate[]{cert});

            try (FileOutputStream fos = new FileOutputStream(keyStorePath.toFile())) {
                keyStore.store(fos, password.toCharArray());
            }
        }
    }
}