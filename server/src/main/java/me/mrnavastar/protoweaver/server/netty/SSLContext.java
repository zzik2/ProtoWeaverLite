package me.mrnavastar.protoweaver.server.netty;

import io.netty.handler.ssl.*;
import lombok.Cleanup;
import lombok.Getter;
import lombok.SneakyThrows;
import me.mrnavastar.protoweaver.core.util.ProtoLogger;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.pkcs.PrivateKeyInfo;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.BasicConstraints;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.openssl.PEMKeyPair;
import org.bouncycastle.openssl.PEMParser;
import org.bouncycastle.openssl.jcajce.JcaPEMKeyConverter;
import org.bouncycastle.openssl.jcajce.JcaPEMWriter;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;

import java.io.*;
import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.security.*;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.*;

public class SSLContext {

    @Getter
    private static io.netty.handler.ssl.SslContext context;
    private static final Provider provider = new BouncyCastleProvider();

    // These https://wiki.mozilla.org/Security/Server_Side_TLS#Intermediate_compatibility_.28recommended.29
    // Minus These https://datatracker.ietf.org/doc/html/rfc7540#appendix-A
    private static final List<String> CIPHERS = List.of(
            "TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256",
            "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256",
            "TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384",
            "TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384",
            "TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256",
            "TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256",
            "TLS_AES_128_GCM_SHA256",
            "TLS_AES_256_GCM_SHA384",
            "TLS_CHACHA20_POLY1305_SHA256"
    );

    @SneakyThrows
    public static void init(String dir) {
        String keyValue = System.getenv("PROTOWEAVER_PRIVATE_KEY");
        String certValue = System.getenv("PROTOWEAVER_CERT");
        boolean environmentKeys = keyValue != null && certValue != null;
        if (!environmentKeys) genKeys(dir);

        try (InputStream privateKey = environmentKeys ? new ByteArrayInputStream(keyValue.getBytes(StandardCharsets.UTF_8)) : new FileInputStream(new File(dir, "private.pem"));
             InputStream cert = environmentKeys ? new ByteArrayInputStream(certValue.getBytes(StandardCharsets.UTF_8)) : new FileInputStream(new File(dir, "cert.pem"))) {
            context = SslContextBuilder.forServer(readPrivateKey(privateKey), readCertificates(cert))
                    .sslProvider(OpenSsl.isAvailable() ? SslProvider.OPENSSL : SslProvider.JDK)
                    .ciphers(CIPHERS, SupportedCipherSuiteFilter.INSTANCE)
                    .applicationProtocolConfig(new ApplicationProtocolConfig(
                            ApplicationProtocolConfig.Protocol.ALPN,
                            ApplicationProtocolConfig.SelectorFailureBehavior.NO_ADVERTISE,
                            ApplicationProtocolConfig.SelectedListenerFailureBehavior.ACCEPT,
                            ApplicationProtocolNames.HTTP_2)
                    ).build();
        }
    }

    private static void genKeys(String dir) throws NoSuchAlgorithmException, CertificateException, IOException, OperatorCreationException {
        File privateKeyFile = new File(dir + "/private.pem");
        File certFile = new File(dir + "/cert.pem");

        if (!privateKeyFile.exists() || !certFile.exists()) {
            KeyPairGenerator kpg = KeyPairGenerator.getInstance("RSA");
            kpg.initialize(2048);
            KeyPair kp = kpg.generateKeyPair();
            X509Certificate certificate = genCert(kp);

            ProtoLogger.info("Generating SSL Keys");
            privateKeyFile.getParentFile().mkdirs();

            @Cleanup JcaPEMWriter privateWriter = new JcaPEMWriter(new FileWriter(privateKeyFile));
            @Cleanup JcaPEMWriter certWriter = new JcaPEMWriter(new FileWriter(certFile));
            privateWriter.writeObject(kp.getPrivate());
            certWriter.writeObject(certificate);
        }
    }

    private static PrivateKey readPrivateKey(InputStream input) throws IOException {
        JcaPEMKeyConverter converter = new JcaPEMKeyConverter().setProvider(provider);
        try (PEMParser parser = new PEMParser(new InputStreamReader(input, StandardCharsets.US_ASCII))) {
            Object value;
            while ((value = parser.readObject()) != null) {
                if (value instanceof PEMKeyPair pair) return converter.getKeyPair(pair).getPrivate();
                if (value instanceof PrivateKeyInfo key) return converter.getPrivateKey(key);
            }
        }
        throw new IOException("No unencrypted private key found in PEM input");
    }

    private static X509Certificate[] readCertificates(InputStream input) throws IOException, CertificateException {
        List<X509Certificate> certificates = new ArrayList<>();
        JcaX509CertificateConverter converter = new JcaX509CertificateConverter().setProvider(provider);
        try (PEMParser parser = new PEMParser(new InputStreamReader(input, StandardCharsets.US_ASCII))) {
            Object value;
            while ((value = parser.readObject()) != null) {
                if (value instanceof X509CertificateHolder certificate) certificates.add(converter.getCertificate(certificate));
            }
        }
        if (certificates.isEmpty()) throw new CertificateException("No X.509 certificates found in PEM input");
        return certificates.toArray(X509Certificate[]::new);
    }

    // From https://stackoverflow.com/questions/29852290/self-signed-x509-certificate-with-bouncy-castle-in-java
    private static X509Certificate genCert(KeyPair keyPair) throws OperatorCreationException, CertificateException, IOException {
        long now = System.currentTimeMillis();
        Date startDate = new Date(now);
        Calendar calendar = Calendar.getInstance();
        calendar.setTime(startDate);
        calendar.add(Calendar.YEAR, 999);
        Date endDate = calendar.getTime();

        X500Name dnName = new X500Name("CN=PROTOWEAVER");
        ContentSigner contentSigner = new JcaContentSignerBuilder("SHA256WithRSA").setProvider(provider).build(keyPair.getPrivate());
        JcaX509v3CertificateBuilder certBuilder = new JcaX509v3CertificateBuilder(dnName, new BigInteger(Long.toString(now)), startDate, endDate, dnName, keyPair.getPublic());
        certBuilder.addExtension(new ASN1ObjectIdentifier("2.5.29.19"), true, new BasicConstraints(true));

        return new JcaX509CertificateConverter().setProvider(provider).getCertificate(certBuilder.build(contentSigner));
    }
}
