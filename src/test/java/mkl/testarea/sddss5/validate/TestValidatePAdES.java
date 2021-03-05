package mkl.testarea.sddss5.validate;

import static java.util.Collections.singleton;

import java.io.File;
import java.io.IOException;
import java.io.InputStream;
import java.nio.charset.Charset;
import java.nio.file.Files;
import java.security.Security;
import java.util.Arrays;
import java.util.function.Consumer;

import org.apache.http.conn.ssl.TrustAllStrategy;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.junit.Assert;
import org.junit.BeforeClass;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.Parameterized;
import org.junit.runners.Parameterized.Parameter;
import org.junit.runners.Parameterized.Parameters;

import eu.europa.esig.dss.enumerations.Indication;
import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.model.DSSException;
import eu.europa.esig.dss.model.InMemoryDocument;
import eu.europa.esig.dss.service.crl.OnlineCRLSource;
import eu.europa.esig.dss.service.http.commons.CommonsDataLoader;
import eu.europa.esig.dss.service.http.commons.FileCacheDataLoader;
import eu.europa.esig.dss.service.http.commons.OCSPDataLoader;
import eu.europa.esig.dss.service.ocsp.OnlineOCSPSource;
import eu.europa.esig.dss.simplereport.SimpleReport;
import eu.europa.esig.dss.spi.client.http.DSSFileLoader;
import eu.europa.esig.dss.spi.client.http.IgnoreDataLoader;
import eu.europa.esig.dss.spi.tsl.TrustedListsCertificateSource;
import eu.europa.esig.dss.spi.x509.CertificateSource;
import eu.europa.esig.dss.spi.x509.KeyStoreCertificateSource;
import eu.europa.esig.dss.tsl.alerts.LOTLAlert;
import eu.europa.esig.dss.tsl.alerts.TLAlert;
import eu.europa.esig.dss.tsl.alerts.detections.LOTLLocationChangeDetection;
import eu.europa.esig.dss.tsl.alerts.detections.OJUrlChangeDetection;
import eu.europa.esig.dss.tsl.alerts.detections.TLExpirationDetection;
import eu.europa.esig.dss.tsl.alerts.detections.TLSignatureErrorDetection;
import eu.europa.esig.dss.tsl.alerts.handlers.log.LogLOTLLocationChangeAlertHandler;
import eu.europa.esig.dss.tsl.alerts.handlers.log.LogOJUrlChangeAlertHandler;
import eu.europa.esig.dss.tsl.alerts.handlers.log.LogTLExpirationAlertHandler;
import eu.europa.esig.dss.tsl.alerts.handlers.log.LogTLSignatureErrorAlertHandler;
import eu.europa.esig.dss.tsl.cache.CacheCleaner;
import eu.europa.esig.dss.tsl.function.OfficialJournalSchemeInformationURI;
import eu.europa.esig.dss.tsl.job.TLValidationJob;
import eu.europa.esig.dss.tsl.source.LOTLSource;
import eu.europa.esig.dss.tsl.sync.AcceptAllStrategy;
import eu.europa.esig.dss.validation.CommonCertificateVerifier;
import eu.europa.esig.dss.validation.SignedDocumentValidator;
import eu.europa.esig.dss.validation.reports.Reports;

/**
 * @author mkl
 */
@RunWith(Parameterized.class)
public class TestValidatePAdES
{
    final static File OUTPUTDIR = new File("target/test-outputs/validate");
    final static TrustedListsCertificateSource LOTL = new TrustedListsCertificateSource();

    @BeforeClass
    public static void setUpBeforeClass() throws Exception
    {
        if (Security.getProvider(BouncyCastleProvider.PROVIDER_NAME) == null)
        {
            Security.addProvider(new BouncyCastleProvider());
            //Security.insertProviderAt(new BouncyCastleProvider(), 1);
        }
        OUTPUTDIR.mkdirs();

        TLValidationJob job = new TLValidationJob();
        job.setOfflineDataLoader(offlineLoader());
        job.setOnlineDataLoader(onlineLoader());
        job.setTrustedListCertificateSource(LOTL);
        job.setSynchronizationStrategy(new AcceptAllStrategy());
        job.setCacheCleaner(cacheCleaner());

        LOTLSource europeanLOTL = europeanLOTL("src/test/resources/keystore.p12", "PKCS12", "dss-password",
                "https://ec.europa.eu/tools/lotl/eu-lotl.xml",
                "https://eur-lex.europa.eu/legal-content/EN/TXT/?uri=uriserv:OJ.C_.2019.276.01.0001.01.ENG");
        job.setListOfTrustedListSources(europeanLOTL);

        job.setLOTLAlerts(Arrays.asList(ojUrlAlert(europeanLOTL), lotlLocationAlert(europeanLOTL)));
        job.setTLAlerts(Arrays.asList(tlSigningAlert(), tlExpirationDetection()));
        job.onlineRefresh();

        // For PLAIN-ECDSA
//        Field OID_ALGORITHMS = SignatureAlgorithm.class.getDeclaredField("OID_ALGORITHMS");
//        OID_ALGORITHMS.setAccessible(true);
//        @SuppressWarnings("unchecked")
//        Map<String, SignatureAlgorithm> map = (Map<String, SignatureAlgorithm>) OID_ALGORITHMS.get(null);
//        map.put("0.4.0.127.0.7.1.1.4.1.3", SignatureAlgorithm.ECDSA_SHA256);
    }

    //
    // helpers
    //
    public static CacheCleaner cacheCleaner() {
        CacheCleaner cacheCleaner = new CacheCleaner();
        cacheCleaner.setCleanMemory(true);
        cacheCleaner.setCleanFileSystem(true);
        cacheCleaner.setDSSFileLoader(offlineLoader());
        return cacheCleaner;
    }

    public static CommonsDataLoader dataLoader() {
        CommonsDataLoader commonsDataLoader = new CommonsDataLoader();
        commonsDataLoader.setTrustStrategy(new TrustAllStrategy());
        return commonsDataLoader;
    } 

    public static LOTLSource europeanLOTL(String keystoreFile, String keystoreType, String keyStorePassword, String lotlUrl, String ojUrl) {
        LOTLSource lotlSource = new LOTLSource();
        lotlSource.setUrl(lotlUrl);
        lotlSource.setCertificateSource(officialJournalContentKeyStore(keystoreFile, keystoreType, keyStorePassword));
//        lotlSource.setCertificateSource(new CommonCertificateSource());
        lotlSource.setSigningCertificatesAnnouncementPredicate(new OfficialJournalSchemeInformationURI(ojUrl));
        lotlSource.setPivotSupport(true);
        return lotlSource;
    }

    public static CertificateSource officialJournalContentKeyStore(String keystoreFile, String keystoreType, String keyStorePassword) {
        try {
            return new KeyStoreCertificateSource(new File(keystoreFile), keystoreType, keyStorePassword);
        } catch (IOException e) {
            throw new DSSException("Unable to load the keystore", e);
        }
    }

    public static DSSFileLoader offlineLoader() {
        FileCacheDataLoader offlineFileLoader = new FileCacheDataLoader();
        offlineFileLoader.setCacheExpirationTime(Long.MAX_VALUE);
        offlineFileLoader.setDataLoader(new IgnoreDataLoader());
        offlineFileLoader.setFileCacheDirectory(tlCacheDirectory());
        return offlineFileLoader;
    }

    public static LOTLAlert ojUrlAlert(LOTLSource source) {
        OJUrlChangeDetection ojUrlDetection = new OJUrlChangeDetection(source);
        LogOJUrlChangeAlertHandler handler = new LogOJUrlChangeAlertHandler();
        return new LOTLAlert(ojUrlDetection, handler);
    }

    public static LOTLAlert lotlLocationAlert(LOTLSource source) {
        LOTLLocationChangeDetection lotlLocationDetection = new LOTLLocationChangeDetection(source);
        LogLOTLLocationChangeAlertHandler handler = new LogLOTLLocationChangeAlertHandler();
        return new LOTLAlert(lotlLocationDetection, handler);
    }
 

    public static DSSFileLoader onlineLoader() {
        FileCacheDataLoader onlineFileLoader = new FileCacheDataLoader();
        onlineFileLoader.setCacheExpirationTime(0);
        onlineFileLoader.setDataLoader(dataLoader());
        onlineFileLoader.setFileCacheDirectory(tlCacheDirectory());
        return onlineFileLoader;
    } 

    public static File tlCacheDirectory() {
        File rootFolder = new File(System.getProperty("java.io.tmpdir"));
        File tslCache = new File(rootFolder, "dss-tsl-loader");
        tslCache.mkdirs();
        return tslCache;
    }

    public static TLAlert tlSigningAlert() {
        TLSignatureErrorDetection signingDetection = new TLSignatureErrorDetection();
        LogTLSignatureErrorAlertHandler handler = new LogTLSignatureErrorAlertHandler();
        return new TLAlert(signingDetection, handler);
    }

    public static TLAlert tlExpirationDetection() {
        TLExpirationDetection expirationDetection = new TLExpirationDetection();
        LogTLExpirationAlertHandler handler = new LogTLExpirationAlertHandler();
        return new TLAlert(expirationDetection, handler);
    }


    @Parameters(name = "{index}: Validate signed PDF {0}")
    public static Object[][] data()
    {
        return new Object[][]
        {
            // Pades LTV verification in iTextSharp throws Public key presented not for certificate signature for root CA certificate
            // http://stackoverflow.com/questions/41548918/pades-ltv-verification-in-itextsharp-throws-public-key-presented-not-for-certifi
            {"pdfa2b_instance_signed_ltv_sample.pdf", (Consumer<Reports>) TestValidatePAdES::simpleIndicationIndeterminate},
            // some PDF, Signamus signed, Adobe LTV enabled
            {"pdf-exceetLegacySigned-ltvEnabled.pdf", (Consumer<Reports>) TestValidatePAdES::simpleIndicationTotalPassed},
            // some PDF, SLMBC signed, ECDSA signature
            {"pdf-exceetLegacySigned-ECDSA.pdf", (Consumer<Reports>) TestValidatePAdES::simpleIndicationTotalPassed},
            // some PDF, ISAF signed, RSAwithSHA256andMGF1, test CA (and, therefore, indeterminate)
            {"pdf-exceetLegacySigned-RSASSA-test.pdf", (Consumer<Reports>) TestValidatePAdES::simpleIndicationIndeterminate},
            // some PDF, SecCommerce signed, PLAIN-ECDSA signature
            {"pdf-secCommerceLegacySigned-PLAIN.pdf", (Consumer<Reports>) TestValidatePAdES::simpleIndicationIndeterminate}
        };
    }

    public static void simpleIndicationIndeterminate(Reports reports)
    {
        SimpleReport simple = reports.getSimpleReport();
        Assert.assertEquals("Unexpected simple report indication", Indication.INDETERMINATE, simple.getIndication(simple.getFirstSignatureId()));
    }

    public static void simpleIndicationTotalPassed(Reports reports)
    {
        SimpleReport simple = reports.getSimpleReport();
        Assert.assertEquals("Unexpected simple report indication", Indication.TOTAL_PASSED, simple.getIndication(simple.getFirstSignatureId()));
    }

    @Parameter(0)
    public String pdfResourceName;

    @Parameter(1)
    public Consumer<Reports> reportsAssertion;

    @Test
    public void testValidateEuLOTL() throws IOException
    {
        try (   InputStream resource = getClass().getResourceAsStream(pdfResourceName))
        {
            DSSDocument document = new InMemoryDocument(resource, pdfResourceName);

            OnlineOCSPSource ocspSource = new OnlineOCSPSource();
            ocspSource.setDataLoader(new OCSPDataLoader());

            OnlineCRLSource crlSource = new OnlineCRLSource();
            crlSource.setDataLoader(new CommonsDataLoader());

            CommonCertificateVerifier verifier = new CommonCertificateVerifier();
            verifier.setCrlSource(crlSource);
            verifier.setDataLoader(new CommonsDataLoader());
            verifier.setOcspSource(ocspSource);
            verifier.setTrustedCertSources(LOTL);

            SignedDocumentValidator validator = SignedDocumentValidator.fromDocument(document);
            // validation at claimed signing time
            validator.setValidationTime(validator.getSignatures().get(0).getSigningTime());
            validator.setCertificateVerifier(verifier);

            Reports reports = validator.validateDocument();
            Files.write(new File(OUTPUTDIR, pdfResourceName + "-simple.xml").toPath(), singleton(reports.getXmlSimpleReport()), Charset.forName("UTF8"));
            Files.write(new File(OUTPUTDIR, pdfResourceName + "-detailed.xml").toPath(), singleton(reports.getXmlDetailedReport()), Charset.forName("UTF8"));
            Files.write(new File(OUTPUTDIR, pdfResourceName + "-diagnostic.xml").toPath(), singleton(reports.getXmlDiagnosticData()), Charset.forName("UTF8"));

            reportsAssertion.accept(reports);
        } catch (Throwable e) {
            e.printStackTrace();
            throw e;
        }
    }
}
