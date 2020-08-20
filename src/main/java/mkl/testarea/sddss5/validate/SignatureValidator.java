package mkl.testarea.sddss5.validate;

import static java.util.Collections.singleton;

import java.io.File;
import java.io.IOException;
import java.nio.charset.Charset;
import java.nio.file.Files;
import java.security.Security;
import java.util.Arrays;

import org.bouncycastle.jce.provider.BouncyCastleProvider;

import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.model.DSSException;
import eu.europa.esig.dss.model.FileDocument;
import eu.europa.esig.dss.service.crl.OnlineCRLSource;
import eu.europa.esig.dss.service.http.commons.CommonsDataLoader;
import eu.europa.esig.dss.service.http.commons.FileCacheDataLoader;
import eu.europa.esig.dss.service.http.commons.OCSPDataLoader;
import eu.europa.esig.dss.service.ocsp.OnlineOCSPSource;
import eu.europa.esig.dss.spi.client.http.DSSFileLoader;
import eu.europa.esig.dss.spi.client.http.IgnoreDataLoader;
import eu.europa.esig.dss.spi.tsl.TrustedListsCertificateSource;
import eu.europa.esig.dss.spi.x509.CertificateSource;
import eu.europa.esig.dss.spi.x509.CommonCertificateSource;
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
 * This class validates the (hopefully signed) PDFs on the command line.
 * 
 * @author mkl
 */
public class SignatureValidator {
    final static TrustedListsCertificateSource LOTL = new TrustedListsCertificateSource();

    public static void initialize()
    {
        try {
            if (Security.getProvider(BouncyCastleProvider.PROVIDER_NAME) == null)
            {
                Security.addProvider(new BouncyCastleProvider());
                //Security.insertProviderAt(new BouncyCastleProvider(), 1);
            }

            TLValidationJob job = new TLValidationJob();
            job.setOfflineDataLoader(offlineLoader());
            job.setOnlineDataLoader(onlineLoader());
            job.setTrustedListCertificateSource(LOTL);
            job.setSynchronizationStrategy(new AcceptAllStrategy());
            job.setCacheCleaner(cacheCleaner());

            LOTLSource europeanLOTL = europeanLOTL();
            job.setListOfTrustedListSources(europeanLOTL);

            job.setLOTLAlerts(Arrays.asList(ojUrlAlert(europeanLOTL), lotlLocationAlert(europeanLOTL)));
            job.setTLAlerts(Arrays.asList(tlSigningAlert(), tlExpirationDetection()));

            job.onlineRefresh();
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }

    private static final String LOTL_URL = "https://ec.europa.eu/tools/lotl/eu-lotl.xml";
    private static final String OJ_URL = "https://eur-lex.europa.eu/legal-content/EN/TXT/?uri=uriserv:OJ.C_.2019.276.01.0001.01.ENG";

    public static LOTLSource europeanLOTL() {
        LOTLSource lotlSource = new LOTLSource();
        lotlSource.setUrl(LOTL_URL);
        lotlSource.setCertificateSource(officialJournalContentKeyStore());
//        lotlSource.setCertificateSource(new CommonCertificateSource());
        lotlSource.setSigningCertificatesAnnouncementPredicate(new OfficialJournalSchemeInformationURI(OJ_URL));
        lotlSource.setPivotSupport(true);
        return lotlSource;
    }

    public static CertificateSource officialJournalContentKeyStore() {
        try {
            return new KeyStoreCertificateSource(new File("src/test/resources/keystore.p12"), "PKCS12", "dss-password");
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
        if (tslCache.mkdirs()) {
//            LOG.info("TL Cache folder : {}", tslCache.getAbsolutePath());
        }
        return tslCache;
    }

    public static CommonsDataLoader dataLoader() {
        return new CommonsDataLoader();
    } 

    public static CacheCleaner cacheCleaner() {
        CacheCleaner cacheCleaner = new CacheCleaner();
        cacheCleaner.setCleanMemory(true);
        cacheCleaner.setCleanFileSystem(true);
        cacheCleaner.setDSSFileLoader(offlineLoader());
        return cacheCleaner;
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
 
    public static void main(String[] args) throws IOException {
        initialize();
        for (String arg: args)
        {
            final File file = new File(arg);
            if (file.exists())
            {
                SignatureValidator validator = new SignatureValidator(file);
                Reports reports = validator.validate();

                Files.write(new File(file.getParent(), file.getName() + "-simple.xml").toPath(), singleton(reports.getXmlSimpleReport()), Charset.forName("UTF8"));
                Files.write(new File(file.getParent(), file.getName() + "-detailed.xml").toPath(), singleton(reports.getXmlDetailedReport()), Charset.forName("UTF8"));
                Files.write(new File(file.getParent(), file.getName() + "-diagnostic.xml").toPath(), singleton(reports.getXmlDiagnosticData()), Charset.forName("UTF8"));
            }
        }
    }

    public SignatureValidator(File file) {
        this.file = file;
    }

    public Reports validate() {
        DSSDocument document = new FileDocument(file);

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
//        validator.provideProcessExecutorInstance().setCurrentTime(validator.getSignatures().get(0).getSigningTime());
        validator.setCertificateVerifier(verifier);

        return validator.validateDocument(validationPolicyName);
    }

    final File file;
    String validationPolicyName = null;
}
