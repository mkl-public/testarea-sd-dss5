package mkl.testarea.sddss5.validate;

import static java.util.Collections.singleton;

import java.io.File;
import java.io.IOException;
import java.lang.reflect.Field;
import java.nio.charset.Charset;
import java.nio.file.Files;
import java.security.Security;
import java.util.Map;

import org.bouncycastle.jce.provider.BouncyCastleProvider;

import eu.europa.esig.dss.DSSDocument;
import eu.europa.esig.dss.FileDocument;
import eu.europa.esig.dss.SignatureAlgorithm;
import eu.europa.esig.dss.client.crl.OnlineCRLSource;
import eu.europa.esig.dss.client.http.commons.CommonsDataLoader;
import eu.europa.esig.dss.client.http.commons.OCSPDataLoader;
import eu.europa.esig.dss.client.ocsp.OnlineOCSPSource;
import eu.europa.esig.dss.tsl.TrustedListsCertificateSource;
import eu.europa.esig.dss.tsl.service.TSLRepository;
import eu.europa.esig.dss.tsl.service.TSLValidationJob;
import eu.europa.esig.dss.validation.CommonCertificateVerifier;
import eu.europa.esig.dss.validation.SignedDocumentValidator;
import eu.europa.esig.dss.validation.reports.Reports;
import eu.europa.esig.dss.x509.KeyStoreCertificateSource;

/**
 * This class validates the (hopefully signed) PDFs on the command line.
 * 
 * @author mkl
 */
public class SignatureValidator {
    final static TrustedListsCertificateSource LOTL = new TrustedListsCertificateSource();

    static
    {
        try {
            if (Security.getProvider(BouncyCastleProvider.PROVIDER_NAME) == null)
            {
                //Security.addProvider(new BouncyCastleProvider());
                Security.insertProviderAt(new BouncyCastleProvider(), 1);
            }

            // The keystore contains certificates extracted from the OJ
            KeyStoreCertificateSource keyStoreCertificateSource = new KeyStoreCertificateSource(new File("src/test/resources/keystore.p12"), "PKCS12", "dss-password");
            TSLRepository tslRepository = new TSLRepository();
            tslRepository.setTrustedListsCertificateSource(LOTL);
            TSLValidationJob job = new TSLValidationJob();
            job.setDataLoader(new CommonsDataLoader());
            job.setOjContentKeyStore(keyStoreCertificateSource);
            job.setLotlRootSchemeInfoUri("https://ec.europa.eu/information_society/policy/esignature/trusted-list/tl.html");
            job.setLotlUrl("https://ec.europa.eu/information_society/policy/esignature/trusted-list/tl-mp.xml");
            job.setOjUrl("http://eur-lex.europa.eu/legal-content/EN/TXT/?uri=uriserv:OJ.C_.2016.233.01.0001.01.ENG");
            job.setLotlCode("EU");
            job.setRepository(tslRepository);
            job.refresh();

            // For PLAIN-ECDSA
            Field OID_ALGORITHMS = SignatureAlgorithm.class.getDeclaredField("OID_ALGORITHMS");
            OID_ALGORITHMS.setAccessible(true);
            @SuppressWarnings("unchecked")
            Map<String, SignatureAlgorithm> map = (Map<String, SignatureAlgorithm>) OID_ALGORITHMS.get(null);
            map.put("0.4.0.127.0.7.1.1.4.1.3", SignatureAlgorithm.ECDSA_SHA256);
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }

    public static void main(String[] args) throws IOException {
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
        verifier.setTrustedCertSource(LOTL);

        SignedDocumentValidator validator = SignedDocumentValidator.fromDocument(document);
        // validation at claimed signing time
//        validator.provideProcessExecutorInstance().setCurrentTime(validator.getSignatures().get(0).getSigningTime());
        validator.setCertificateVerifier(verifier);

        return validator.validateDocument(validationPolicyName);
    }

    final File file;
    String validationPolicyName = null;
}
