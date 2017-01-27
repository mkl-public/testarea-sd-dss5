package mkl.testarea.sddss4.validate;

import static java.util.Collections.singleton;

import java.io.File;
import java.io.IOException;
import java.io.InputStream;
import java.nio.charset.Charset;
import java.nio.file.Files;
import java.util.function.Predicate;

import org.junit.Assert;
import org.junit.BeforeClass;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.Parameterized;
import org.junit.runners.Parameterized.Parameter;
import org.junit.runners.Parameterized.Parameters;

import eu.europa.esig.dss.DSSDocument;
import eu.europa.esig.dss.InMemoryDocument;
import eu.europa.esig.dss.client.crl.OnlineCRLSource;
import eu.europa.esig.dss.client.http.commons.CommonsDataLoader;
import eu.europa.esig.dss.client.http.commons.OCSPDataLoader;
import eu.europa.esig.dss.client.ocsp.OnlineOCSPSource;
import eu.europa.esig.dss.tsl.TrustedListsCertificateSource;
import eu.europa.esig.dss.tsl.service.TSLRepository;
import eu.europa.esig.dss.tsl.service.TSLValidationJob;
import eu.europa.esig.dss.validation.CommonCertificateVerifier;
import eu.europa.esig.dss.validation.SignedDocumentValidator;
import eu.europa.esig.dss.validation.policy.rules.Indication;
import eu.europa.esig.dss.validation.reports.Reports;
import eu.europa.esig.dss.validation.reports.SimpleReport;
import eu.europa.esig.dss.x509.KeyStoreCertificateSource;

/**
 * @author mkl
 */
@RunWith(Parameterized.class)
public class TestValidatePAdES
{
    final static File OUTPUTDIR = new File("target/test-outputs/validate");
    final static TrustedListsCertificateSource TOTL = new TrustedListsCertificateSource();

    @BeforeClass
    public static void setUpBeforeClass() throws Exception
    {
        OUTPUTDIR.mkdirs();

        // The keystore contains certificates extracted from the OJ
        KeyStoreCertificateSource keyStoreCertificateSource = new KeyStoreCertificateSource(new File("src/test/resources/keystore.p12"), "PKCS12", "dss-password");
        TSLRepository tslRepository = new TSLRepository();
        tslRepository.setTrustedListsCertificateSource(TOTL);
        TSLValidationJob job = new TSLValidationJob();
        job.setDataLoader(new CommonsDataLoader());
        job.setDssKeyStore(keyStoreCertificateSource);
        job.setLotlUrl("https://ec.europa.eu/information_society/policy/esignature/trusted-list/tl-mp.xml");
        job.setLotlCode("EU");
        job.setRepository(tslRepository);
        job.refresh();
    }

    @Parameters(name = "{index}: Validate signed PDF `{0}´")
    public static Object[][] data()
    {
        return new Object[][]
        {
            // Pades LTV verification in iTextSharp throws Public key presented not for certificate signature for root CA certificate
            // http://stackoverflow.com/questions/41548918/pades-ltv-verification-in-itextsharp-throws-public-key-presented-not-for-certifi
            {"pdfa2b_instance_signed_ltv_sample.pdf", (Predicate<Reports>) TestValidatePAdES::simpleIndicationIndeterminate},
            // some PDF, Signamus signed, Adobe LTV enabled
            {"pdf-exceetLegacySigned-ltvEnabled.pdf", (Predicate<Reports>) TestValidatePAdES::simpleIndicationTotalPassed}
        };
    }

    public static boolean simpleIndicationIndeterminate(Reports reports)
    {
        SimpleReport simple = reports.getSimpleReport();
        return simple.getIndication(simple.getFirstSignatureId()).equals(Indication.INDETERMINATE);
    }

    public static boolean simpleIndicationTotalPassed(Reports reports)
    {
        SimpleReport simple = reports.getSimpleReport();
        return simple.getIndication(simple.getFirstSignatureId()).equals(Indication.TOTAL_PASSED);
    }

    @Parameter(0)
    public String pdfResourceName;

    @Parameter(1)
    public Predicate<Reports> reportsAssertion;

    @Test
    public void testValidateEuLOTL() throws IOException
    {
        try (   InputStream resource = getClass().getResourceAsStream(pdfResourceName))
        {
            DSSDocument document = new InMemoryDocument(resource);

            OnlineOCSPSource ocspSource = new OnlineOCSPSource();
            ocspSource.setDataLoader(new OCSPDataLoader());

            OnlineCRLSource crlSource = new OnlineCRLSource();
            crlSource.setDataLoader(new CommonsDataLoader());

            CommonCertificateVerifier verifier = new CommonCertificateVerifier();
            verifier.setCrlSource(crlSource);
            verifier.setDataLoader(new CommonsDataLoader());
            verifier.setOcspSource(ocspSource);
            verifier.setTrustedCertSource(TOTL);

            SignedDocumentValidator validator = SignedDocumentValidator.fromDocument(document);
            validator.setCertificateVerifier(verifier);

            Reports reports = validator.validateDocument();
            Files.write(new File(OUTPUTDIR, pdfResourceName + "-simple.xml").toPath(), singleton(reports.getXmlSimpleReport()), Charset.forName("UTF8"));
            Files.write(new File(OUTPUTDIR, pdfResourceName + "-detailed.xml").toPath(), singleton(reports.getXmlDetailedReport()), Charset.forName("UTF8"));
            Files.write(new File(OUTPUTDIR, pdfResourceName + "-diagnostic.xml").toPath(), singleton(reports.getXmlDiagnosticData()), Charset.forName("UTF8"));

            Assert.assertTrue("Assertion of Reports failed", reportsAssertion.test(reports));
        }
    }
}
