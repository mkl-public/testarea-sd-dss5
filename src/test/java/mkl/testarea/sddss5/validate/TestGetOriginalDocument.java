package mkl.testarea.sddss5.validate;

import java.io.File;
import java.io.IOException;
import java.io.InputStream;
import java.util.List;

import org.junit.BeforeClass;
import org.junit.Test;

import eu.europa.esig.dss.DSSDocument;
import eu.europa.esig.dss.InMemoryDocument;
import eu.europa.esig.dss.validation.AdvancedSignature;
import eu.europa.esig.dss.validation.CommonCertificateVerifier;
import eu.europa.esig.dss.validation.SignedDocumentValidator;
import eu.europa.esig.dss.validation.reports.Reports;
import eu.europa.esig.dss.validation.reports.wrapper.DiagnosticData;

/**
 * @author mkl
 */
public class TestGetOriginalDocument {
    final static File OUTPUTDIR = new File("target/test-outputs/validate");

    @BeforeClass
    public static void setUpBeforeClass() throws Exception {
        OUTPUTDIR.mkdirs();
    }

    /**
     * <a href="https://ec.europa.eu/cefdigital/tracker/browse/DSS-1376">
     * DSS-1376 - PAdES - difference between the validator.getOriginal and the original doc
     * </a>
     * <p>
     * Inspired by DSS-1376 this test applies <code>getOriginalDocuments</code>
     * to a test file in which the original DSS assumption that each signature
     * is applied in an incremental update and each incremental update includes
     * a signature, are not fulfilled: The first document revision here already
     * contains a signature and the first few incremental updates don't.
     * </p>
     */
    @Test
    public void testDSS1376UpdatesForFillins() throws IOException {
        try (   InputStream resource = getClass().getResourceAsStream("DSS1376-updates-for-fillins.pdf")) {
            DSSDocument document = new InMemoryDocument(resource);
            SignedDocumentValidator validator = SignedDocumentValidator.fromDocument(document );
            validator.setCertificateVerifier(new CommonCertificateVerifier());
            Reports reports = validator.validateDocument();
            DiagnosticData diagnosticData = reports.getDiagnosticData();

            for (AdvancedSignature signature : validator.getSignatures())
            {
                List<DSSDocument> sigDocuments = validator.getOriginalDocuments(signature.getId());
                if (sigDocuments.size() == 1)
                    sigDocuments.get(0).save(new File(OUTPUTDIR, signature.getId() + "-Orig.pdf").getAbsolutePath());
                else
                    System.out.printf("%s originals expected: %s, found: %s\n", signature.getId(), 1, sigDocuments.size());
            }
        }
    }

}
