package mkl.testarea.sddss5.pdf;

import java.io.File;
import java.io.IOException;
import java.io.InputStream;
import java.util.List;

import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;

import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.model.InMemoryDocument;
import eu.europa.esig.dss.pades.PAdESUtils;
import eu.europa.esig.dss.pades.validation.timestamp.PdfTimestampToken;
import eu.europa.esig.dss.pdf.PdfDocTimestampRevision;
import eu.europa.esig.dss.validation.CommonCertificateVerifier;
import eu.europa.esig.dss.validation.SignedDocumentValidator;
import eu.europa.esig.dss.validation.timestamp.TimestampToken;

/**
 * @author mkl
 */
class DSS2415 {
    final static File RESULT_FOLDER = new File("target/test-outputs", "pdf");

    @BeforeAll
    static void setUpBeforeClass() throws Exception {
        RESULT_FOLDER.mkdirs();
    }

    /**
     * <a href="https://ec.europa.eu/cefdigital/tracker/browse/DSS-2415">
     * Retrieval of original documents from PAdES w/ removal of timestamps
     * </a>
     * <br/>
     * <a href="https://ec.europa.eu/cefdigital/tracker/secure/attachment/49315/timestamped_and_signed_sigS-E9E310399BD6D23DF05725988F8128699766E467BB42277D87A94182D6E11AFCoriginal1.pdf">
     * timestamped_and_signed_sigS-E9E310399BD6D23DF05725988F8128699766E467BB42277D87A94182D6E11AFCoriginal1.pdf
     * </a>
     * <p>
     * Similar to the <code>RetrieveOriginalDocumentTest</code> example
     * this test shows how to extract "original documents" for document
     * timestamps.
     * </p>
     */
    @Test
    void testExtractFromTimestampedAndSignedSigSE9E310399BD6D23DF05725988F8128699766E467BB42277D87A94182D6E11AFCoriginal1() throws IOException {
        int index = 0;
        try (   InputStream resource = getClass().getResourceAsStream("timestamped_and_signed_sigS-E9E310399BD6D23DF05725988F8128699766E467BB42277D87A94182D6E11AFCoriginal1.pdf")  ) {
            DSSDocument document = new InMemoryDocument(resource);

            SignedDocumentValidator documentValidator = SignedDocumentValidator.fromDocument(document);
            documentValidator.setCertificateVerifier(new CommonCertificateVerifier());

            List<TimestampToken> timestamps = documentValidator.getDetachedTimestamps();
            for (TimestampToken timestamp : timestamps) {
                if (timestamp instanceof PdfTimestampToken) {
                    PdfTimestampToken pdfTimestamp = (PdfTimestampToken) timestamp;
                    PdfDocTimestampRevision revision = pdfTimestamp.getPdfRevision();
                    InMemoryDocument previousRevision = PAdESUtils.getOriginalPDF(revision);
                    previousRevision.save(new File(RESULT_FOLDER, String.format("timestamped_and_signed_sigS-E9E310399BD6D23DF05725988F8128699766E467BB42277D87A94182D6E11AFCoriginal1-%s.pdf", index++)).getAbsolutePath());
                }
            }
        }
    }

}
