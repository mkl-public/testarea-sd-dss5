package mkl.testarea.sddss5.pdf;

import java.io.IOException;
import java.io.InputStream;
import java.util.List;

import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;

import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.model.InMemoryDocument;
import eu.europa.esig.dss.pades.validation.PdfModification;
import eu.europa.esig.dss.pades.validation.PdfModificationDetection;
import eu.europa.esig.dss.pades.validation.PdfRevision;
import eu.europa.esig.dss.pdf.PDFServiceMode;
import eu.europa.esig.dss.pdf.pdfbox.PdfBoxSignatureService;
import eu.europa.esig.dss.pdf.pdfbox.visible.defaultdrawer.PdfBoxDefaultSignatureDrawerFactory;

class DSS2400 {

    @BeforeAll
    static void setUpBeforeClass() throws Exception {
    }

    /**
     * <a href="https://ec.europa.eu/cefdigital/tracker/browse/DSS-2400">
     * Validator fails format on PDF page count wrongly(?)
     * </a>
     * <br/>
     * <a href="https://ec.europa.eu/cefdigital/tracker/secure/attachment/48617/DSS58_FailValidateFormat.pdf">
     * DSS58_FailValidateFormat.pdf
     * </a>
     * <p>
     * Indeed, due to DSS-2375 non-final revisions are extracted incorrectly
     * and PDFBox tries to repair them. The repair results, though, sometimes
     * don't match the actual signed revision. In this case, for example, the
     * "repaired" version has a page count of 0.
     * </p>
     */
    @Test
    void testPdfboxDSS58_FailValidateFormat() throws IOException {
        System.out.printf("***\n*** %s\n***\n", "DSS58_FailValidateFormat.pdf");

        try (   InputStream resource = getClass().getResourceAsStream("DSS58_FailValidateFormat.pdf")   ) {
            DSSDocument document = new InMemoryDocument(resource);

            PdfBoxSignatureService signatureService = new PdfBoxSignatureService(PDFServiceMode.SIGNATURE, new PdfBoxDefaultSignatureDrawerFactory());

            List<PdfRevision> revisions = signatureService.getRevisions(document, null);
            printRevisions(revisions);
        }
    }

    /**
     * <a href="https://ec.europa.eu/cefdigital/tracker/browse/DSS-2400">
     * Validator fails format on PDF page count wrongly(?)
     * </a>
     * <br/>
     * <a href="https://ec.europa.eu/cefdigital/tracker/secure/attachment/48616/DSS58_PassValidateFormat.pdf">
     * DSS58_PassValidateFormat.pdf
     * </a>
     * <p>
     * Indeed, due to DSS-2375 non-final revisions are extracted incorrectly
     * and PDFBox tries to repair them. Sometimes repair fails completely and
     * no comparisons are made, for example in this case.
     * </p>
     */
    @Test
    void testPdfboxDSS58_PassValidateFormat() throws IOException {
        System.out.printf("***\n*** %s\n***\n", "DSS58_PassValidateFormat.pdf");

        try (   InputStream resource = getClass().getResourceAsStream("DSS58_PassValidateFormat.pdf")   ) {
            DSSDocument document = new InMemoryDocument(resource);

            PdfBoxSignatureService signatureService = new PdfBoxSignatureService(PDFServiceMode.SIGNATURE, new PdfBoxDefaultSignatureDrawerFactory());

            List<PdfRevision> revisions = signatureService.getRevisions(document, null);
            printRevisions(revisions);
        }
    }

    void printRevisions(List<PdfRevision> revisions ) {
        for (PdfRevision revision : revisions) {
            System.out.printf("*\n* %s\n***\n", revision.getFieldNames());
            PdfModificationDetection modificationDetection = revision.getModificationDetection();
            if (modificationDetection != null && modificationDetection.areModificationsDetected()) {
                System.out.println("Modifications detected:");
                List<PdfModification> annotationOverlaps = modificationDetection.getAnnotationOverlaps();
                if (annotationOverlaps != null && !annotationOverlaps.isEmpty()) {
                    System.out.print("Annotation overlaps:");
                    for (PdfModification modification : annotationOverlaps) {
                        System.out.printf(" %d", modification.getPage());
                    }
                    System.out.println();
                }
                List<PdfModification> pageDifferences = modificationDetection.getPageDifferences();
                if (pageDifferences != null && !pageDifferences.isEmpty()) {
                    System.out.print("Page differences:");
                    for (PdfModification modification : pageDifferences) {
                        System.out.printf(" %d", modification.getPage());
                    }
                    System.out.println();
                }
                List<PdfModification> visualDifferences = modificationDetection.getVisualDifferences();
                if (visualDifferences != null && !visualDifferences.isEmpty()) {
                    System.out.print("Visual differences:");
                    for (PdfModification modification : visualDifferences) {
                        System.out.printf(" %d", modification.getPage());
                    }
                    System.out.println();
                }
            } else {
                System.out.println("No modifications detected.");
            }
        }
    }
}
