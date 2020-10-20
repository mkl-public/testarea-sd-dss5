package mkl.testarea.sddss5.sign;

import java.io.File;
import java.io.IOException;
import java.io.InputStream;
import java.security.KeyStore;
import java.security.KeyStore.PasswordProtection;

import org.apache.pdfbox.cos.COSName;
import org.apache.pdfbox.cos.COSUpdateInfo;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;

import eu.europa.esig.dss.enumerations.DigestAlgorithm;
import eu.europa.esig.dss.enumerations.SignatureLevel;
import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.model.InMemoryDocument;
import eu.europa.esig.dss.model.SignatureValue;
import eu.europa.esig.dss.model.ToBeSigned;
import eu.europa.esig.dss.pades.PAdESSignatureParameters;
import eu.europa.esig.dss.pades.SignatureImageParameters;
import eu.europa.esig.dss.pades.signature.PAdESService;
import eu.europa.esig.dss.token.DSSPrivateKeyEntry;
import eu.europa.esig.dss.token.KeyStoreSignatureTokenConnection;
import eu.europa.esig.dss.token.SignatureTokenConnection;
import eu.europa.esig.dss.validation.CommonCertificateVerifier;

/**
 * @author mkl
 */
public class DSS2260 {
    final static File RESULT_FOLDER = new File("target/test-outputs", "sign");

    @BeforeAll
    static void setUpBeforeClass() throws Exception {
        RESULT_FOLDER.mkdirs();
    }

    /**
     * <a href="https://ec.europa.eu/cefdigital/tracker/browse/DSS-2260">
     * Multiple PADeS signatures with images do not work
     * </a>
     * <br/>
     * <a href="https://ec.europa.eu/cefdigital/tracker/secure/attachment/42608/signed.pdf">
     * signed.pdf
     * </a>, the original (unsigned) revision of which is used as "signed-000.pdf"
     * <br/>
     * <a href="https://issues.apache.org/jira/browse/PDFBOX-4997">
     * Incremental update adds certain objects not marked as needing update
     * </a>
     * <p>
     * This test signs the PDF invisibly. Nothing noteworthy happens.
     * But see {@link #testSignOnceVisible()}.
     * </p>
     */
    @Test
    void testSignOnce() throws IOException {
        try (   InputStream resource = getClass().getResourceAsStream("signed-000.pdf");
                SignatureTokenConnection signingToken = new KeyStoreSignatureTokenConnection(
                        new File("keystores/demo-rsa2048.ks"),
                        KeyStore.getDefaultType(),
                        new PasswordProtection("demo-rsa2048".toCharArray()))   ) {
            DSSDocument toSignDocument = new InMemoryDocument(resource);
            DSSPrivateKeyEntry privateKey = signingToken.getKeys().get(0);

            PAdESSignatureParameters parameters = new PAdESSignatureParameters();
            parameters.setSignatureLevel(SignatureLevel.PAdES_BASELINE_B);
            parameters.setDigestAlgorithm(DigestAlgorithm.SHA256);
            parameters.setSigningCertificate(privateKey.getCertificate());
            parameters.setCertificateChain(privateKey.getCertificateChain());

            CommonCertificateVerifier commonCertificateVerifier = new CommonCertificateVerifier();
            PAdESService service = new PAdESService(commonCertificateVerifier);

            ToBeSigned dataToSign = service.getDataToSign(toSignDocument, parameters);
            DigestAlgorithm digestAlgorithm = parameters.getDigestAlgorithm();
            SignatureValue signatureValue = signingToken.sign(dataToSign, digestAlgorithm, privateKey);
            DSSDocument signedDocument = service.signDocument(toSignDocument, parameters, signatureValue);

            signedDocument.save(new File(RESULT_FOLDER, "signed-000-once.pdf").getAbsolutePath());
        }
    }

    /**
     * <a href="https://ec.europa.eu/cefdigital/tracker/browse/DSS-2260">
     * Multiple PADeS signatures with images do not work
     * </a>
     * <br/>
     * <a href="https://ec.europa.eu/cefdigital/tracker/secure/attachment/42608/signed.pdf">
     * signed.pdf
     * </a>, the original (unsigned) revision of which is used as "signed-000.pdf"
     * <br/>
     * <a href="https://issues.apache.org/jira/browse/PDFBOX-4997">
     * Incremental update adds certain objects not marked as needing update
     * </a>
     * <p>
     * This test signs the PDF with a visual signature. And indeed, the issue
     * DSS-2260 can be reproduced, not only the page object is copied to the
     * incremental update, the object 54 referenced from it is, too.
     * </p>
     * <p>
     * The cause is that the PDFBox incremental update mechanism checks the
     * <code>COSUpdateInfo.isNeedToBeUpdated</code> value and only does not
     * write an object if it has a value of <code>false</code> there.
     * Unfortunately the object 54 only contains a {@link COSName} which does
     * not implement {@link COSUpdateInfo} and, therefore, does not offer such
     * a value. See also PDFBOX-4997.
     * </p>
     */
    @Test
    void testSignOnceVisible() throws IOException {
        try (   InputStream source = getClass().getResourceAsStream("signed-000.pdf");
                InputStream image = getClass().getResourceAsStream("signature-pen.png");
                SignatureTokenConnection signingToken = new KeyStoreSignatureTokenConnection(
                        new File("keystores/demo-rsa2048.ks"),
                        KeyStore.getDefaultType(),
                        new PasswordProtection("demo-rsa2048".toCharArray()))   ) {
            DSSDocument toSignDocument = new InMemoryDocument(source);
            DSSDocument imageDocument = new InMemoryDocument(image, "image.png");
            DSSPrivateKeyEntry privateKey = signingToken.getKeys().get(0);

            PAdESSignatureParameters parameters = new PAdESSignatureParameters();
            parameters.setSignatureLevel(SignatureLevel.PAdES_BASELINE_B);
            parameters.setDigestAlgorithm(DigestAlgorithm.SHA256);
            parameters.setSigningCertificate(privateKey.getCertificate());
            parameters.setCertificateChain(privateKey.getCertificateChain());

            SignatureImageParameters imageParameters = new SignatureImageParameters();
            imageParameters.setImage(imageDocument);
            imageParameters.setxAxis(200);
            imageParameters.setyAxis(400);
            imageParameters.setWidth(300);
            imageParameters.setHeight(200);
            parameters.setImageParameters(imageParameters);

            CommonCertificateVerifier commonCertificateVerifier = new CommonCertificateVerifier();
            PAdESService service = new PAdESService(commonCertificateVerifier);

            ToBeSigned dataToSign = service.getDataToSign(toSignDocument, parameters);
            DigestAlgorithm digestAlgorithm = parameters.getDigestAlgorithm();
            SignatureValue signatureValue = signingToken.sign(dataToSign, digestAlgorithm, privateKey);
            DSSDocument signedDocument = service.signDocument(toSignDocument, parameters, signatureValue);

            signedDocument.save(new File(RESULT_FOLDER, "signed-000-once-visible.pdf").getAbsolutePath());
        }
    }

}
