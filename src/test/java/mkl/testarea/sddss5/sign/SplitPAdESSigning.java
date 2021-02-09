package mkl.testarea.sddss5.sign;

import java.awt.Color;
import java.awt.Font;
import java.io.File;
import java.io.IOException;
import java.io.InputStream;
import java.security.KeyStore;
import java.util.Map;
import java.util.Objects;

import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.DEROctetString;
import org.bouncycastle.asn1.cms.AttributeTable;
import org.bouncycastle.asn1.cms.CMSAttributes;
import org.bouncycastle.cms.CMSAttributeTableGenerationException;
import org.bouncycastle.cms.CMSAttributeTableGenerator;
import org.bouncycastle.cms.CMSProcessableByteArray;
import org.bouncycastle.cms.CMSSignedData;
import org.bouncycastle.cms.CMSSignedDataGenerator;
import org.bouncycastle.cms.SignerInfoGeneratorBuilder;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.DigestCalculatorProvider;
import org.bouncycastle.operator.bc.BcDigestCalculatorProvider;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;

import eu.europa.esig.dss.cades.CAdESSignatureParameters;
import eu.europa.esig.dss.cades.CMSUtils;
import eu.europa.esig.dss.cades.signature.CAdESLevelBaselineB;
import eu.europa.esig.dss.cades.signature.CMSSignedDataBuilder;
import eu.europa.esig.dss.cades.signature.CustomContentSigner;
import eu.europa.esig.dss.enumerations.DigestAlgorithm;
import eu.europa.esig.dss.enumerations.EncryptionAlgorithm;
import eu.europa.esig.dss.enumerations.SignatureAlgorithm;
import eu.europa.esig.dss.enumerations.SignatureLevel;
import eu.europa.esig.dss.enumerations.SignerTextHorizontalAlignment;
import eu.europa.esig.dss.enumerations.SignerTextPosition;
import eu.europa.esig.dss.enumerations.SignerTextVerticalAlignment;
import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.model.DSSException;
import eu.europa.esig.dss.model.InMemoryDocument;
import eu.europa.esig.dss.model.SignatureValue;
import eu.europa.esig.dss.model.ToBeSigned;
import eu.europa.esig.dss.pades.DSSFont;
import eu.europa.esig.dss.pades.DSSJavaFont;
import eu.europa.esig.dss.pades.PAdESSignatureParameters;
import eu.europa.esig.dss.pades.SignatureImageParameters;
import eu.europa.esig.dss.pades.SignatureImageTextParameters;
import eu.europa.esig.dss.pdf.IPdfObjFactory;
import eu.europa.esig.dss.pdf.PDFSignatureService;
import eu.europa.esig.dss.pdf.ServiceLoaderPdfObjFactory;
import eu.europa.esig.dss.spi.DSSASN1Utils;
import eu.europa.esig.dss.token.DSSPrivateKeyEntry;
import eu.europa.esig.dss.token.Pkcs12SignatureToken;
import eu.europa.esig.dss.validation.CertificateVerifier;
import eu.europa.esig.dss.validation.CommonCertificateVerifier;

/**
 * @author mkl
 */
class SplitPAdESSigning {
    final static File RESULT_FOLDER = new File("target/test-outputs", "sign");

    @BeforeAll
    static void setUpBeforeClass() throws Exception {
        RESULT_FOLDER.mkdirs();
    }

    /**
     * <a href="https://stackoverflow.com/questions/66049319/signing-a-hash-with-dss-digital-signature-service">
     * Signing a hash with DSS (Digital Signature Service)
     * </a>
     * <p>
     * This proof-of-concept test shows how in eSig DSS PAdES signing
     * to separate PDF processing from CMS generation. Here the test
     * method {@link #testSplitPAdESGenerationForMehdi()} itself contains
     * the code preparing the PDF, hashing the signed byte ranges, and
     * injecting a CMS container. The method {@link #signHash(byte[])}
     * for the given document hash value then generates a CMS container.
     * </p>
     * <p>
     * {@link #signHash(byte[])} with its helper methods
     * {@link #getDataToSign(byte[], PAdESSignatureParameters)} and
     * {@link #generateCMSSignedData(byte[], PAdESSignatureParameters, SignatureValue)}
     * and its helper classes {@link PadesCMSSignedDataBuilder} and
     * {@link PAdESLevelBaselineB} can be located on a different server
     * and merely the document hash value needs to be communicated.
     * </p>
     * <p>
     * This POC is limited to Baseline-B PAdES but can easily be
     * extended to Baseline-T. Any extending beyond that can be
     * executed locally anyways.
     * </p>
     */
    @Test
    void testSplitPAdESGenerationForMehdi() throws IOException {
        IPdfObjFactory pdfObjFactory = new ServiceLoaderPdfObjFactory();
        PDFSignatureService pdfSignatureService = pdfObjFactory.newPAdESSignatureService();

        PAdESSignatureParameters parameters = new PAdESSignatureParameters();

        parameters.setDigestAlgorithm(DigestAlgorithm.SHA512);
        parameters.setReason("Preuve de signature");
        parameters.setLocation("MAROC");
        parameters.setGenerateTBSWithoutCertificate(true);

        SignatureImageParameters imageParameters = new SignatureImageParameters();

        imageParameters.setPage(1);

        try (   InputStream imageStream = getClass().getResourceAsStream("Willi-1.jpg") ) {
            DSSDocument image = new InMemoryDocument(imageStream);
            imageParameters.setImage(image);
        }

        imageParameters.setxAxis(350);
        imageParameters.setyAxis(400);
        imageParameters.setWidth(200);
        imageParameters.setHeight(100);
        parameters.setImageParameters(imageParameters);
        SignatureImageTextParameters textParameters = new SignatureImageTextParameters();
        DSSFont font = new DSSJavaFont(Font.SERIF);
        font.setSize(16);
        textParameters.setFont(font);
        textParameters.setTextColor(Color.BLUE);

        textParameters.setSignerTextPosition(SignerTextPosition.RIGHT);
        textParameters.setSignerTextHorizontalAlignment(SignerTextHorizontalAlignment.LEFT);
        textParameters.setSignerTextVerticalAlignment(SignerTextVerticalAlignment.TOP);
        textParameters.setText("TESTING");
        imageParameters.setTextParameters(textParameters);

        DSSDocument toSignDocument;
        try (   InputStream pdfStream = getClass().getResourceAsStream("sbi statment_out2.pdf") ) {
            toSignDocument = new InMemoryDocument(pdfStream);
        }

        byte[] hash = pdfSignatureService.digest(toSignDocument, parameters);

        byte[] signatureValue = signHash(hash);

        DSSDocument signedDocument = pdfSignatureService.sign(toSignDocument, signatureValue, parameters);

        signedDocument.save(new File(RESULT_FOLDER, "sbi statment_out2-splitSigned.pdf").getAbsolutePath());
    }

    byte[] signHash(byte[] hash) throws IOException {
        Pkcs12SignatureToken signingToken;
        try (   InputStream p12Stream = getClass().getResourceAsStream("demo-rsa2048.p12")) {
            signingToken = new Pkcs12SignatureToken(p12Stream,
                    new KeyStore.PasswordProtection("demo-rsa2048".toCharArray()));
        }
        DSSPrivateKeyEntry privateKey = signingToken.getKey("demo");

        CommonCertificateVerifier commonCertificateVerifier = new CommonCertificateVerifier();
        padesCMSSignedDataBuilder = new PadesCMSSignedDataBuilder(commonCertificateVerifier);

        PAdESSignatureParameters parameters = new PAdESSignatureParameters();
        parameters.setDigestAlgorithm(DigestAlgorithm.SHA512);
        parameters.setEncryptionAlgorithm(EncryptionAlgorithm.RSA);
        parameters.setSignatureLevel(SignatureLevel.PAdES_BASELINE_B);
        parameters.setSigningCertificate(privateKey.getCertificate());

        ToBeSigned dataToSign = getDataToSign(hash, parameters);
        SignatureValue signatureValue = signingToken.sign(dataToSign, DigestAlgorithm.SHA512, privateKey);
        return generateCMSSignedData(hash, parameters, signatureValue);
    }

    PadesCMSSignedDataBuilder padesCMSSignedDataBuilder;

    /** @see eu.europa.esig.dss.pades.signature.PAdESService#getDataToSign(DSSDocument, PAdESSignatureParameters) */
    public ToBeSigned getDataToSign(byte[] messageDigest, final PAdESSignatureParameters parameters) throws DSSException {
        final SignatureAlgorithm signatureAlgorithm = parameters.getSignatureAlgorithm();
        final CustomContentSigner customContentSigner = new CustomContentSigner(signatureAlgorithm.getJCEId());

        SignerInfoGeneratorBuilder signerInfoGeneratorBuilder = padesCMSSignedDataBuilder.getSignerInfoGeneratorBuilder(parameters, messageDigest);

        final CMSSignedDataGenerator generator = padesCMSSignedDataBuilder.createCMSSignedDataGenerator(parameters, customContentSigner,
                signerInfoGeneratorBuilder, null);

        final CMSProcessableByteArray content = new CMSProcessableByteArray(messageDigest);

        CMSUtils.generateDetachedCMSSignedData(generator, content);

        final byte[] dataToSign = customContentSigner.getOutputStream().toByteArray();
        return new ToBeSigned(dataToSign);
    }

    /** @see eu.europa.esig.dss.pades.signature.PAdESService#generateCMSSignedData(DSSDocument, PAdESSignatureParameters, SignatureValue) */
    protected byte[] generateCMSSignedData(byte[] messageDigest, final PAdESSignatureParameters parameters,
            final SignatureValue signatureValue) {
        final SignatureAlgorithm signatureAlgorithm = parameters.getSignatureAlgorithm();
        final SignatureLevel signatureLevel = parameters.getSignatureLevel();
        Objects.requireNonNull(signatureAlgorithm, "SignatureAlgorithm cannot be null!");
        Objects.requireNonNull(signatureLevel, "SignatureLevel must be defined!");
        
        final CustomContentSigner customContentSigner = new CustomContentSigner(signatureAlgorithm.getJCEId(), signatureValue.getValue());
        
        final SignerInfoGeneratorBuilder signerInfoGeneratorBuilder = padesCMSSignedDataBuilder.getSignerInfoGeneratorBuilder(parameters, messageDigest);
        
        final CMSSignedDataGenerator generator = padesCMSSignedDataBuilder.createCMSSignedDataGenerator(parameters, customContentSigner,
        signerInfoGeneratorBuilder, null);
        
        final CMSProcessableByteArray content = new CMSProcessableByteArray(messageDigest);
        CMSSignedData data = CMSUtils.generateDetachedCMSSignedData(generator, content);

        return DSSASN1Utils.getDEREncoded(data);
    }

    /** @see eu.europa.esig.dss.cades.signature.CMSSignedDataBuilder */
    class PadesCMSSignedDataBuilder extends CMSSignedDataBuilder {
        public PadesCMSSignedDataBuilder(CertificateVerifier certificateVerifier) {
            super(certificateVerifier);
        }

        @Override
        protected CMSSignedDataGenerator createCMSSignedDataGenerator(CAdESSignatureParameters parameters, ContentSigner contentSigner, SignerInfoGeneratorBuilder signerInfoGeneratorBuilder,
                CMSSignedData originalSignedData) throws DSSException {

            return super.createCMSSignedDataGenerator(parameters, contentSigner, signerInfoGeneratorBuilder, originalSignedData);
        }

        protected SignerInfoGeneratorBuilder getSignerInfoGeneratorBuilder(final PAdESSignatureParameters parameters, final byte[] messageDigest) {
            final CAdESLevelBaselineB cadesLevelBaselineB = new CAdESLevelBaselineB(true);
            final PAdESLevelBaselineB padesProfileB = new PAdESLevelBaselineB();

            final DigestCalculatorProvider digestCalculatorProvider = new BcDigestCalculatorProvider();

            SignerInfoGeneratorBuilder signerInfoGeneratorBuilder = new SignerInfoGeneratorBuilder(digestCalculatorProvider);

            signerInfoGeneratorBuilder = signerInfoGeneratorBuilder.setSignedAttributeGenerator(new CMSAttributeTableGenerator() {
                @Override
                public AttributeTable getAttributes(@SuppressWarnings("rawtypes") Map params) throws CMSAttributeTableGenerationException {
                    return padesProfileB.getSignedAttributes(params, cadesLevelBaselineB, parameters, messageDigest);
                }
            });

            signerInfoGeneratorBuilder = signerInfoGeneratorBuilder.setUnsignedAttributeGenerator(new CMSAttributeTableGenerator() {
                @Override
                public AttributeTable getAttributes(@SuppressWarnings("rawtypes") Map params) throws CMSAttributeTableGenerationException {
                    return padesProfileB.getUnsignedAttributes();
                }
            });

            return signerInfoGeneratorBuilder;
        }
    }

    /** @see eu.europa.esig.dss.pades.signature.PAdESLevelBaselineB */
    class PAdESLevelBaselineB {
        AttributeTable getSignedAttributes(@SuppressWarnings("rawtypes") Map params, 
                CAdESLevelBaselineB cadesProfile, PAdESSignatureParameters parameters, byte[] messageDigest) {
            AttributeTable signedAttributes = cadesProfile.getSignedAttributes(parameters);

            if (signedAttributes.get(CMSAttributes.contentType) == null) {
                ASN1ObjectIdentifier contentType = (ASN1ObjectIdentifier) params.get(CMSAttributeTableGenerator.CONTENT_TYPE);
                if (contentType != null) {
                    signedAttributes = signedAttributes.add(CMSAttributes.contentType, contentType);
                }
            }

            if (signedAttributes.get(CMSAttributes.messageDigest) == null) {
                signedAttributes = signedAttributes.add(CMSAttributes.messageDigest, new DEROctetString(messageDigest));
            }

            return signedAttributes;
        }

        AttributeTable getUnsignedAttributes() {
            return null;
        }
    }
}
