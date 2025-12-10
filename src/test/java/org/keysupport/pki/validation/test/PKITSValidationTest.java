package org.keysupport.pki.validation.test;

import java.io.ByteArrayInputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.security.cert.CertPath;
import java.security.cert.CertStore;
import java.security.cert.CertStoreParameters;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.CollectionCertStoreParameters;
import java.security.cert.PKIXCertPathBuilderResult;
import java.security.cert.PKIXCertPathValidatorResult;
import java.security.cert.TrustAnchor;
import java.security.cert.X509CRL;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Collection;
import java.util.Date;
import java.util.HashSet;
import java.util.List;
import java.util.Set;

import org.junit.Before;
import org.junit.Test;
import org.keysupport.pki.validation.PKIXValidator;
import org.keysupport.pki.validation.PKIXValidatorException;
import org.keysupport.pki.validation.ValidationUtils;

/**
 * Test class for PKI Validation Library
 * This test harness will validate the functionality of the PKI validation library
 * using provided trust anchors, intermediates, and CRLs
 */
public class PKITSValidationTest {
    
    // Core components needed for validation
    private TrustAnchor trustAnchor;
    private CertStore intermediateStore;
    private CertStore crlStore;
    private PKIXValidator validator;
    
    // Collections to hold test data
    private X509Certificate trustAnchorCert;
    private List<X509Certificate> intermediateCerts = new ArrayList<>();
    private List<X509CRL> crls = new ArrayList<>();
    private CertificateCacheManager cacheManager;
    private CRLCacheManager crlManager;
    private String testDataPKITS = "src/test/resources/PKITS";
    private String trustAnchorStore = "resources/PKITS/truststore/trust_anchors.jks";
    private PKIXValidatorManager validatorManager;
    
    /**
     * @return the validatorManager
     */
    public PKIXValidatorManager getValidatorManager() {
        return validatorManager;
    }
    
    /**
     * @param validatorManager the validatorManager to set
     */
    public void setValidatorManager(PKIXValidatorManager validatorManager) {
        this.validatorManager = validatorManager;
    }
    private PKIXValidator validator;
    
    /**
     * @return the trustAnchorCert
     */
    public X509Certificate getTrustAnchorCert() {
        return trustAnchorCert;
    }
    

    
    /**
     * @return the testDataPKITS
     */
    public String getTestDataPKITS() {
        return testDataPKITS;
    }
    
    /**
     * @param testDataPKITS the testDataPKITS to set
     */
    public void setTestDataPKITS(String testDataPKITS) {
        this.testDataPKITS = testDataPKITS;
    }
    
    /**
     * @return the trustAnchorStore
     */
    public String getTrustAnchorStore() {
        return trustAnchorStore;
    }
    
    /**
     * @param trustAnchorStore the trustAnchorStore to set
     */
    public void setTrustAnchorStore(String trustAnchorStore) {
        this.trustAnchorStore = trustAnchorStore;
    }
    
    /**
     * @return the validator
     */
    public PKIXValidator getValidator() {
        return validator;
    }
    
    /**
     * Setup method to initialize the test environment
     * This will be populated with the trust anchor, intermediates, and CRLs you provide
     */
    @Before
    public void setUp() throws Exception {
        // This setup will be completed when you provide the test data
        System.out.println("Setting up PKITSValidationTest...");

        cacheManager = CertificateCacheManager.getInstance(loadTrustAnchor(trust_anchor_store));
        crlManager = CRLCacheManager.getInstance();
        loadPKITSTestData(testDataPKITS);
        validatorManager = PKITSValidatorManager.getInstance(cacheManager, crlManager);
        validator = validatorManager.getValidator();
    }
    
    /**
     * Helper method to load a certificate from a file
     * @param filePath Path to the certificate file
     * @return X509Certificate object
     */
    private X509Certificate loadCertificate(String filePath) throws CertificateException, IOException {
        try (FileInputStream fis = new FileInputStream(new File(filePath))) {
            CertificateFactory cf = CertificateFactory.getInstance("X.509");
            return (X509Certificate) cf.generateCertificate(fis);
        }

        

    }

    /**
     * Loads the trust anchor certificate from a JKS truststore
     * @param truststorePath Path to the truststore file
     * @return The trust anchor certificate
     * @throws Exception If any error occurs during loading
     */
    private X509Certificate loadTrustAnchor(String truststorePath) throws Exception {
        KeyStore trustStore = KeyStore.getInstance("JKS");
        char[] password = "changeit".toCharArray();
        
        try (FileInputStream fis = new FileInputStream(truststorePath)) {
            trustStore.load(fis, password);
        }
        
        // Assuming the first certificate in the store is the trust anchor
        String alias = trustStore.aliases().nextElement();
        X509Certificate trustAnchorCert = (X509Certificate) trustStore.getCertificate(alias);
        
        if (trustAnchorCert == null) {
            throw new Exception("Trust anchor certificate not found in truststore");
        }
        
        this.trustAnchorCert = trustAnchorCert;

        System.out.println("Loaded trust anchor: " + trustAnchorCert.getSubjectX500Principal().getName());
        return trustAnchorCert;
    }
    /**
     * Method to populate the trust anchor, intermediate store and CRL store from the PKITS directory
     * @param baseDirectory Base directory containing the PKITS test files
     */
    public void loadPKITSTestData(String baseDirectory) throws Exception {
        File baseDir = new File(baseDirectory);
        if (!baseDir.exists() || !baseDir.isDirectory()) {
            throw new IOException("Base directory does not exist or is not a directory: " + baseDirectory);
        }
        
        // Process all subdirectories
        for (File subDir : baseDir.listFiles(File::isDirectory)) {
            processPKITSDirectory(subDir);
        }
        
        // Initialize validator with the loaded data
        initializeValidator();
        
        System.out.println("Loaded trust anchor: " + (trustAnchorCert != null ? 
            trustAnchorCert.getSubjectX500Principal().getName() : "None"));
        System.out.println("Loaded " + intermediateCerts.size() + " intermediate certificates");
        System.out.println("Loaded " + crls.size() + " CRLs");
    }
    
    /**
     * Process a single PKITS directory to load certificates and CRLs
     * @param directory Directory to process
     */
    private void processPKITSDirectory(File directory) throws Exception {
        for (File file : directory.listFiles()) {
            String fileName = file.getName().toLowerCase();
            
            if (file.isDirectory()) {
                processPKITSDirectory(file);
            } else if (fileName.endsWith(".crt") || fileName.endsWith(".cer")) {
                // Skip trust anchor certificates - these will be loaded separately
                if (fileName.contains("trust") || fileName.contains("anchor")) {
                    continue;
                } else if (fileName.contains("intermediate")) {
                    X509Certificate cert = loadCertificate(file.getAbsolutePath());
                    // Add intermediate certificate to cache manager
                    CertificateCacheManager.putfCacheEntry(new CertificateCache(cert));
                    
                    System.out.println("Added intermediate certificate: " + file.getName());
                }
                // Skip end-entity certificates
            } else if (fileName.endsWith(".crl")) {
                // Add CRL to cache manager
                crlManager.getCRLCache().update(file.toURI(), loadCRL(file.getAbsolutePath()));
                System.out.println("Added CRL: " + file.getName());
            }
        }
    }
    /**
     * Helper method to load a CRL from a file
     * @param filePath Path to the CRL file
     * @return X509CRL object
     */
    private X509CRL loadCRL(String filePath) throws CertificateException, IOException {
        try (FileInputStream fis = new FileInputStream(new File(filePath))) {
            CertificateFactory cf = CertificateFactory.getInstance("X.509");
            return (X509CRL) cf.generateCRL(fis);
        }
    }
    
    /**
     * Helper method to initialize the validator with provided certificates and CRLs
     */
    private void initializeValidator() throws Exception {
        if (trustAnchorCert == null) {
            throw new IllegalStateException("Trust anchor certificate must be provided");
        }
        
        // Configure validation parameters
        validator.setValidityDate(new Date()); // Current date
        validator.setRequreExplicitPolicy(true);
        validator.setInhibitPolicyMapping(false);
        validator.setInhibitAnyPolcy(true);
        validator.setPolicyQualifiersRejected(false);
        validator.setMaxPathLength(20);
    }
    
    

    
    /**
     * Method to validate a specific end entity certificate
     * @param certIndex Index of the end entity certificate to validate
     * @return Validation result
     */
    public PKIXCertPathBuilderResult validateCertificate(X509Certificate cert) throws Exception {
        if (validator == null) {
            initializeValidator();
        }
        
        if (cert == null) {
            throw new IllegalArgumentException("Certificate index out of bounds");
        }
        
        System.out.println("Validating certificate: " + cert.getSubjectX500Principal().getName());
        
        // Perform validation with revocation checking
        PKIXCertPathBuilderResult result = validator.discoverPath(cert, true);
        
        // Print validation result
        System.out.println("Validation successful");
        System.out.println("Certificate path length: " + result.getCertPath().getCertificates().size());
        
        return result;
    }
    
    /**
     * Method to print certificate details
     * @param cert Certificate to print details for
     */
    public void printCertificateDetails(X509Certificate cert) {
        System.out.println("Certificate Details:");
        System.out.println("  Subject: " + cert.getSubjectX500Principal().getName());
        System.out.println("  Issuer: " + cert.getIssuerX500Principal().getName());
        System.out.println("  Serial Number: " + cert.getSerialNumber());
        System.out.println("  Not Before: " + cert.getNotBefore());
        System.out.println("  Not After: " + cert.getNotAfter());
        
        try {
            String pemCert = ValidationUtils.certToPem(cert);
            System.out.println("  PEM Format:");
            System.out.println(pemCert);
        } catch (Exception e) {
            System.out.println("  Error converting to PEM: " + e.getMessage());
        }
    }
    

}
