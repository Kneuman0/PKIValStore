package org.keysupport.pki.validation.test;

import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.security.cert.CertificateFactory;
import java.security.cert.PKIXCertPathBuilderResult;
import java.security.cert.X509Certificate;

import org.keysupport.pki.validation.PKIXValidator;
import org.keysupport.pki.validation.PKIXValidatorManager;
import org.keysupport.pki.validation.cache.CRLCacheManager;
import org.keysupport.pki.validation.cache.CertificateCacheManager;
import org.keysupport.pki.validation.cache.RejectedCertCacheManager;

/**
 * Initialization class for PDTS (Path Discovery Test Suite) testing.
 * 
 * Unlike PKITS, PDTS tests the library's ability to discover certification paths
 * by following AIA/SIA URIs in certificates. We do NOT pre-load intermediates
 * or CRLs - the library must discover them automatically.
 * 
 * Configures the PKIXValidator with:
 * - initial-policy-set: any-policy (2.5.29.32.0)
 * - initial-explicit-policy: false
 * - initial-policy-mapping-inhibit: false
 * - initial-inhibit-any-policy: false
 */
public class InitPDTS {

    // RFC 5280 anyPolicy OID
    private static final String ANY_POLICY = "2.5.29.32.0";
    
    // Trust anchor certificate path (loaded from JKS truststore)
    private static String trustAnchorStore = "resources/PDTS/truststore/pdts.jks";
    
    // End entity certificates directory
    private static String endEntityCertsPath = "resources/PDTS/End Entity Certs";
    
    // Core components
    private X509Certificate trustAnchorCert;
    private CertificateCacheManager cacheManager;
    private CRLCacheManager crlManager;
    private PKIXValidatorManager validatorManager;
    private PKIXValidator validator;
    
    // Accessors
    public PKIXValidatorManager getValidatorManager() { 
        return validatorManager; 
    }
    
    public PKIXValidator getValidator() { 
        return validator; 
    }
    
    public X509Certificate getTrustAnchorCert() { 
        return trustAnchorCert; 
    }
    
    public CertificateCacheManager getCacheManager() { 
        return cacheManager; 
    }
    
    public CRLCacheManager getCrlManager() { 
        return crlManager; 
    }
    
    /**
     * Setup method to initialize the PDTS test environment.
     * 
     * Unlike PKITS, we only load the trust anchor. The library must discover
     * intermediate certificates and CRLs via AIA/SIA/CDP URIs.
     */
    public void setUp() throws Exception {
        System.out.println("Setting up PDTS test environment...");
        
        // Reset singletons to ensure fresh state
        CertificateCacheManager.resetInstance();
        PKIXValidatorManager.resetInstance();
        
        // Set validation date to August 1, 2015 BEFORE SIA discovery
        // PDTS certificates expired in August 2015
        java.util.Calendar cal = java.util.Calendar.getInstance();
        cal.set(2015, java.util.Calendar.AUGUST, 1, 12, 0, 0);
        RejectedCertCacheManager.getInstance().setValidityDate(cal.getTime());
        System.out.println("Set validity date for certificate discovery: " + cal.getTime());
        
        // Load trust anchor from JKS truststore
        trustAnchorCert = loadTrustAnchor(trustAnchorStore);
        System.out.println("Loaded Trust Anchor: " + trustAnchorCert.getSubjectX500Principal().getName());
        
        // Initialize CertificateCacheManager with trust anchor
        // SIA discovery will run and should find certificates via HTTP URIs
        cacheManager = CertificateCacheManager.getInstance(trustAnchorCert);
        
        // Get CRL cache manager
        crlManager = CRLCacheManager.getInstance();
        
        // Create PKIXValidatorManager
        validatorManager = PKIXValidatorManager.getInstance(cacheManager, crlManager);
        validator = validatorManager.getPKIXValidator();
        
        // Configure validator with PDTS-specific settings
        configurePDTSValidator();
        
        System.out.println("PDTS initialization complete.");
    }
    
    /**
     * Load trust anchor from JKS truststore.
     */
    private X509Certificate loadTrustAnchor(String truststorePath) throws Exception {
        java.security.KeyStore trustStore = java.security.KeyStore.getInstance("JKS");
        try (FileInputStream fis = new FileInputStream(truststorePath)) {
            trustStore.load(fis, "changeit".toCharArray());
        }
        String alias = trustStore.aliases().nextElement();
        X509Certificate cert = (X509Certificate) trustStore.getCertificate(alias);
        if (cert == null) {
            throw new Exception("Trust anchor not found in truststore");
        }
        return cert;
    }
    
    /**
     * Configure the validator with PDTS-specific settings:
     * - initial-policy-set: any-policy
     * - initial-explicit-policy: false
     * - initial-policy-mapping-inhibit: false
     * - initial-inhibit-any-policy: false
     * - validity date: August 1, 2015 (PDTS certificates expired in August 2015)
     */
    private void configurePDTSValidator() {
        validator.clearInitialPolicySet();
        validator.addInitialPolicy(ANY_POLICY);
        validator.setRequreExplicitPolicy(false);
        validator.setInhibitPolicyMapping(false);
        validator.setInhibitAnyPolcy(false);
        
        // Set validation date to August 1, 2015 - PDTS certificates expired in August 2015
        java.util.Calendar cal = java.util.Calendar.getInstance();
        cal.set(2015, java.util.Calendar.AUGUST, 1, 12, 0, 0);
        validator.setValidityDate(cal.getTime());
        
        System.out.println("PDTS Validator configured:");
        System.out.println("  - initial-policy-set: any-policy (2.5.29.32.0)");
        System.out.println("  - initial-explicit-policy: false");
        System.out.println("  - initial-policy-mapping-inhibit: false");
        System.out.println("  - validity-date: " + cal.getTime());
        System.out.println("  - initial-inhibit-any-policy: false");
    }
    
    /**
     * Load a certificate from a file path.
     */
    private X509Certificate loadCertificate(String filePath) throws Exception {
        CertificateFactory cf = CertificateFactory.getInstance("X.509");
        try (FileInputStream fis = new FileInputStream(filePath)) {
            return (X509Certificate) cf.generateCertificate(fis);
        }
    }
    
    /**
     * Load an end entity certificate by name from the End Entity Certs directory.
     * 
     * @param certName The certificate filename (without path, e.g., "BasicHTTPURIPathDiscoveryTest2EE.crt")
     */
    public X509Certificate loadEndCertificate(String certName) throws Exception {
        String fullPath = endEntityCertsPath + "/" + certName;
        if (!certName.endsWith(".crt")) {
            fullPath += ".crt";
        }
        
        File certFile = new File(fullPath);
        if (!certFile.exists()) {
            throw new IOException("End certificate not found: " + fullPath);
        }
        
        return loadCertificate(fullPath);
    }
    
    /**
     * Validate an end entity certificate.
     * The library should discover the certification path via AIA/SIA URIs.
     */
    public PKIXCertPathBuilderResult validateCertificate(X509Certificate cert, boolean checkRevocation) 
            throws Exception {
        System.out.println("Validating: " + cert.getSubjectX500Principal().getName());
        PKIXCertPathBuilderResult result = validator.discoverPath(cert, checkRevocation);
        System.out.println("Validation successful. Path length: " + 
            result.getCertPath().getCertificates().size());
        return result;
    }
    
    /**
     * Print certificate details for debugging.
     */
    public void printCertificateDetails(X509Certificate cert) {
        System.out.println("Certificate Details:");
        System.out.println("  Subject: " + cert.getSubjectX500Principal().getName());
        System.out.println("  Issuer: " + cert.getIssuerX500Principal().getName());
        System.out.println("  Serial: " + cert.getSerialNumber());
        System.out.println("  Valid: " + cert.getNotBefore() + " to " + cert.getNotAfter());
    }
}
