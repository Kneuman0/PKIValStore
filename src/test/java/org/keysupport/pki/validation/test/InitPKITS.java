package org.keysupport.pki.validation.test;

import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.net.URI;
import java.security.KeyStore;
import java.security.cert.CRLException;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.PKIXCertPathBuilderResult;
import java.security.cert.X509CRL;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Comparator;
import java.util.Date;
import java.util.List;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import org.bouncycastle.cert.ocsp.CertificateID;
import org.junit.Before;
import org.junit.Test;
import org.keysupport.pki.validation.PKIXValidator;
import org.keysupport.pki.validation.PKIXValidatorManager;
import org.keysupport.pki.validation.ValidationException;
import org.keysupport.pki.validation.ValidationUtils;
import org.keysupport.pki.validation.cache.CRLCacheManager;
import org.keysupport.pki.validation.cache.CertificateCache;
import org.keysupport.pki.validation.cache.CertificateCacheManager;

/**
 * Test class for PKI Validation Library using NIST PKITS test data.
 * 
 * PKITS certificates do not contain AIA/SIA/CDP URIs, so we must manually
 * load and populate the cache managers with the test data based on file naming.
 * 
 * File naming convention:
 * - Trust Anchor CP.01.01.crt - Trust anchor certificate
 * - Trust Anchor CRL CP.01.01.crl - Trust anchor's CRL  
 * - Intermediate Certificate N <TestID>.crt - Intermediate CA (N = chain position)
 * - Intermediate CRL N <TestID>.crl - CRL for intermediate N
 * - End Certificate <TestID>.crt - End entity certificate to validate
 */
public class InitPKITS {
    
    // Core components
    private PKIXValidator validator;
    private CertificateCacheManager cacheManager;
    private CRLCacheManager crlManager;
    private PKIXValidatorManager validatorManager;
    
    // Track counts ourselves since getAllIntermediateEntries() re-flattens from tree
    private int loadedIntermediateCount = 0;
    private int loadedCRLCount = 0;
    
    // Test data
    private X509Certificate trustAnchorCert;
    private String testDataPKITS = "resources/PKITS/X509tests";
    private String trustAnchorStore = "resources/PKITS/truststore/pkits.jks";
    
    // Pattern to extract number from "Intermediate Certificate N" or "Intermediate CRL N"
    private static final Pattern INTERMEDIATE_NUMBER_PATTERN = 
        Pattern.compile("Intermediate (?:Certificate|CRL) (\\d+)", Pattern.CASE_INSENSITIVE);
    
    // Accessors
    public PKIXValidatorManager getValidatorManager() { return validatorManager; }
    public PKIXValidator getValidator() { return validator; }
    public X509Certificate getTrustAnchorCert() { return trustAnchorCert; }
    
    /**
     * Setup method to initialize the test environment.
     * 
     * Order is critical:
     * 1. Load trust anchor and create CertificateCacheManager (SIA discovery finds nothing)
     * 2. Get CRLCacheManager instance
     * 3. Load all PKITS test data into the caches
     * 4. THEN create PKIXValidatorManager (reads from populated caches)
     */
    @Before
    public void setUp() throws Exception {
        System.out.println("Setting up PKITSValidationTest...");
        
        // Reset singletons to ensure fresh state for testing
        CertificateCacheManager.resetInstance();
        PKIXValidatorManager.resetInstance();
        
        // Step 1: Initialize cache manager with trust anchor
        // SIA discovery will run but find nothing (PKITS certs have no SIA)
        trustAnchorCert = loadTrustAnchor(trustAnchorStore);
        cacheManager = CertificateCacheManager.getInstance(trustAnchorCert);
        
        // Step 2: Get CRL cache manager
        crlManager = CRLCacheManager.getInstance();
        
        // Step 3: Load all PKITS intermediates and CRLs into caches
        loadAllPKITSTestData(testDataPKITS);
        
        // Step 4: Now create validator manager - it reads from the populated caches
        validatorManager = PKIXValidatorManager.getInstance(cacheManager, crlManager);
        validator = validatorManager.getPKIXValidator();
        
        System.out.println("Setup complete. Cache has " + 
            cacheManager.getAllIntermediateEntries().size() + " intermediate certificates.");
        System.out.println("Trust anchor has " + 
            cacheManager.getCache().getSubjects().size() + " direct children in tree.");
    }
    
    // ==================== File Loading Helpers ====================
    
    /**
     * Load a certificate from a file
     */
    private X509Certificate loadCertificate(String filePath) throws CertificateException, IOException {
        try (FileInputStream fis = new FileInputStream(filePath)) {
            CertificateFactory cf = CertificateFactory.getInstance("X.509");
            return (X509Certificate) cf.generateCertificate(fis);
        }
    }
    
    /**
     * Load a CRL from a file
     */
    private X509CRL loadCRL(String filePath) throws CertificateException, IOException, CRLException {
        try (FileInputStream fis = new FileInputStream(filePath)) {
            CertificateFactory cf = CertificateFactory.getInstance("X.509");
            return (X509CRL) cf.generateCRL(fis);
        }
    }

    /**
     * Load trust anchor from JKS truststore
     */
    private X509Certificate loadTrustAnchor(String truststorePath) throws Exception {
        KeyStore trustStore = KeyStore.getInstance("JKS");
        try (FileInputStream fis = new FileInputStream(truststorePath)) {
            trustStore.load(fis, "changeit".toCharArray());
        }
        String alias = trustStore.aliases().nextElement();
        X509Certificate cert = (X509Certificate) trustStore.getCertificate(alias);
        if (cert == null) {
            throw new Exception("Trust anchor not found in truststore");
        }
        System.out.println("Loaded trust anchor: " + cert.getSubjectX500Principal().getName());
        return cert;
    }
    
    // ==================== PKITS Data Loading ====================
    
    /**
     * Load all PKITS test data from all test directories.
     * Processes each testN/ directory and loads intermediates and CRLs.
     */
    private void loadAllPKITSTestData(String baseDirectory) throws Exception {
        File baseDir = new File(baseDirectory);
        if (!baseDir.exists() || !baseDir.isDirectory()) {
            throw new IOException("PKITS directory not found: " + baseDirectory);
        }
        
        int totalIntermediates = 0;
        int totalCRLs = 0;
        
        // Get all test directories and sort them
        File[] testDirs = baseDir.listFiles(File::isDirectory);
        if (testDirs == null) return;
        
        Arrays.sort(testDirs, Comparator.comparing(File::getName));
        
        for (File testDir : testDirs) {
            int[] counts = loadTestDirectory(testDir);
            totalIntermediates += counts[0];
            totalCRLs += counts[1];
        }
        
        loadedIntermediateCount = totalIntermediates;
        loadedCRLCount = totalCRLs;
        System.out.println("Loaded " + totalIntermediates + " intermediate certificates");
        System.out.println("Loaded " + totalCRLs + " CRLs");
    }
    
    /**
     * Load a single PKITS test directory.
     * Builds the certificate chain in correct order based on file naming.
     * 
     * @return int[] {intermediateCount, crlCount}
     */
    private int[] loadTestDirectory(File testDir) throws Exception {
        int intermediateCount = 0;
        int crlCount = 0;
        
        // Collect and sort intermediate certificates by their number
        List<File> intermediateCertFiles = new ArrayList<>();
        List<File> intermediateCrlFiles = new ArrayList<>();
        File trustAnchorCrlFile = null;
        
        for (File file : testDir.listFiles()) {
            String fileName = file.getName();
            String lowerName = fileName.toLowerCase();
            
            if (lowerName.startsWith("intermediate certificate") && 
                (lowerName.endsWith(".crt") || lowerName.endsWith(".cer"))) {
                intermediateCertFiles.add(file);
            } else if (lowerName.startsWith("intermediate crl") && lowerName.endsWith(".crl")) {
                intermediateCrlFiles.add(file);
            } else if (lowerName.startsWith("trust anchor crl") && lowerName.endsWith(".crl")) {
                trustAnchorCrlFile = file;
            }
            // Skip: Trust Anchor .crt (already loaded), End Certificate (loaded per test)
        }
        
        // Sort by the number in "Intermediate Certificate N" or "Intermediate CRL N"
        Comparator<File> byIntermediateNumber = (f1, f2) -> {
            int n1 = extractIntermediateNumber(f1.getName());
            int n2 = extractIntermediateNumber(f2.getName());
            return Integer.compare(n1, n2);
        };
        intermediateCertFiles.sort(byIntermediateNumber);
        intermediateCrlFiles.sort(byIntermediateNumber);
        
        // Load Trust Anchor CRL (if present and not already loaded)
        if (trustAnchorCrlFile != null) {
            URI crlUri = trustAnchorCrlFile.toURI();
            if (!crlManager.getCRLCache().isInCache(crlUri)) {
                X509CRL crl = loadCRL(trustAnchorCrlFile.getAbsolutePath());
                crlManager.getCRLCache().update(crlUri, crl);
                crlCount++;
            }
        }
        
        // Load intermediate certificates in order, building the chain
        // Intermediate 1 is signed by Trust Anchor
        // Intermediate 2 is signed by Intermediate 1, etc.
        X509Certificate issuer = trustAnchorCert;
        CertificateCache parentCacheEntry = cacheManager.getCache(); // Start with trust anchor
        
        for (File certFile : intermediateCertFiles) {
            X509Certificate cert = loadCertificate(certFile.getAbsolutePath());
            
            // Create cache entry with proper issuer/subject CertIDs
            CertificateCache certCache = new CertificateCache(cert);
            try {
                // Subject CertID: identifies this cert (issuer signs this cert)
                CertificateID subjectCertId = ValidationUtils.getCertIdentifier(issuer, cert);
                certCache.setSubjectCertId(subjectCertId.toASN1Primitive());
                
                // Issuer CertID: identifies the issuer
                CertificateID issuerCertId = ValidationUtils.getCertIdentifier(
                    issuer.getSubjectX500Principal().equals(issuer.getIssuerX500Principal()) ? issuer : issuer, 
                    issuer);
                certCache.setIssuerCertId(issuerCertId.toASN1Primitive());
                
            } catch (ValidationException e) {
                System.err.println("Error creating CertID for " + certFile.getName() + ": " + e.getMessage());
                continue;
            }
            
            // Add to tree structure - link this cert as a child of its parent
            parentCacheEntry.addSubject(certCache);
            intermediateCount++;
            
            // This cert becomes the issuer/parent for the next one in the chain
            issuer = cert;
            parentCacheEntry = certCache;
        }
        
        // Load intermediate CRLs
        for (File crlFile : intermediateCrlFiles) {
            URI crlUri = crlFile.toURI();
            if (!crlManager.getCRLCache().isInCache(crlUri)) {
                X509CRL crl = loadCRL(crlFile.getAbsolutePath());
                crlManager.getCRLCache().update(crlUri, crl);
                crlCount++;
            }
        }
        
        return new int[] {intermediateCount, crlCount};
    }
    
    /**
     * Extract the number N from "Intermediate Certificate N" or "Intermediate CRL N"
     * Returns 0 if no number found (handles single intermediate case)
     */
    private int extractIntermediateNumber(String fileName) {
        Matcher m = INTERMEDIATE_NUMBER_PATTERN.matcher(fileName);
        if (m.find()) {
            return Integer.parseInt(m.group(1));
        }
        // No number found - treat as position 0 (single intermediate case)
        return 0;
    }

    // ==================== Validation Methods ====================
    
    /**
     * Load an end entity certificate from a specific test directory
     */
    public X509Certificate loadEndCertificate(String testDirName) throws Exception {
        File testDir = new File(testDataPKITS, testDirName);
        if (!testDir.exists()) {
            throw new IOException("Test directory not found: " + testDir.getAbsolutePath());
        }
        
        for (File file : testDir.listFiles()) {
            String lowerName = file.getName().toLowerCase();
            if (lowerName.startsWith("end certificate") && 
                (lowerName.endsWith(".crt") || lowerName.endsWith(".cer"))) {
                return loadCertificate(file.getAbsolutePath());
            }
        }
        throw new IOException("End certificate not found in " + testDirName);
    }
    
    /**
     * Validate an end entity certificate
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
     * Print certificate details for debugging
     */
    public void printCertificateDetails(X509Certificate cert) {
        System.out.println("Certificate Details:");
        System.out.println("  Subject: " + cert.getSubjectX500Principal().getName());
        System.out.println("  Issuer: " + cert.getIssuerX500Principal().getName());
        System.out.println("  Serial: " + cert.getSerialNumber());
        System.out.println("  Valid: " + cert.getNotBefore() + " to " + cert.getNotAfter());
    }
    
    // ==================== Sample Test ====================
    
    @Test
    public void testSetupComplete() {
        // Verify setup completed successfully
        System.out.println("\n=== Test Setup Verification ===");
        System.out.println("Trust Anchor: " + trustAnchorCert.getSubjectX500Principal().getName());
        // Note: getAllIntermediateEntries() re-flattens from tree, wiping putfCacheEntry() additions
        // Use our tracked count instead
        System.out.println("Intermediates loaded: " + loadedIntermediateCount);
        System.out.println("CRLs in cache: " + crlManager.getCRLCache().getCRLs().size());
        System.out.println("Validator ready: " + (validator != null));
    }
}
