package org.keysupport.pki.validation.test;

import static org.junit.Assert.*;

import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.PKIXCertPathBuilderResult;
import java.security.cert.X509Certificate;
import java.util.HashMap;
import java.util.Map;

import org.junit.Before;
import org.junit.Test;
import org.keysupport.pki.validation.PKIXValidatorException;

/**
 * Test class for running the 76 PKITS test cases
 * This class uses the PKITSValidationTest to validate certificates
 * for each test case in the PKITS test suite
 */
public class PKITSTestCases {
    
    // Base directory for PKITS test data
    private static final String PKITS_BASE_DIR = "src/test/resources/PKITS";
    
    // Directory containing end entity certificates for test cases
    private static final String END_ENTITY_CERTS_DIR = PKITS_BASE_DIR + "/certs";
    
    // The main validation test harness
    private PKITSValidationTest validationTest;
    
    // Map to store end entity certificates by test case number
    private Map<String, X509Certificate> endEntityCerts;
    
    /**
     * Setup method to initialize the test environment
     * Loads the PKITSValidationTest and all end entity certificates
     */
    @Before
    public void setUp() throws Exception {
        System.out.println("Setting up PKITS test cases...");
        
        // Initialize the validation test harness
        validationTest = new PKITSValidationTest();
        validationTest.setUp();
        
        // Load all end entity certificates
        loadEndEntityCertificates();

    }
    
    /**
     * Load all end entity certificates from the test directory
     */
    private void loadEndEntityCertificates() throws IOException, CertificateException {
        endEntityCerts = new HashMap<>();
        
        File certsDir = new File(END_ENTITY_CERTS_DIR);
        if (!certsDir.exists() || !certsDir.isDirectory()) {
            throw new IOException("End entity certificates directory not found: " + END_ENTITY_CERTS_DIR);
        }
        
        CertificateFactory cf = CertificateFactory.getInstance("X.509");
        
        for (File file : certsDir.listFiles()) {
            String fileName = file.getName().toLowerCase();
            if (fileName.endsWith(".crt") || fileName.endsWith(".cer")) {
                try (FileInputStream fis = new FileInputStream(file)) {
                    X509Certificate cert = (X509Certificate) cf.generateCertificate(fis);
                    // Store certificate with test case number as key
                    // Assuming filename format like "TestCase1EE.crt"
                    String testCaseId = extractTestCaseId(fileName);
                    if (testCaseId != null) {
                        endEntityCerts.put(testCaseId, cert);
                        System.out.println("Loaded end entity certificate for test case: " + testCaseId);
                    }
                }
            }
        }
        
        System.out.println("Loaded " + endEntityCerts.size() + " end entity certificates");
    }
    
    /**
     * Extract test case ID from filename
     * @param fileName Filename of the certificate
     * @return Test case ID or null if not found
     */
    private String extractTestCaseId(String fileName) {
        // Assuming filename format like "TestCase1EE.crt"
        if (fileName.toLowerCase().contains("testcase") && fileName.toLowerCase().contains("ee")) {
            // Extract the number between "TestCase" and "EE"
            int startIndex = fileName.toLowerCase().indexOf("testcase") + "testcase".length();
            int endIndex = fileName.toLowerCase().indexOf("ee");
            if (startIndex < endIndex) {
                return fileName.substring(startIndex, endIndex);
            }
        }
        return null;
    }
    

    
    /**
     * Test case 1: Valid Signatures Test Case
     * This test case verifies that a valid certification path is correctly validated
     */
    @Test
    public void testCase1() {
        X509Certificate eeTest1 = endEntityCerts.get("1");
        try {
            PKIXCertPathBuilderResult result = validationTest.validateCertificate(eeTest1);
            assertTrue("Certificate validation should succeed for test case 1", result != null);
        } catch (Exception e) {
            fail("Test case 1 should pass validation but failed with: " + e.getMessage());
        }
    }

        /**
     * Main method to run the test harness from command line
     */
    public static void main(String[] args) {
        PKITSTestCases testCases = new PKITSTestCases();
        testCases.setUp();
        testCases.testCase1();
        System.out.println("PKI Validation Test Harness");
        System.out.println("This test harness will be populated with your provided test data");
    }
    
    // Additional test case methods will be added for all 76 test cases
}
