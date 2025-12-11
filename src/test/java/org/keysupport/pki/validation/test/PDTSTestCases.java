package org.keysupport.pki.validation.test;

import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.fail;

import java.security.cert.PKIXCertPathBuilderResult;
import java.security.cert.X509Certificate;

import org.junit.BeforeClass;
import org.junit.Test;

/**
 * PDTS (Path Discovery Test Suite) Test Cases
 * 
 * Tests the library's ability to discover certification paths by following
 * AIA/SIA URIs in certificates. Unlike PKITS, intermediates and CRLs are NOT
 * pre-loaded - the library must discover them automatically via HTTP URIs.
 * 
 * Reference: PathDiscoveryTestSuite.pdf-edited.txt
 * 
 * Default settings (Section 3):
 * - Trust anchor: Basic HTTP URI Trust Anchor Root Cert
 * - initial-policy-set: any-policy
 * - initial-explicit-policy: false
 * - initial-policy-mapping-inhibit: false
 * - initial-inhibit-any-policy: false
 */
public class PDTSTestCases {

    private static InitPDTS pdts;
    
    @BeforeClass
    public static void setUpClass() throws Exception {
        pdts = new InitPDTS();
        pdts.setUp();
    }
    
    // ==================== 4.1.2 Rudimentary URI based Path Discovery ====================
    
    /**
     * 4.1.2.2 Rudimentary HTTP Path Discovery Test2
     * 
     * In this test, the end entity certificate is hierarchically subordinate to the trust anchor CA.
     * All intermediate certificates include subjectInfoAccess extensions with HTTP URIs and all
     * certificates include authorityInfoAccess extensions with HTTP URIs.
     * 
     * Expected Result: The path should validate successfully.
     * 
     * Certification Path:
     * - Basic HTTP URI Trust Anchor Root Cert, Basic HTTP URI Trust Anchor Root CRL
     * - Basic HTTP URI Trust Anchor SubCA1 Cert, Basic HTTP URI Trust Anchor SubCA1 CRL
     * - Basic HTTP URI Trust Anchor SubSubCA1 Cert, Basic HTTP URI Trust Anchor SubSubCA1 CRL
     * - Rudimentary HTTP URI Path Discovery Test2 EE
     */
    @Test
    public void testRudimentaryHTTPPathDiscoveryTest2() throws Exception {
        X509Certificate endCert = pdts.loadEndCertificate("RudimentaryHTTPURIPathDiscoveryTest2EE.crt");
        
        try {
            // The library should discover the path via AIA/SIA HTTP URIs
            PKIXCertPathBuilderResult result = pdts.validateCertificate(endCert, true);
            assertNotNull("Rudimentary HTTP Path Discovery Test2 should validate successfully", result);
            System.out.println("PDTS 4.1.2.2 Rudimentary HTTP Path Discovery Test2 PASSED");
        } catch (Exception e) {
            fail("Rudimentary HTTP Path Discovery Test2 should validate but failed: " + e.getMessage());
        }
    }
    
    // TODO: Add remaining test cases from PathDiscoveryTestSuite.pdf-edited.txt
    // 4.1.2.4 Rudimentary HTTP Path Discovery Test4
    // 4.1.2.7 Rudimentary HTTP Path Discovery Test7
    // 4.1.2.8 Rudimentary HTTP Path Discovery Test8 (expect failure - revoked)
    // ... and more
}
