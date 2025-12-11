package org.keysupport.pki.validation.test;

import static org.junit.Assert.*;

import java.security.cert.PKIXCertPathBuilderResult;
import java.security.cert.X509Certificate;

import org.junit.BeforeClass;
import org.junit.Test;

/**
 * Test class for running the 76 PKITS test cases.
 * Uses InitPKITS to initialize the validation library with all
 * intermediate certificates and CRLs loaded.
 * 
 * Each test case loads its end entity certificate and validates it.
 */
public class PKITSTestCases {
    
    private static InitPKITS pkits;
    
    // PKITS Policy OIDs
    private static final String TEST_POLICY_1 = "2.16.840.1.101.3.1.48.1";
    private static final String TEST_POLICY_2 = "2.16.840.1.101.3.1.48.2";
    private static final String TEST_POLICY_3 = "2.16.840.1.101.3.1.48.3";
    private static final String TEST_POLICY_4 = "2.16.840.1.101.3.1.48.4";
    private static final String TEST_POLICY_5 = "2.16.840.1.101.3.1.48.5";
    
    // RFC 5280 anyPolicy OID
    private static final String ANY_POLICY = "2.5.29.32.0";
    
    // PKIXValidator default settings (mirrors PKIXValidator.java defaults)
    // These are used to reset state after tests that modify validator settings
    private static final boolean DEFAULT_REQUIRE_EXPLICIT_POLICY = true;
    private static final boolean DEFAULT_INHIBIT_ANY_POLICY = true;
    private static final boolean DEFAULT_INHIBIT_POLICY_MAPPING = false;
    
    /**
     * Initialize the PKITS test environment once before all tests.
     * Loads trust anchor, all intermediate certificates, and CRLs.
     */
    @BeforeClass
    public static void setUpClass() throws Exception {
        System.out.println("Initializing PKITS test environment...");
        pkits = new InitPKITS();
        pkits.setUp();
        System.out.println("PKITS initialization complete.");
    }
    
    // ==================== Helper Methods ====================
    
    /**
     * Helper for tests expecting a valid path.
     * Fails if validation throws an exception.
     */
    private void expectValidPath(String testDir, String testName) throws Exception {
        X509Certificate endCert = pkits.loadEndCertificate(testDir);
        try {
            PKIXCertPathBuilderResult result = pkits.validateCertificate(endCert, true);
            assertNotNull("Valid path expected for " + testName, result);
            System.out.println(testName + " PASSED: Valid path built");
        } catch (Exception e) {
            fail(testName + " should have valid path but failed: " + e.getMessage());
        }
    }
    
    /**
     * Helper for tests expecting validation to fail (invalid path).
     * Fails if validation succeeds.
     */
    private void expectInvalidPath(String testDir, String testName) throws Exception {
        X509Certificate endCert = pkits.loadEndCertificate(testDir);
        try {
            pkits.validateCertificate(endCert, true);
            fail(testName + " should have failed validation but succeeded");
        } catch (Exception e) {
            System.out.println(testName + " PASSED: Validation correctly rejected - " + e.getMessage());
        }
    }
    
    // ==================== Section 3.1: Certificate Processing Tests (CP) ====================
    
    /**
     * Test 1: TE:CP.01.01 - Valid Signatures Test
     * The path should be successfully validated, all signatures and data are correct.
     */
    @Test
    public void testCase1() throws Exception {
        expectValidPath("test1", "TE:CP.01.01 Valid Signatures");
    }
    
    /**
     * Test 2: TE:CP.01.02 - Invalid CA Signature
     * The signature on the intermediate certificate is invalid.
     */
    @Test
    public void testCase2() throws Exception {
        expectInvalidPath("test2", "TE:CP.01.02 Invalid CA Signature");
    }
    
    /**
     * Test 3: TE:CP.01.03 - Invalid EE Signature
     * The signature on the end certificate is invalid.
     */
    @Test
    public void testCase3() throws Exception {
        expectInvalidPath("test3", "TE:CP.01.03 Invalid EE Signature");
    }
    
    /**
     * Test 4: TE:CP.02.01 - Valid notBefore Dates
     * All certificates have notBefore earlier than current time.
     */
    @Test
    public void testCase4() throws Exception {
        expectValidPath("test4", "TE:CP.02.01 Valid notBefore Dates");
    }
    
    /**
     * Test 5: TE:CP.02.02 - Invalid CA notBefore Date
     * The intermediate certificate has a notBefore later than current time.
     */
    @Test
    public void testCase5() throws Exception {
        expectInvalidPath("test5", "TE:CP.02.02 Invalid CA notBefore Date");
    }
    
    /**
     * Test 6: TE:CP.02.03 - Invalid EE notBefore Date
     * The end certificate has a notBefore later than current time.
     */
    @Test
    public void testCase6() throws Exception {
        expectInvalidPath("test6", "TE:CP.02.03 Invalid EE notBefore Date");
    }
    
    /**
     * Test 7: TE:CP.02.04 - Valid notBefore UTC 50
     * The end certificate has a notBefore set as UTC time with year 50 (should treat as 1950).
     */
    @Test
    public void testCase7() throws Exception {
        expectValidPath("test7", "TE:CP.02.04 Valid notBefore UTC 50");
    }
    
    /**
     * Test 8: TE:CP.02.05 - Invalid notBefore Generalized 2050
     * The end certificate has a notBefore set as generalized time with year 2050.
     */
    @Test
    public void testCase8() throws Exception {
        expectInvalidPath("test8", "TE:CP.02.05 Invalid notBefore Generalized 2050");
    }
    
    /**
     * Test 9: TE:CP.03.01 - Invalid CA notAfter Date
     * The intermediate certificate has a notAfter earlier than current time.
     */
    @Test
    public void testCase9() throws Exception {
        expectInvalidPath("test9", "TE:CP.03.01 Invalid CA notAfter Date");
    }
    
    /**
     * Test 10: TE:CP.03.02 - Invalid EE notAfter Date
     * The end certificate has a notAfter earlier than current time.
     */
    @Test
    public void testCase10() throws Exception {
        expectInvalidPath("test10", "TE:CP.03.02 Invalid EE notAfter Date");
    }
    
    /**
     * Test 11: TE:CP.03.03 - Invalid notAfter UTC 50
     * The end certificate has a notAfter set as UTC time with year 50 (should treat as 1950).
     */
    @Test
    public void testCase11() throws Exception {
        expectInvalidPath("test11", "TE:CP.03.03 Invalid notAfter UTC 50");
    }
    
    /**
     * Test 12: TE:CP.03.04 - Valid notAfter Generalized 2050
     * The end certificate has a notAfter set as generalized time with year 2050.
     */
    @Test
    public void testCase12() throws Exception {
        expectValidPath("test12", "TE:CP.03.04 Valid notAfter Generalized 2050");
    }
    
    /**
     * Test 13: TE:CP.04.01 - Invalid Name Chaining - Different Names
     * The names do not chain (cn=A vs cn=B).
     */
    @Test
    public void testCase13() throws Exception {
        expectInvalidPath("test13", "TE:CP.04.01 Invalid Name Chaining Different Names");
    }
    
    /**
     * Test 14: TE:CP.04.02 - Invalid Name Chaining - Order Differs
     * The names differ by order of RDNs.
     */
    @Test
    public void testCase14() throws Exception {
        expectInvalidPath("test14", "TE:CP.04.02 Invalid Name Chaining Order Differs");
    }
    
    /**
     * Test 15: TE:CP.04.03 - Valid Name Chaining - Whitespace/Capitalization
     * The names differ only by whitespace and capitalization (should be insignificant).
     */
    @Test
    public void testCase15() throws Exception {
        expectValidPath("test15", "TE:CP.04.03 Valid Name Chaining Whitespace");
    }
    
    /**
     * Test 16: TE:CP.04.04 - Valid Name Chaining - Whitespace
     * The names differ only by whitespace (cn=My Name vs cn=My  Name).
     */
    @Test
    public void testCase16() throws Exception {
        expectValidPath("test16", "TE:CP.04.04 Valid Name Chaining Whitespace 2");
    }
    
    /**
     * Test 17: TE:CP.04.05 - Valid Name Chaining - Leading/Trailing Whitespace
     * The names differ only by leading/trailing whitespace.
     */
    @Test
    public void testCase17() throws Exception {
        expectValidPath("test17", "TE:CP.04.05 Valid Name Chaining Leading/Trailing Whitespace");
    }
    
    /**
     * Test 18: TE:CP.04.06 - Valid Name Chaining - Capitalization
     * The names differ only by capitalization (cn=A vs cn=a).
     */
    @Test
    public void testCase18() throws Exception {
        expectValidPath("test18", "TE:CP.04.06 Valid Name Chaining Capitalization");
    }
    
    /**
     * Test 19: TE:CP.05.01 - Missing CRL
     * The path contains a certificate without revocation data.
     */
    @Test
    public void testCase19() throws Exception {
        expectInvalidPath("test19", "TE:CP.05.01 Missing CRL");
    }
    
    /**
     * Test 20: TE:CP.06.01 - Revoked CA Certificate
     * The intermediate certificate has been revoked.
     */
    @Test
    public void testCase20() throws Exception {
        expectInvalidPath("test20", "TE:CP.06.01 Revoked CA Certificate");
    }
    
    /**
     * Test 21: TE:CP.06.02 - Revoked EE Certificate
     * The end certificate has been revoked.
     */
    @Test
    public void testCase21() throws Exception {
        expectInvalidPath("test21", "TE:CP.06.02 Revoked EE Certificate");
    }
    
    // ==================== Section 3.2: Intermediate Certificate Processing Tests (IC) ====================
    
    /**
     * Test 22: TE:IC.01.01 - Missing basicConstraints
     * The intermediate certificate does not have a basicConstraints extension.
     */
    @Test
    public void testCase22() throws Exception {
        expectInvalidPath("test22", "TE:IC.01.01 Missing basicConstraints");
    }
    
    /**
     * Test 23: TE:IC.02.01 - basicConstraints cA=false (critical)
     * The intermediate certificate has basicConstraints critical with cA=false.
     */
    @Test
    public void testCase23() throws Exception {
        expectInvalidPath("test23", "TE:IC.02.01 basicConstraints cA=false critical");
    }
    
    /**
     * Test 24: TE:IC.02.02 - basicConstraints cA=true (critical)
     * The intermediate certificate has basicConstraints critical with cA=true.
     */
    @Test
    public void testCase24() throws Exception {
        expectValidPath("test24", "TE:IC.02.02 basicConstraints cA=true critical");
    }
    
    /**
     * Test 25: TE:IC.02.03 - basicConstraints cA=false (non-critical)
     * The intermediate certificate has basicConstraints non-critical with cA=false.
     */
    @Test
    public void testCase25() throws Exception {
        expectInvalidPath("test25", "TE:IC.02.03 basicConstraints cA=false non-critical");
    }
    
    /**
     * Test 26: TE:IC.02.04 - basicConstraints cA=true (non-critical)
     * The intermediate certificate has basicConstraints non-critical with cA=true.
     */
    @Test
    public void testCase26() throws Exception {
        expectValidPath("test26", "TE:IC.02.04 basicConstraints cA=true non-critical");
    }
    
    /**
     * Test 27: TE:IC.04.01 - Valid keyUsage keyCertSign
     * The intermediate certificate has keyUsage with keyCertSign and cRLSign set.
     */
    @Test
    public void testCase27() throws Exception {
        expectValidPath("test27", "TE:IC.04.01 Valid keyUsage keyCertSign");
    }
    
    /**
     * Test 28: TE:IC.05.01 - Invalid keyUsage keyCertSign=false (critical)
     * The intermediate certificate has keyUsage critical with keyCertSign=false.
     */
    @Test
    public void testCase28() throws Exception {
        expectInvalidPath("test28", "TE:IC.05.01 Invalid keyUsage keyCertSign=false critical");
    }
    
    /**
     * Test 29: TE:IC.05.02 - Invalid keyUsage keyCertSign=false (non-critical)
     * The intermediate certificate has keyUsage non-critical with keyCertSign=false.
     */
    @Test
    public void testCase29() throws Exception {
        expectInvalidPath("test29", "TE:IC.05.02 Invalid keyUsage keyCertSign=false non-critical");
    }
    
    /**
     * Test 30: TE:IC.05.03 - Valid keyUsage keyCertSign=true (non-critical)
     * The intermediate certificate has keyUsage non-critical with keyCertSign=true.
     */
    @Test
    public void testCase30() throws Exception {
        expectValidPath("test30", "TE:IC.05.03 Valid keyUsage keyCertSign=true non-critical");
    }
    
    /**
     * Test 31: TE:IC.06.01 - Invalid keyUsage cRLSign=false (critical)
     * The intermediate certificate has keyUsage critical with cRLSign=false.
     */
    @Test
    public void testCase31() throws Exception {
        expectInvalidPath("test31", "TE:IC.06.01 Invalid keyUsage cRLSign=false critical");
    }
    
    /**
     * Test 32: TE:IC.06.02 - Invalid keyUsage cRLSign=false (non-critical)
     * The intermediate certificate has keyUsage non-critical with cRLSign=false.
     */
    @Test
    public void testCase32() throws Exception {
        expectInvalidPath("test32", "TE:IC.06.02 Invalid keyUsage cRLSign=false non-critical");
    }
    
    /**
     * Test 33: TE:IC.06.03 - Valid keyUsage cRLSign=true (non-critical)
     * The intermediate certificate has keyUsage non-critical with cRLSign=true.
     */
    @Test
    public void testCase33() throws Exception {
        expectValidPath("test33", "TE:IC.06.03 Valid keyUsage cRLSign=true non-critical");
    }
    
    // ==================== Section 3.3: Policy Processing Tests (PP) ====================
    // NOTE: Many of these tests require specific policy settings (ipolset, explicit, inhibit)
    // Tests marked with TODO require special validator configuration
    
    /**
     * Test 34: TE:PP.01.01 - All Certificates Same Policy
     * All certificates assert the same policy (test-policy-1).
     * 
     * This test requires 6 sub-tests with different policy configurations:
     * 34_1: ipolset=any-policy, explicit=true  -> accept
     * 34_2: ipolset=any-policy, explicit=false -> accept
     * 34_3: ipolset=test-policy-1, explicit=true  -> accept
     * 34_4: ipolset=test-policy-1, explicit=false -> accept
     * 34_5: ipolset=set NOT including test-policy-1, explicit=true  -> REJECT
     * 34_6: ipolset=set NOT including test-policy-1, explicit=false -> accept
     */
    
    @Test
    public void testCase34_1() throws Exception {
        // Configuration: ipolset=any-policy, explicit=true -> expect accept
        X509Certificate endCert = pkits.loadEndCertificate("test34");
        
        // Configure validator: any-policy (RFC 5280 OID 2.5.29.32.0), explicit=true
        pkits.getValidator().clearInitialPolicySet();
        pkits.getValidator().addInitialPolicy(ANY_POLICY);
        pkits.getValidator().setRequreExplicitPolicy(true);
        
        try {
            PKIXCertPathBuilderResult result = pkits.validateCertificate(endCert, true);
            assertNotNull("TE:PP.01.01 (ipolset=any-policy, explicit=true) should accept", result);
            System.out.println("TE:PP.01.01 testCase34_1 PASSED: ipolset=any-policy, explicit=true -> accepted");
        } catch (Exception e) {
            fail("TE:PP.01.01 (ipolset=any-policy, explicit=true) should accept but failed: " + e.getMessage());
        }
    }
    
    @Test
    public void testCase34_2() throws Exception {
        // Configuration: ipolset=any-policy, explicit=false -> expect accept
        X509Certificate endCert = pkits.loadEndCertificate("test34");
        
        // Configure validator: any-policy (RFC 5280 OID 2.5.29.32.0), explicit=false
        pkits.getValidator().clearInitialPolicySet();
        pkits.getValidator().addInitialPolicy(ANY_POLICY);
        pkits.getValidator().setRequreExplicitPolicy(false);
        
        try {
            PKIXCertPathBuilderResult result = pkits.validateCertificate(endCert, true);
            assertNotNull("TE:PP.01.01 (ipolset=any-policy, explicit=false) should accept", result);
            System.out.println("TE:PP.01.01 testCase34_2 PASSED: ipolset=any-policy, explicit=false -> accepted");
        } catch (Exception e) {
            fail("TE:PP.01.01 (ipolset=any-policy, explicit=false) should accept but failed: " + e.getMessage());
        }
    }
    
    @Test
    public void testCase34_3() throws Exception {
        // Configuration: ipolset=test-policy-1, explicit=true -> expect accept
        X509Certificate endCert = pkits.loadEndCertificate("test34");
        
        // Configure validator: test-policy-1, explicit=true
        pkits.getValidator().clearInitialPolicySet();
        pkits.getValidator().addInitialPolicy(TEST_POLICY_1);
        pkits.getValidator().setRequreExplicitPolicy(true);
        
        try {
            PKIXCertPathBuilderResult result = pkits.validateCertificate(endCert, true);
            assertNotNull("TE:PP.01.01 (ipolset=test-policy-1, explicit=true) should accept", result);
            System.out.println("TE:PP.01.01 testCase34_3 PASSED: ipolset=test-policy-1, explicit=true -> accepted");
        } catch (Exception e) {
            fail("TE:PP.01.01 (ipolset=test-policy-1, explicit=true) should accept but failed: " + e.getMessage());
        }
    }
    
    @Test
    public void testCase34_4() throws Exception {
        // Configuration: ipolset=test-policy-1, explicit=false -> expect accept
        X509Certificate endCert = pkits.loadEndCertificate("test34");
        
        // Configure validator: test-policy-1, explicit=false
        pkits.getValidator().clearInitialPolicySet();
        pkits.getValidator().addInitialPolicy(TEST_POLICY_1);
        pkits.getValidator().setRequreExplicitPolicy(false);
        
        try {
            PKIXCertPathBuilderResult result = pkits.validateCertificate(endCert, true);
            assertNotNull("TE:PP.01.01 (ipolset=test-policy-1, explicit=false) should accept", result);
            System.out.println("TE:PP.01.01 testCase34_4 PASSED: ipolset=test-policy-1, explicit=false -> accepted");
        } catch (Exception e) {
            fail("TE:PP.01.01 (ipolset=test-policy-1, explicit=false) should accept but failed: " + e.getMessage());
        }
    }
    
    @Test
    public void testCase34_5() throws Exception {
        // Configuration: ipolset=set NOT including test-policy-1, explicit=true -> expect REJECT
        X509Certificate endCert = pkits.loadEndCertificate("test34");
        
        // Configure validator: set NOT including test-policy-1 (all others), explicit=true
        pkits.getValidator().clearInitialPolicySet();
        pkits.getValidator().addInitialPolicy(TEST_POLICY_2);
        pkits.getValidator().addInitialPolicy(TEST_POLICY_3);
        pkits.getValidator().addInitialPolicy(TEST_POLICY_4);
        pkits.getValidator().addInitialPolicy(TEST_POLICY_5);
        pkits.getValidator().setRequreExplicitPolicy(true);
        
        try {
            pkits.validateCertificate(endCert, true);
            fail("TE:PP.01.01 (ipolset=set-not-including-test-policy-1, explicit=true) should REJECT but succeeded");
        } catch (Exception e) {
            System.out.println("TE:PP.01.01 testCase34_5 PASSED: ipolset=set-not-including-test-policy-1, explicit=true -> rejected: " + e.getMessage());
        }
    }
    
    @Test
    public void testCase34_6() throws Exception {
        // Configuration: ipolset=set NOT including test-policy-1, explicit=false -> expect accept
        X509Certificate endCert = pkits.loadEndCertificate("test34");
        
        // Configure validator: set NOT including test-policy-1 (all others), explicit=false
        pkits.getValidator().clearInitialPolicySet();
        pkits.getValidator().addInitialPolicy(TEST_POLICY_2);
        pkits.getValidator().addInitialPolicy(TEST_POLICY_3);
        pkits.getValidator().addInitialPolicy(TEST_POLICY_4);
        pkits.getValidator().addInitialPolicy(TEST_POLICY_5);
        pkits.getValidator().setRequreExplicitPolicy(false);
        
        try {
            PKIXCertPathBuilderResult result = pkits.validateCertificate(endCert, true);
            assertNotNull("TE:PP.01.01 (ipolset=not-test-policy-1, explicit=false) should accept", result);
            System.out.println("TE:PP.01.01 testCase34_6 PASSED: ipolset=not-test-policy-1, explicit=false -> accepted");
        } catch (Exception e) {
            fail("TE:PP.01.01 (ipolset=not-test-policy-1, explicit=false) should accept but failed: " + e.getMessage());
        }
    }
    
    /**
     * Test 35: TE:PP.01.02 - No Policy Asserted
     * All certificates have no policy asserted.
     * Authority-constrained policy set: <empty>
     * User-constrained policy set: <empty>
     * 
     * This test requires 2 sub-tests:
     * 35_1: explicit=false -> accept
     * 35_2: explicit=true  -> REJECT
     */
    
    @Test
    public void testCase35_1() throws Exception {
        // Configuration: explicit=false -> expect accept
        X509Certificate endCert = pkits.loadEndCertificate("test35");
        
        // Configure validator: explicit=false
        pkits.getValidator().clearInitialPolicySet();
        pkits.getValidator().setRequreExplicitPolicy(false);
        
        try {
            PKIXCertPathBuilderResult result = pkits.validateCertificate(endCert, true);
            assertNotNull("TE:PP.01.02 (explicit=false) should accept", result);
            System.out.println("TE:PP.01.02 testCase35_1 PASSED: explicit=false -> accepted");
        } catch (Exception e) {
            fail("TE:PP.01.02 (explicit=false) should accept but failed: " + e.getMessage());
        }
    }
    
    @Test
    public void testCase35_2() throws Exception {
        // Configuration: explicit=true -> expect REJECT
        X509Certificate endCert = pkits.loadEndCertificate("test35");
        
        // Configure validator: explicit=true
        pkits.getValidator().clearInitialPolicySet();
        pkits.getValidator().setRequreExplicitPolicy(true);
        
        try {
            pkits.validateCertificate(endCert, true);
            fail("TE:PP.01.02 (explicit=true) should REJECT but succeeded");
        } catch (Exception e) {
            System.out.println("TE:PP.01.02 testCase35_2 PASSED: explicit=true -> rejected: " + e.getMessage());
        }
    }
    
    /**
     * Test 36: TE:PP.01.03 - First Certificate No Policy
     * All certificates except the first certificate in the path have the same policy asserted.
     * Authority-constrained policy set: <empty>
     * User-constrained policy set: <empty>
     * 
     * This test requires 2 sub-tests:
     * 36_1: explicit=false -> accept
     * 36_2: explicit=true  -> REJECT
     */
    
    @Test
    public void testCase36_1() throws Exception {
        // Configuration: explicit=false -> expect accept
        X509Certificate endCert = pkits.loadEndCertificate("test36");
        
        // Configure validator: explicit=false
        pkits.getValidator().clearInitialPolicySet();
        pkits.getValidator().setRequreExplicitPolicy(false);
        
        try {
            PKIXCertPathBuilderResult result = pkits.validateCertificate(endCert, true);
            assertNotNull("TE:PP.01.03 (explicit=false) should accept", result);
            System.out.println("TE:PP.01.03 testCase36_1 PASSED: explicit=false -> accepted");
        } catch (Exception e) {
            fail("TE:PP.01.03 (explicit=false) should accept but failed: " + e.getMessage());
        }
    }
    
    @Test
    public void testCase36_2() throws Exception {
        // Configuration: explicit=true -> expect REJECT
        X509Certificate endCert = pkits.loadEndCertificate("test36");
        
        // Configure validator: explicit=true
        pkits.getValidator().clearInitialPolicySet();
        pkits.getValidator().setRequreExplicitPolicy(true);
        
        try {
            pkits.validateCertificate(endCert, true);
            fail("TE:PP.01.03 (explicit=true) should REJECT but succeeded");
        } catch (Exception e) {
            System.out.println("TE:PP.01.03 testCase36_2 PASSED: explicit=true -> rejected: " + e.getMessage());
        }
    }
    
    /**
     * Test 37: TE:PP.01.04 - End Certificate No Policy
     * All certificates except the end certificate in the path have the same policy asserted.
     * Authority-constrained policy set: <empty>
     * User-constrained policy set: <empty>
     * 
     * This test requires 2 sub-tests:
     * 37_1: explicit=false -> accept
     * 37_2: explicit=true  -> REJECT
     */
    
    @Test
    public void testCase37_1() throws Exception {
        // Configuration: explicit=false -> expect accept
        X509Certificate endCert = pkits.loadEndCertificate("test37");
        
        // Configure validator: explicit=false
        pkits.getValidator().clearInitialPolicySet();
        pkits.getValidator().setRequreExplicitPolicy(false);
        
        try {
            PKIXCertPathBuilderResult result = pkits.validateCertificate(endCert, true);
            assertNotNull("TE:PP.01.04 (explicit=false) should accept", result);
            System.out.println("TE:PP.01.04 testCase37_1 PASSED: explicit=false -> accepted");
        } catch (Exception e) {
            fail("TE:PP.01.04 (explicit=false) should accept but failed: " + e.getMessage());
        }
    }
    
    @Test
    public void testCase37_2() throws Exception {
        // Configuration: explicit=true -> expect REJECT
        X509Certificate endCert = pkits.loadEndCertificate("test37");
        
        // Configure validator: explicit=true
        pkits.getValidator().clearInitialPolicySet();
        pkits.getValidator().setRequreExplicitPolicy(true);
        
        try {
            pkits.validateCertificate(endCert, true);
            fail("TE:PP.01.04 (explicit=true) should REJECT but succeeded");
        } catch (Exception e) {
            System.out.println("TE:PP.01.04 testCase37_2 PASSED: explicit=true -> rejected: " + e.getMessage());
        }
    }
    
    /**
     * Test 38: TE:PP.01.05 - Second Certificate No Policy
     * All certificates except the second certificate in the path have the same policy asserted.
     * Authority-constrained policy set: <empty>
     * User-constrained policy set: <empty>
     * 
     * This test requires 2 sub-tests:
     * 38_1: explicit=false -> accept
     * 38_2: explicit=true  -> REJECT
     */
    
    @Test
    public void testCase38_1() throws Exception {
        // Configuration: explicit=false -> expect accept
        X509Certificate endCert = pkits.loadEndCertificate("test38");
        
        // Configure validator: explicit=false
        pkits.getValidator().clearInitialPolicySet();
        pkits.getValidator().setRequreExplicitPolicy(false);
        
        try {
            PKIXCertPathBuilderResult result = pkits.validateCertificate(endCert, true);
            assertNotNull("TE:PP.01.05 (explicit=false) should accept", result);
            System.out.println("TE:PP.01.05 testCase38_1 PASSED: explicit=false -> accepted");
        } catch (Exception e) {
            fail("TE:PP.01.05 (explicit=false) should accept but failed: " + e.getMessage());
        }
    }
    
    @Test
    public void testCase38_2() throws Exception {
        // Configuration: explicit=true -> expect REJECT
        X509Certificate endCert = pkits.loadEndCertificate("test38");
        
        // Configure validator: explicit=true
        pkits.getValidator().clearInitialPolicySet();
        pkits.getValidator().setRequreExplicitPolicy(true);
        
        try {
            pkits.validateCertificate(endCert, true);
            fail("TE:PP.01.05 (explicit=true) should REJECT but succeeded");
        } catch (Exception e) {
            System.out.println("TE:PP.01.05 testCase38_2 PASSED: explicit=true -> rejected: " + e.getMessage());
        }
    }
    
    /**
     * Test 39: TE:PP.01.06 - Policy Intersection One Policy
     * The intersection of certificate policies among all certificates has exactly one policy.
     * Authority-constrained policy set: test-policy-1
     * 
     * This test requires 6 sub-tests with different policy configurations:
     * 39_1: ipolset=any-policy, explicit=true  -> accept
     * 39_2: ipolset=any-policy, explicit=false -> accept
     * 39_3: ipolset=set including test-policy-1, explicit=true  -> accept
     * 39_4: ipolset=set including test-policy-1, explicit=false -> accept
     * 39_5: ipolset=set NOT including test-policy-1, explicit=true  -> REJECT
     * 39_6: ipolset=set NOT including test-policy-1, explicit=false -> accept
     */
    
    @Test
    public void testCase39_1() throws Exception {
        // Configuration: ipolset=any-policy, explicit=true -> expect accept
        X509Certificate endCert = pkits.loadEndCertificate("test39");
        
        // Configure validator: any-policy (RFC 5280 OID 2.5.29.32.0), explicit=true
        pkits.getValidator().clearInitialPolicySet();
        pkits.getValidator().addInitialPolicy(ANY_POLICY);
        pkits.getValidator().setRequreExplicitPolicy(true);
        
        try {
            PKIXCertPathBuilderResult result = pkits.validateCertificate(endCert, true);
            assertNotNull("TE:PP.01.06 (ipolset=any-policy, explicit=true) should accept", result);
            System.out.println("TE:PP.01.06 testCase39_1 PASSED: ipolset=any-policy, explicit=true -> accepted");
        } catch (Exception e) {
            fail("TE:PP.01.06 (ipolset=any-policy, explicit=true) should accept but failed: " + e.getMessage());
        }
    }
    
    @Test
    public void testCase39_2() throws Exception {
        // Configuration: ipolset=any-policy, explicit=false -> expect accept
        X509Certificate endCert = pkits.loadEndCertificate("test39");
        
        // Configure validator: any-policy (RFC 5280 OID 2.5.29.32.0), explicit=false
        pkits.getValidator().clearInitialPolicySet();
        pkits.getValidator().addInitialPolicy(ANY_POLICY);
        pkits.getValidator().setRequreExplicitPolicy(false);
        
        try {
            PKIXCertPathBuilderResult result = pkits.validateCertificate(endCert, true);
            assertNotNull("TE:PP.01.06 (ipolset=any-policy, explicit=false) should accept", result);
            System.out.println("TE:PP.01.06 testCase39_2 PASSED: ipolset=any-policy, explicit=false -> accepted");
        } catch (Exception e) {
            fail("TE:PP.01.06 (ipolset=any-policy, explicit=false) should accept but failed: " + e.getMessage());
        }
    }
    
    @Test
    public void testCase39_3() throws Exception {
        // Configuration: ipolset=set including test-policy-1, explicit=true -> expect accept
        X509Certificate endCert = pkits.loadEndCertificate("test39");
        
        // Configure validator: test-policy-1, explicit=true
        pkits.getValidator().clearInitialPolicySet();
        pkits.getValidator().addInitialPolicy(TEST_POLICY_1);
        pkits.getValidator().setRequreExplicitPolicy(true);
        
        try {
            PKIXCertPathBuilderResult result = pkits.validateCertificate(endCert, true);
            assertNotNull("TE:PP.01.06 (ipolset=test-policy-1, explicit=true) should accept", result);
            System.out.println("TE:PP.01.06 testCase39_3 PASSED: ipolset=test-policy-1, explicit=true -> accepted");
        } catch (Exception e) {
            fail("TE:PP.01.06 (ipolset=test-policy-1, explicit=true) should accept but failed: " + e.getMessage());
        }
    }
    
    @Test
    public void testCase39_4() throws Exception {
        // Configuration: ipolset=set including test-policy-1, explicit=false -> expect accept
        X509Certificate endCert = pkits.loadEndCertificate("test39");
        
        // Configure validator: test-policy-1, explicit=false
        pkits.getValidator().clearInitialPolicySet();
        pkits.getValidator().addInitialPolicy(TEST_POLICY_1);
        pkits.getValidator().setRequreExplicitPolicy(false);
        
        try {
            PKIXCertPathBuilderResult result = pkits.validateCertificate(endCert, true);
            assertNotNull("TE:PP.01.06 (ipolset=test-policy-1, explicit=false) should accept", result);
            System.out.println("TE:PP.01.06 testCase39_4 PASSED: ipolset=test-policy-1, explicit=false -> accepted");
        } catch (Exception e) {
            fail("TE:PP.01.06 (ipolset=test-policy-1, explicit=false) should accept but failed: " + e.getMessage());
        }
    }
    
    @Test
    public void testCase39_5() throws Exception {
        // Configuration: ipolset=set NOT including test-policy-1, explicit=true -> expect REJECT
        X509Certificate endCert = pkits.loadEndCertificate("test39");
        
        // Configure validator: set NOT including test-policy-1 (all others), explicit=true
        pkits.getValidator().clearInitialPolicySet();
        pkits.getValidator().addInitialPolicy(TEST_POLICY_2);
        pkits.getValidator().addInitialPolicy(TEST_POLICY_3);
        pkits.getValidator().addInitialPolicy(TEST_POLICY_4);
        pkits.getValidator().addInitialPolicy(TEST_POLICY_5);
        pkits.getValidator().setRequreExplicitPolicy(true);
        
        try {
            pkits.validateCertificate(endCert, true);
            fail("TE:PP.01.06 (ipolset=set-not-including-test-policy-1, explicit=true) should REJECT but succeeded");
        } catch (Exception e) {
            System.out.println("TE:PP.01.06 testCase39_5 PASSED: ipolset=set-not-including-test-policy-1, explicit=true -> rejected: " + e.getMessage());
        }
    }
    
    @Test
    public void testCase39_6() throws Exception {
        // Configuration: ipolset=set NOT including test-policy-1, explicit=false -> expect accept
        X509Certificate endCert = pkits.loadEndCertificate("test39");
        
        // Configure validator: set NOT including test-policy-1 (all others), explicit=false
        pkits.getValidator().clearInitialPolicySet();
        pkits.getValidator().addInitialPolicy(TEST_POLICY_2);
        pkits.getValidator().addInitialPolicy(TEST_POLICY_3);
        pkits.getValidator().addInitialPolicy(TEST_POLICY_4);
        pkits.getValidator().addInitialPolicy(TEST_POLICY_5);
        pkits.getValidator().setRequreExplicitPolicy(false);
        
        try {
            PKIXCertPathBuilderResult result = pkits.validateCertificate(endCert, true);
            assertNotNull("TE:PP.01.06 (ipolset=set-not-including-test-policy-1, explicit=false) should accept", result);
            System.out.println("TE:PP.01.06 testCase39_6 PASSED: ipolset=set-not-including-test-policy-1, explicit=false -> accepted");
        } catch (Exception e) {
            fail("TE:PP.01.06 (ipolset=set-not-including-test-policy-1, explicit=false) should accept but failed: " + e.getMessage());
        }
    }
    
    /**
     * Test 40: TE:PP.01.07 - Policy Intersection Empty
     * The intersection of certificate policies among all certificates is empty,
     * even though all certificates assert a policy.
     * Authority-constrained policy set: <empty>
     * User-constrained policy set: <empty>
     * 
     * This test requires 2 sub-tests:
     * 40_1: explicit=false -> accept
     * 40_2: explicit=true  -> REJECT
     */
    
    @Test
    public void testCase40_1() throws Exception {
        // Configuration: explicit=false -> expect accept
        X509Certificate endCert = pkits.loadEndCertificate("test40");
        
        // Configure validator: explicit=false
        pkits.getValidator().clearInitialPolicySet();
        pkits.getValidator().setRequreExplicitPolicy(false);
        
        try {
            PKIXCertPathBuilderResult result = pkits.validateCertificate(endCert, true);
            assertNotNull("TE:PP.01.07 (explicit=false) should accept", result);
            System.out.println("TE:PP.01.07 testCase40_1 PASSED: explicit=false -> accepted");
        } catch (Exception e) {
            fail("TE:PP.01.07 (explicit=false) should accept but failed: " + e.getMessage());
        }
    }
    
    @Test
    public void testCase40_2() throws Exception {
        // Configuration: explicit=true -> expect REJECT
        X509Certificate endCert = pkits.loadEndCertificate("test40");
        
        // Configure validator: explicit=true
        pkits.getValidator().clearInitialPolicySet();
        pkits.getValidator().setRequreExplicitPolicy(true);
        
        try {
            pkits.validateCertificate(endCert, true);
            fail("TE:PP.01.07 (explicit=true) should REJECT but succeeded");
        } catch (Exception e) {
            System.out.println("TE:PP.01.07 testCase40_2 PASSED: explicit=true -> rejected: " + e.getMessage());
        }
    }
    
    /**
     * Test 41: TE:PP.01.08 - Policy Intersection Empty 2
     * The intersection of certificate policies among all certificates is empty,
     * even though all certificates assert a policy.
     * Authority-constrained policy set: <empty>
     * User-constrained policy set: <empty>
     * 
     * This test requires 2 sub-tests:
     * 41_1: explicit=false -> accept
     * 41_2: explicit=true  -> REJECT
     */
    
    @Test
    public void testCase41_1() throws Exception {
        // Configuration: explicit=false -> expect accept
        X509Certificate endCert = pkits.loadEndCertificate("test41");
        
        // Configure validator: explicit=false
        pkits.getValidator().clearInitialPolicySet();
        pkits.getValidator().setRequreExplicitPolicy(false);
        
        try {
            PKIXCertPathBuilderResult result = pkits.validateCertificate(endCert, true);
            assertNotNull("TE:PP.01.08 (explicit=false) should accept", result);
            System.out.println("TE:PP.01.08 testCase41_1 PASSED: explicit=false -> accepted");
        } catch (Exception e) {
            fail("TE:PP.01.08 (explicit=false) should accept but failed: " + e.getMessage());
        }
    }
    
    @Test
    public void testCase41_2() throws Exception {
        // Configuration: explicit=true -> expect REJECT
        X509Certificate endCert = pkits.loadEndCertificate("test41");
        
        // Configure validator: explicit=true
        pkits.getValidator().clearInitialPolicySet();
        pkits.getValidator().setRequreExplicitPolicy(true);
        
        try {
            pkits.validateCertificate(endCert, true);
            fail("TE:PP.01.08 (explicit=true) should REJECT but succeeded");
        } catch (Exception e) {
            System.out.println("TE:PP.01.08 testCase41_2 PASSED: explicit=true -> rejected: " + e.getMessage());
        }
    }
    
    /**
     * Test 42: TE:PP.01.09 - Policy Intersection Empty 3
     * The intersection of certificate policies among all certificates is empty,
     * even though all certificates assert a policy.
     * Authority-constrained policy set: <empty>
     * User-constrained policy set: <empty>
     * 
     * This test requires 2 sub-tests:
     * 42_1: explicit=false -> accept
     * 42_2: explicit=true  -> REJECT
     */
    
    @Test
    public void testCase42_1() throws Exception {
        // Configuration: explicit=false -> expect accept
        X509Certificate endCert = pkits.loadEndCertificate("test42");
        
        // Configure validator: explicit=false
        pkits.getValidator().clearInitialPolicySet();
        pkits.getValidator().setRequreExplicitPolicy(false);
        
        try {
            PKIXCertPathBuilderResult result = pkits.validateCertificate(endCert, true);
            assertNotNull("TE:PP.01.09 (explicit=false) should accept", result);
            System.out.println("TE:PP.01.09 testCase42_1 PASSED: explicit=false -> accepted");
        } catch (Exception e) {
            fail("TE:PP.01.09 (explicit=false) should accept but failed: " + e.getMessage());
        }
    }
    
    @Test
    public void testCase42_2() throws Exception {
        // Configuration: explicit=true -> expect REJECT
        X509Certificate endCert = pkits.loadEndCertificate("test42");
        
        // Configure validator: explicit=true
        pkits.getValidator().clearInitialPolicySet();
        pkits.getValidator().setRequreExplicitPolicy(true);
        
        try {
            pkits.validateCertificate(endCert, true);
            fail("TE:PP.01.09 (explicit=true) should REJECT but succeeded");
        } catch (Exception e) {
            System.out.println("TE:PP.01.09 testCase42_2 PASSED: explicit=true -> rejected: " + e.getMessage());
        }
    }
    
    /**
     * Test 43: TE:PP.06.01 - requireExplicitPolicy=10
     * The first certificate in the path (length 5) contains the policy constraints
     * extension with requireExplicitPolicy=10.
     * Authority-constrained policy set: <empty>
     * User-constrained policy set: <empty>
     * 
     * This test requires 2 sub-tests:
     * 43_1: explicit=false -> accept
     * 43_2: explicit=true  -> REJECT
     */
    
    @Test
    public void testCase43_1() throws Exception {
        // Configuration: explicit=false -> expect accept
        X509Certificate endCert = pkits.loadEndCertificate("test43");
        
        // Configure validator: explicit=false
        pkits.getValidator().clearInitialPolicySet();
        pkits.getValidator().setRequreExplicitPolicy(false);
        
        try {
            PKIXCertPathBuilderResult result = pkits.validateCertificate(endCert, true);
            assertNotNull("TE:PP.06.01 (explicit=false) should accept", result);
            System.out.println("TE:PP.06.01 testCase43_1 PASSED: explicit=false -> accepted");
        } catch (Exception e) {
            fail("TE:PP.06.01 (explicit=false) should accept but failed: " + e.getMessage());
        }
    }
    
    @Test
    public void testCase43_2() throws Exception {
        // Configuration: explicit=true -> expect REJECT
        X509Certificate endCert = pkits.loadEndCertificate("test43");
        
        // Configure validator: explicit=true
        pkits.getValidator().clearInitialPolicySet();
        pkits.getValidator().setRequreExplicitPolicy(true);
        
        try {
            pkits.validateCertificate(endCert, true);
            fail("TE:PP.06.01 (explicit=true) should REJECT but succeeded");
        } catch (Exception e) {
            System.out.println("TE:PP.06.01 testCase43_2 PASSED: explicit=true -> rejected: " + e.getMessage());
        }
    }
    
    /**
     * Test 44: TE:PP.06.02 - requireExplicitPolicy=5
     * The first certificate in the path (length 5) contains the policy constraints
     * extension with requireExplicitPolicy=5.
     * Authority-constrained policy set: <empty>
     * User-constrained policy set: <empty>
     * 
     * This test requires 2 sub-tests:
     * 44_1: explicit=false -> accept
     * 44_2: explicit=true  -> REJECT
     */
    
    @Test
    public void testCase44_1() throws Exception {
        // Configuration: explicit=false -> expect accept
        X509Certificate endCert = pkits.loadEndCertificate("test44");
        
        // Configure validator: explicit=false
        pkits.getValidator().clearInitialPolicySet();
        pkits.getValidator().setRequreExplicitPolicy(false);
        
        try {
            PKIXCertPathBuilderResult result = pkits.validateCertificate(endCert, true);
            assertNotNull("TE:PP.06.02 (explicit=false) should accept", result);
            System.out.println("TE:PP.06.02 testCase44_1 PASSED: explicit=false -> accepted");
        } catch (Exception e) {
            fail("TE:PP.06.02 (explicit=false) should accept but failed: " + e.getMessage());
        }
    }
    
    @Test
    public void testCase44_2() throws Exception {
        // Configuration: explicit=true -> expect REJECT
        X509Certificate endCert = pkits.loadEndCertificate("test44");
        
        // Configure validator: explicit=true
        pkits.getValidator().clearInitialPolicySet();
        pkits.getValidator().setRequreExplicitPolicy(true);
        
        try {
            pkits.validateCertificate(endCert, true);
            fail("TE:PP.06.02 (explicit=true) should REJECT but succeeded");
        } catch (Exception e) {
            System.out.println("TE:PP.06.02 testCase44_2 PASSED: explicit=true -> rejected: " + e.getMessage());
        }
    }
    
    /**
     * Test 45: TE:PP.06.03 - requireExplicitPolicy=4
     * The first certificate in the path (length 5) contains the policy constraints
     * extension with requireExplicitPolicy=4.
     * Authority-constrained policy set: <empty>
     * User-constrained policy set: <empty>
     * Explicit Policy Indicator: true (regardless of input)
     * 
     * This test requires 2 sub-tests - both REJECT:
     * 45_1: explicit=false -> REJECT
     * 45_2: explicit=true  -> REJECT
     */
    
    @Test
    public void testCase45_1() throws Exception {
        // Configuration: explicit=false -> expect REJECT
        X509Certificate endCert = pkits.loadEndCertificate("test45");
        
        // Configure validator: explicit=false
        pkits.getValidator().clearInitialPolicySet();
        pkits.getValidator().setRequreExplicitPolicy(false);
        
        try {
            pkits.validateCertificate(endCert, true);
            fail("TE:PP.06.03 (explicit=false) should REJECT but succeeded");
        } catch (Exception e) {
            System.out.println("TE:PP.06.03 testCase45_1 PASSED: explicit=false -> rejected: " + e.getMessage());
        }
    }
    
    @Test
    public void testCase45_2() throws Exception {
        // Configuration: explicit=true -> expect REJECT
        X509Certificate endCert = pkits.loadEndCertificate("test45");
        
        // Configure validator: explicit=true
        pkits.getValidator().clearInitialPolicySet();
        pkits.getValidator().setRequreExplicitPolicy(true);
        
        try {
            pkits.validateCertificate(endCert, true);
            fail("TE:PP.06.03 (explicit=true) should REJECT but succeeded");
        } catch (Exception e) {
            System.out.println("TE:PP.06.03 testCase45_2 PASSED: explicit=true -> rejected: " + e.getMessage());
        }
    }
    
    /**
     * Test 46: TE:PP.06.04 - requireExplicitPolicy=0 with Policy
     * The first certificate contains policy constraints with requireExplicitPolicy=0.
     * All certificates in the path contain a certificate policy.
     * Authority-constrained policy set: test-policy-1
     * Explicit Policy Indicator: true (regardless of input)
     * 
     * This test requires 6 sub-tests:
     * 46_1: ipolset=any-policy, explicit=false -> accept
     * 46_2: ipolset=any-policy, explicit=true  -> accept
     * 46_3: ipolset=set including test-policy-1, explicit=true  -> accept
     * 46_4: ipolset=set including test-policy-1, explicit=false -> accept
     * 46_5: ipolset=set NOT including test-policy-1, explicit=true  -> REJECT
     * 46_6: ipolset=set NOT including test-policy-1, explicit=false -> REJECT
     */
    
    @Test
    public void testCase46_1() throws Exception {
        // Configuration: ipolset=any-policy, explicit=false -> expect accept
        X509Certificate endCert = pkits.loadEndCertificate("test46");
        
        // Configure validator: any-policy (RFC 5280 OID 2.5.29.32.0), explicit=false
        pkits.getValidator().clearInitialPolicySet();
        pkits.getValidator().addInitialPolicy(ANY_POLICY);
        pkits.getValidator().setRequreExplicitPolicy(false);
        
        try {
            PKIXCertPathBuilderResult result = pkits.validateCertificate(endCert, true);
            assertNotNull("TE:PP.06.04 (ipolset=any-policy, explicit=false) should accept", result);
            System.out.println("TE:PP.06.04 testCase46_1 PASSED: ipolset=any-policy, explicit=false -> accepted");
        } catch (Exception e) {
            fail("TE:PP.06.04 (ipolset=any-policy, explicit=false) should accept but failed: " + e.getMessage());
        }
    }
    
    @Test
    public void testCase46_2() throws Exception {
        // Configuration: ipolset=any-policy, explicit=true -> expect accept
        X509Certificate endCert = pkits.loadEndCertificate("test46");
        
        // Configure validator: any-policy (RFC 5280 OID 2.5.29.32.0), explicit=true
        pkits.getValidator().clearInitialPolicySet();
        pkits.getValidator().addInitialPolicy(ANY_POLICY);
        pkits.getValidator().setRequreExplicitPolicy(true);
        
        try {
            PKIXCertPathBuilderResult result = pkits.validateCertificate(endCert, true);
            assertNotNull("TE:PP.06.04 (ipolset=any-policy, explicit=true) should accept", result);
            System.out.println("TE:PP.06.04 testCase46_2 PASSED: ipolset=any-policy, explicit=true -> accepted");
        } catch (Exception e) {
            fail("TE:PP.06.04 (ipolset=any-policy, explicit=true) should accept but failed: " + e.getMessage());
        }
    }
    
    @Test
    public void testCase46_3() throws Exception {
        // Configuration: ipolset=set including test-policy-1, explicit=true -> expect accept
        X509Certificate endCert = pkits.loadEndCertificate("test46");
        
        // Configure validator: test-policy-1, explicit=true
        pkits.getValidator().clearInitialPolicySet();
        pkits.getValidator().addInitialPolicy(TEST_POLICY_1);
        pkits.getValidator().setRequreExplicitPolicy(true);
        
        try {
            PKIXCertPathBuilderResult result = pkits.validateCertificate(endCert, true);
            assertNotNull("TE:PP.06.04 (ipolset=test-policy-1, explicit=true) should accept", result);
            System.out.println("TE:PP.06.04 testCase46_3 PASSED: ipolset=test-policy-1, explicit=true -> accepted");
        } catch (Exception e) {
            fail("TE:PP.06.04 (ipolset=test-policy-1, explicit=true) should accept but failed: " + e.getMessage());
        }
    }
    
    @Test
    public void testCase46_4() throws Exception {
        // Configuration: ipolset=set including test-policy-1, explicit=false -> expect accept
        X509Certificate endCert = pkits.loadEndCertificate("test46");
        
        // Configure validator: test-policy-1, explicit=false
        pkits.getValidator().clearInitialPolicySet();
        pkits.getValidator().addInitialPolicy(TEST_POLICY_1);
        pkits.getValidator().setRequreExplicitPolicy(false);
        
        try {
            PKIXCertPathBuilderResult result = pkits.validateCertificate(endCert, true);
            assertNotNull("TE:PP.06.04 (ipolset=test-policy-1, explicit=false) should accept", result);
            System.out.println("TE:PP.06.04 testCase46_4 PASSED: ipolset=test-policy-1, explicit=false -> accepted");
        } catch (Exception e) {
            fail("TE:PP.06.04 (ipolset=test-policy-1, explicit=false) should accept but failed: " + e.getMessage());
        }
    }
    
    @Test
    public void testCase46_5() throws Exception {
        // Configuration: ipolset=set NOT including test-policy-1, explicit=true -> expect REJECT
        X509Certificate endCert = pkits.loadEndCertificate("test46");
        
        // Configure validator: set NOT including test-policy-1 (all others), explicit=true
        pkits.getValidator().clearInitialPolicySet();
        pkits.getValidator().addInitialPolicy(TEST_POLICY_2);
        pkits.getValidator().addInitialPolicy(TEST_POLICY_3);
        pkits.getValidator().addInitialPolicy(TEST_POLICY_4);
        pkits.getValidator().addInitialPolicy(TEST_POLICY_5);
        pkits.getValidator().setRequreExplicitPolicy(true);
        
        try {
            pkits.validateCertificate(endCert, true);
            fail("TE:PP.06.04 (ipolset=set-not-including-test-policy-1, explicit=true) should REJECT but succeeded");
        } catch (Exception e) {
            System.out.println("TE:PP.06.04 testCase46_5 PASSED: ipolset=set-not-including-test-policy-1, explicit=true -> rejected: " + e.getMessage());
        }
    }
    
    @Test
    public void testCase46_6() throws Exception {
        // Configuration: ipolset=set NOT including test-policy-1, explicit=false -> expect REJECT
        X509Certificate endCert = pkits.loadEndCertificate("test46");
        
        // Configure validator: set NOT including test-policy-1 (all others), explicit=false
        pkits.getValidator().clearInitialPolicySet();
        pkits.getValidator().addInitialPolicy(TEST_POLICY_2);
        pkits.getValidator().addInitialPolicy(TEST_POLICY_3);
        pkits.getValidator().addInitialPolicy(TEST_POLICY_4);
        pkits.getValidator().addInitialPolicy(TEST_POLICY_5);
        pkits.getValidator().setRequreExplicitPolicy(false);
        
        try {
            pkits.validateCertificate(endCert, true);
            fail("TE:PP.06.04 (ipolset=set-not-including-test-policy-1, explicit=false) should REJECT but succeeded");
        } catch (Exception e) {
            System.out.println("TE:PP.06.04 testCase46_6 PASSED: ipolset=set-not-including-test-policy-1, explicit=false -> rejected: " + e.getMessage());
        }
    }
    
    /**
     * Test 47: TE:PP.06.05 - Multiple requireExplicitPolicy
     * The first certificate has requireExplicitPolicy=7, the second has requireExplicitPolicy=2,
     * and the third has requireExplicitPolicy=4.
     * Authority-constrained policy set: <empty>
     * User-constrained policy set: <empty>
     * Explicit Policy Indicator: true (regardless of input)
     * 
     * This test requires 2 sub-tests - both REJECT:
     * 47_1: explicit=false -> REJECT
     * 47_2: explicit=true  -> REJECT
     */
    
    @Test
    public void testCase47_1() throws Exception {
        // Configuration: explicit=false -> expect REJECT
        X509Certificate endCert = pkits.loadEndCertificate("test47");
        
        // Configure validator: explicit=false
        pkits.getValidator().clearInitialPolicySet();
        pkits.getValidator().setRequreExplicitPolicy(false);
        
        try {
            pkits.validateCertificate(endCert, true);
            fail("TE:PP.06.05 (explicit=false) should REJECT but succeeded");
        } catch (Exception e) {
            System.out.println("TE:PP.06.05 testCase47_1 PASSED: explicit=false -> rejected: " + e.getMessage());
        }
    }
    
    @Test
    public void testCase47_2() throws Exception {
        // Configuration: explicit=true -> expect REJECT
        X509Certificate endCert = pkits.loadEndCertificate("test47");
        
        // Configure validator: explicit=true
        pkits.getValidator().clearInitialPolicySet();
        pkits.getValidator().setRequreExplicitPolicy(true);
        
        try {
            pkits.validateCertificate(endCert, true);
            fail("TE:PP.06.05 (explicit=true) should REJECT but succeeded");
        } catch (Exception e) {
            System.out.println("TE:PP.06.05 testCase47_2 PASSED: explicit=true -> rejected: " + e.getMessage());
        }
    }
    
    /**
     * Test 48: TE:PP.08.01 - User Constrained Policy Set
     * All certificates in the path assert the same policy (test-policy-1).
     * Authority-constrained policy set: test-policy-1
     * 
     * This test requires 6 sub-tests:
     * 48_1: ipolset=test-policy-1, explicit=false -> accept
     * 48_2: ipolset=test-policy-1, explicit=true  -> accept
     * 48_3: ipolset=any-policy, explicit=false -> accept
     * 48_4: ipolset=any-policy, explicit=true  -> accept
     * 48_5: ipolset=set NOT including test-policy-1, explicit=false -> accept
     * 48_6: ipolset=set NOT including test-policy-1, explicit=true  -> REJECT
     */
    
    @Test
    public void testCase48_1() throws Exception {
        // Configuration: ipolset=test-policy-1, explicit=false -> expect accept
        X509Certificate endCert = pkits.loadEndCertificate("test48");
        
        // Configure validator: test-policy-1, explicit=false
        pkits.getValidator().clearInitialPolicySet();
        pkits.getValidator().addInitialPolicy(TEST_POLICY_1);
        pkits.getValidator().setRequreExplicitPolicy(false);
        
        try {
            PKIXCertPathBuilderResult result = pkits.validateCertificate(endCert, true);
            assertNotNull("TE:PP.08.01 (ipolset=test-policy-1, explicit=false) should accept", result);
            System.out.println("TE:PP.08.01 testCase48_1 PASSED: ipolset=test-policy-1, explicit=false -> accepted");
        } catch (Exception e) {
            fail("TE:PP.08.01 (ipolset=test-policy-1, explicit=false) should accept but failed: " + e.getMessage());
        }
    }
    
    @Test
    public void testCase48_2() throws Exception {
        // Configuration: ipolset=test-policy-1, explicit=true -> expect accept
        X509Certificate endCert = pkits.loadEndCertificate("test48");
        
        // Configure validator: test-policy-1, explicit=true
        pkits.getValidator().clearInitialPolicySet();
        pkits.getValidator().addInitialPolicy(TEST_POLICY_1);
        pkits.getValidator().setRequreExplicitPolicy(true);
        
        try {
            PKIXCertPathBuilderResult result = pkits.validateCertificate(endCert, true);
            assertNotNull("TE:PP.08.01 (ipolset=test-policy-1, explicit=true) should accept", result);
            System.out.println("TE:PP.08.01 testCase48_2 PASSED: ipolset=test-policy-1, explicit=true -> accepted");
        } catch (Exception e) {
            fail("TE:PP.08.01 (ipolset=test-policy-1, explicit=true) should accept but failed: " + e.getMessage());
        }
    }
    
    @Test
    public void testCase48_3() throws Exception {
        // Configuration: ipolset=any-policy, explicit=false -> expect accept
        X509Certificate endCert = pkits.loadEndCertificate("test48");
        
        // Configure validator: any-policy (RFC 5280 OID 2.5.29.32.0), explicit=false
        pkits.getValidator().clearInitialPolicySet();
        pkits.getValidator().addInitialPolicy(ANY_POLICY);
        pkits.getValidator().setRequreExplicitPolicy(false);
        
        try {
            PKIXCertPathBuilderResult result = pkits.validateCertificate(endCert, true);
            assertNotNull("TE:PP.08.01 (ipolset=any-policy, explicit=false) should accept", result);
            System.out.println("TE:PP.08.01 testCase48_3 PASSED: ipolset=any-policy, explicit=false -> accepted");
        } catch (Exception e) {
            fail("TE:PP.08.01 (ipolset=any-policy, explicit=false) should accept but failed: " + e.getMessage());
        }
    }
    
    @Test
    public void testCase48_4() throws Exception {
        // Configuration: ipolset=any-policy, explicit=true -> expect accept
        X509Certificate endCert = pkits.loadEndCertificate("test48");
        
        // Configure validator: any-policy (RFC 5280 OID 2.5.29.32.0), explicit=true
        pkits.getValidator().clearInitialPolicySet();
        pkits.getValidator().addInitialPolicy(ANY_POLICY);
        pkits.getValidator().setRequreExplicitPolicy(true);
        
        try {
            PKIXCertPathBuilderResult result = pkits.validateCertificate(endCert, true);
            assertNotNull("TE:PP.08.01 (ipolset=any-policy, explicit=true) should accept", result);
            System.out.println("TE:PP.08.01 testCase48_4 PASSED: ipolset=any-policy, explicit=true -> accepted");
        } catch (Exception e) {
            fail("TE:PP.08.01 (ipolset=any-policy, explicit=true) should accept but failed: " + e.getMessage());
        }
    }
    
    @Test
    public void testCase48_5() throws Exception {
        // Configuration: ipolset=set NOT including test-policy-1, explicit=false -> expect accept
        X509Certificate endCert = pkits.loadEndCertificate("test48");
        
        // Configure validator: set NOT including test-policy-1 (all others), explicit=false
        pkits.getValidator().clearInitialPolicySet();
        pkits.getValidator().addInitialPolicy(TEST_POLICY_2);
        pkits.getValidator().addInitialPolicy(TEST_POLICY_3);
        pkits.getValidator().addInitialPolicy(TEST_POLICY_4);
        pkits.getValidator().addInitialPolicy(TEST_POLICY_5);
        pkits.getValidator().setRequreExplicitPolicy(false);
        
        try {
            PKIXCertPathBuilderResult result = pkits.validateCertificate(endCert, true);
            assertNotNull("TE:PP.08.01 (ipolset=set-not-including-test-policy-1, explicit=false) should accept", result);
            System.out.println("TE:PP.08.01 testCase48_5 PASSED: ipolset=set-not-including-test-policy-1, explicit=false -> accepted");
        } catch (Exception e) {
            fail("TE:PP.08.01 (ipolset=set-not-including-test-policy-1, explicit=false) should accept but failed: " + e.getMessage());
        }
    }
    
    @Test
    public void testCase48_6() throws Exception {
        // Configuration: ipolset=set NOT including test-policy-1, explicit=true -> expect REJECT
        X509Certificate endCert = pkits.loadEndCertificate("test48");
        
        // Configure validator: set NOT including test-policy-1 (all others), explicit=true
        pkits.getValidator().clearInitialPolicySet();
        pkits.getValidator().addInitialPolicy(TEST_POLICY_2);
        pkits.getValidator().addInitialPolicy(TEST_POLICY_3);
        pkits.getValidator().addInitialPolicy(TEST_POLICY_4);
        pkits.getValidator().addInitialPolicy(TEST_POLICY_5);
        pkits.getValidator().setRequreExplicitPolicy(true);
        
        try {
            pkits.validateCertificate(endCert, true);
            fail("TE:PP.08.01 (ipolset=set-not-including-test-policy-1, explicit=true) should REJECT but succeeded");
        } catch (Exception e) {
            System.out.println("TE:PP.08.01 testCase48_6 PASSED: ipolset=set-not-including-test-policy-1, explicit=true -> rejected: " + e.getMessage());
        }
    }
    
    /**
     * Test 49: TE:PP.08.02 - Two Policies Asserted
     * All certificates in the path assert the same two policies (test-policy-1 and test-policy-2).
     * Authority-constrained policy set: test-policy-1, test-policy-2
     * 
     * This test requires 6 sub-tests:
     * 49_1: ipolset=test-policy-1, explicit=false -> accept
     * 49_2: ipolset=test-policy-1, explicit=true  -> accept
     * 49_3: ipolset=set NOT including test-policy-1 or test-policy-2, explicit=false -> accept
     * 49_4: ipolset=set NOT including test-policy-1 or test-policy-2, explicit=true  -> REJECT
     * 49_5: ipolset=any-policy, explicit=false -> accept
     * 49_6: ipolset=any-policy, explicit=true  -> accept
     */
    
    @Test
    public void testCase49_1() throws Exception {
        // Configuration: ipolset=test-policy-1, explicit=false -> expect accept
        X509Certificate endCert = pkits.loadEndCertificate("test49");
        
        // Configure validator: test-policy-1, explicit=false
        pkits.getValidator().clearInitialPolicySet();
        pkits.getValidator().addInitialPolicy(TEST_POLICY_1);
        pkits.getValidator().setRequreExplicitPolicy(false);
        
        try {
            PKIXCertPathBuilderResult result = pkits.validateCertificate(endCert, true);
            assertNotNull("TE:PP.08.02 (ipolset=test-policy-1, explicit=false) should accept", result);
            System.out.println("TE:PP.08.02 testCase49_1 PASSED: ipolset=test-policy-1, explicit=false -> accepted");
        } catch (Exception e) {
            fail("TE:PP.08.02 (ipolset=test-policy-1, explicit=false) should accept but failed: " + e.getMessage());
        }
    }
    
    @Test
    public void testCase49_2() throws Exception {
        // Configuration: ipolset=test-policy-1, explicit=true -> expect accept
        X509Certificate endCert = pkits.loadEndCertificate("test49");
        
        // Configure validator: test-policy-1, explicit=true
        pkits.getValidator().clearInitialPolicySet();
        pkits.getValidator().addInitialPolicy(TEST_POLICY_1);
        pkits.getValidator().setRequreExplicitPolicy(true);
        
        try {
            PKIXCertPathBuilderResult result = pkits.validateCertificate(endCert, true);
            assertNotNull("TE:PP.08.02 (ipolset=test-policy-1, explicit=true) should accept", result);
            System.out.println("TE:PP.08.02 testCase49_2 PASSED: ipolset=test-policy-1, explicit=true -> accepted");
        } catch (Exception e) {
            fail("TE:PP.08.02 (ipolset=test-policy-1, explicit=true) should accept but failed: " + e.getMessage());
        }
    }
    
    @Test
    public void testCase49_3() throws Exception {
        // Configuration: ipolset=set NOT including test-policy-1 or test-policy-2, explicit=false -> expect accept
        X509Certificate endCert = pkits.loadEndCertificate("test49");
        
        // Configure validator: set NOT including test-policy-1 or test-policy-2 (only 3,4,5), explicit=false
        pkits.getValidator().clearInitialPolicySet();
        pkits.getValidator().addInitialPolicy(TEST_POLICY_3);
        pkits.getValidator().addInitialPolicy(TEST_POLICY_4);
        pkits.getValidator().addInitialPolicy(TEST_POLICY_5);
        pkits.getValidator().setRequreExplicitPolicy(false);
        
        try {
            PKIXCertPathBuilderResult result = pkits.validateCertificate(endCert, true);
            assertNotNull("TE:PP.08.02 (ipolset=set-not-including-test-policy-1-or-2, explicit=false) should accept", result);
            System.out.println("TE:PP.08.02 testCase49_3 PASSED: ipolset=set-not-including-test-policy-1-or-2, explicit=false -> accepted");
        } catch (Exception e) {
            fail("TE:PP.08.02 (ipolset=set-not-including-test-policy-1-or-2, explicit=false) should accept but failed: " + e.getMessage());
        }
    }
    
    @Test
    public void testCase49_4() throws Exception {
        // Configuration: ipolset=set NOT including test-policy-1 or test-policy-2, explicit=true -> expect REJECT
        X509Certificate endCert = pkits.loadEndCertificate("test49");
        
        // Configure validator: set NOT including test-policy-1 or test-policy-2 (only 3,4,5), explicit=true
        pkits.getValidator().clearInitialPolicySet();
        pkits.getValidator().addInitialPolicy(TEST_POLICY_3);
        pkits.getValidator().addInitialPolicy(TEST_POLICY_4);
        pkits.getValidator().addInitialPolicy(TEST_POLICY_5);
        pkits.getValidator().setRequreExplicitPolicy(true);
        
        try {
            pkits.validateCertificate(endCert, true);
            fail("TE:PP.08.02 (ipolset=set-not-including-test-policy-1-or-2, explicit=true) should REJECT but succeeded");
        } catch (Exception e) {
            System.out.println("TE:PP.08.02 testCase49_4 PASSED: ipolset=set-not-including-test-policy-1-or-2, explicit=true -> rejected: " + e.getMessage());
        }
    }
    
    @Test
    public void testCase49_5() throws Exception {
        // Configuration: ipolset=any-policy, explicit=false -> expect accept
        X509Certificate endCert = pkits.loadEndCertificate("test49");
        
        // Configure validator: any-policy (RFC 5280 OID 2.5.29.32.0), explicit=false
        pkits.getValidator().clearInitialPolicySet();
        pkits.getValidator().addInitialPolicy(ANY_POLICY);
        pkits.getValidator().setRequreExplicitPolicy(false);
        
        try {
            PKIXCertPathBuilderResult result = pkits.validateCertificate(endCert, true);
            assertNotNull("TE:PP.08.02 (ipolset=any-policy, explicit=false) should accept", result);
            System.out.println("TE:PP.08.02 testCase49_5 PASSED: ipolset=any-policy, explicit=false -> accepted");
        } catch (Exception e) {
            fail("TE:PP.08.02 (ipolset=any-policy, explicit=false) should accept but failed: " + e.getMessage());
        }
    }
    
    @Test
    public void testCase49_6() throws Exception {
        // Configuration: ipolset=any-policy, explicit=true -> expect accept
        X509Certificate endCert = pkits.loadEndCertificate("test49");
        
        // Configure validator: any-policy (RFC 5280 OID 2.5.29.32.0), explicit=true
        pkits.getValidator().clearInitialPolicySet();
        pkits.getValidator().addInitialPolicy(ANY_POLICY);
        pkits.getValidator().setRequreExplicitPolicy(true);
        
        try {
            PKIXCertPathBuilderResult result = pkits.validateCertificate(endCert, true);
            assertNotNull("TE:PP.08.02 (ipolset=any-policy, explicit=true) should accept", result);
            System.out.println("TE:PP.08.02 testCase49_6 PASSED: ipolset=any-policy, explicit=true -> accepted");
        } catch (Exception e) {
            fail("TE:PP.08.02 (ipolset=any-policy, explicit=true) should accept but failed: " + e.getMessage());
        }
    }
    
    /**
     * Test 50: TE:PP.08.03 - Any-Policy Asserted
     * All certificates in the path assert the special value any-policy.
     * Authority-constrained policy set: any-policy
     * 
     * This test requires 6 sub-tests - all accept:
     * 50_1: ipolset=test-policy-1, explicit=false -> accept
     * 50_2: ipolset=test-policy-1, explicit=true  -> accept
     * 50_3: ipolset=test-policy-1 and test-policy-2, explicit=false -> accept
     * 50_4: ipolset=test-policy-1 and test-policy-2, explicit=true  -> accept
     * 50_5: ipolset=any-policy, explicit=false -> accept
     * 50_6: ipolset=any-policy, explicit=true  -> accept
     */
    
    @Test
    public void testCase50_1() throws Exception {
        // Configuration: ipolset=test-policy-1, explicit=false -> expect accept
        X509Certificate endCert = pkits.loadEndCertificate("test50");
        
        // Configure validator: test-policy-1, explicit=false
        pkits.getValidator().clearInitialPolicySet();
        pkits.getValidator().addInitialPolicy(TEST_POLICY_1);
        pkits.getValidator().setRequreExplicitPolicy(false);
        
        try {
            PKIXCertPathBuilderResult result = pkits.validateCertificate(endCert, true);
            assertNotNull("TE:PP.08.03 (ipolset=test-policy-1, explicit=false) should accept", result);
            System.out.println("TE:PP.08.03 testCase50_1 PASSED: ipolset=test-policy-1, explicit=false -> accepted");
        } catch (Exception e) {
            fail("TE:PP.08.03 (ipolset=test-policy-1, explicit=false) should accept but failed: " + e.getMessage());
        }
    }
    
    @Test
    public void testCase50_2() throws Exception {
        // Configuration: ipolset=test-policy-1, explicit=true -> expect accept
        X509Certificate endCert = pkits.loadEndCertificate("test50");
        
        // Configure validator: test-policy-1, explicit=true, inhibitAnyPolicy=false
        // inhibitAnyPolicy must be false to allow anyPolicy to satisfy specific policy requirements
        pkits.getValidator().clearInitialPolicySet();
        pkits.getValidator().addInitialPolicy(TEST_POLICY_1);
        pkits.getValidator().setRequreExplicitPolicy(true);
        pkits.getValidator().setInhibitAnyPolcy(false);
        
        try {
            PKIXCertPathBuilderResult result = pkits.validateCertificate(endCert, true);
            assertNotNull("TE:PP.08.03 (ipolset=test-policy-1, explicit=true) should accept", result);
            System.out.println("TE:PP.08.03 testCase50_2 PASSED: ipolset=test-policy-1, explicit=true -> accepted");
        } catch (Exception e) {
            fail("TE:PP.08.03 (ipolset=test-policy-1, explicit=true) should accept but failed: " + e.getMessage());
        } finally {
            // Reset inhibitAnyPolicy to default
            pkits.getValidator().setInhibitAnyPolcy(DEFAULT_INHIBIT_ANY_POLICY);
        }
    }
    
    @Test
    public void testCase50_3() throws Exception {
        // Configuration: ipolset=test-policy-1 and test-policy-2, explicit=false -> expect accept
        X509Certificate endCert = pkits.loadEndCertificate("test50");
        
        // Configure validator: test-policy-1 and test-policy-2, explicit=false
        pkits.getValidator().clearInitialPolicySet();
        pkits.getValidator().addInitialPolicy(TEST_POLICY_1);
        pkits.getValidator().addInitialPolicy(TEST_POLICY_2);
        pkits.getValidator().setRequreExplicitPolicy(false);
        
        try {
            PKIXCertPathBuilderResult result = pkits.validateCertificate(endCert, true);
            assertNotNull("TE:PP.08.03 (ipolset=test-policy-1-and-2, explicit=false) should accept", result);
            System.out.println("TE:PP.08.03 testCase50_3 PASSED: ipolset=test-policy-1-and-2, explicit=false -> accepted");
        } catch (Exception e) {
            fail("TE:PP.08.03 (ipolset=test-policy-1-and-2, explicit=false) should accept but failed: " + e.getMessage());
        }
    }
    
    @Test
    public void testCase50_4() throws Exception {
        // Configuration: ipolset=test-policy-1 and test-policy-2, explicit=true -> expect accept
        X509Certificate endCert = pkits.loadEndCertificate("test50");
        
        // Configure validator: test-policy-1 and test-policy-2, explicit=true, inhibitAnyPolicy=false
        // inhibitAnyPolicy must be false to allow anyPolicy to satisfy specific policy requirements
        pkits.getValidator().clearInitialPolicySet();
        pkits.getValidator().addInitialPolicy(TEST_POLICY_1);
        pkits.getValidator().addInitialPolicy(TEST_POLICY_2);
        pkits.getValidator().setRequreExplicitPolicy(true);
        pkits.getValidator().setInhibitAnyPolcy(false);
        
        try {
            PKIXCertPathBuilderResult result = pkits.validateCertificate(endCert, true);
            assertNotNull("TE:PP.08.03 (ipolset=test-policy-1-and-2, explicit=true) should accept", result);
            System.out.println("TE:PP.08.03 testCase50_4 PASSED: ipolset=test-policy-1-and-2, explicit=true -> accepted");
        } catch (Exception e) {
            fail("TE:PP.08.03 (ipolset=test-policy-1-and-2, explicit=true) should accept but failed: " + e.getMessage());
        } finally {
            // Reset inhibitAnyPolicy to default
            pkits.getValidator().setInhibitAnyPolcy(DEFAULT_INHIBIT_ANY_POLICY);
        }
    }
    
    @Test
    public void testCase50_5() throws Exception {
        // Configuration: ipolset=any-policy, explicit=false -> expect accept
        X509Certificate endCert = pkits.loadEndCertificate("test50");
        
        // Configure validator: any-policy (RFC 5280 OID 2.5.29.32.0), explicit=false
        pkits.getValidator().clearInitialPolicySet();
        pkits.getValidator().addInitialPolicy(ANY_POLICY);
        pkits.getValidator().setRequreExplicitPolicy(false);
        
        try {
            PKIXCertPathBuilderResult result = pkits.validateCertificate(endCert, true);
            assertNotNull("TE:PP.08.03 (ipolset=any-policy, explicit=false) should accept", result);
            System.out.println("TE:PP.08.03 testCase50_5 PASSED: ipolset=any-policy, explicit=false -> accepted");
        } catch (Exception e) {
            fail("TE:PP.08.03 (ipolset=any-policy, explicit=false) should accept but failed: " + e.getMessage());
        }
    }
    
    @Test
    public void testCase50_6() throws Exception {
        // Configuration: ipolset=any-policy, explicit=true -> expect accept
        X509Certificate endCert = pkits.loadEndCertificate("test50");
        
        // Configure validator: any-policy (RFC 5280 OID 2.5.29.32.0), explicit=true, inhibitAnyPolicy=false
        // inhibitAnyPolicy must be false to allow anyPolicy to satisfy policy requirements
        pkits.getValidator().clearInitialPolicySet();
        pkits.getValidator().addInitialPolicy(ANY_POLICY);
        pkits.getValidator().setRequreExplicitPolicy(true);
        pkits.getValidator().setInhibitAnyPolcy(false);
        
        try {
            PKIXCertPathBuilderResult result = pkits.validateCertificate(endCert, true);
            assertNotNull("TE:PP.08.03 (ipolset=any-policy, explicit=true) should accept", result);
            System.out.println("TE:PP.08.03 testCase50_6 PASSED: ipolset=any-policy, explicit=true -> accepted");
        } catch (Exception e) {
            fail("TE:PP.08.03 (ipolset=any-policy, explicit=true) should accept but failed: " + e.getMessage());
        } finally {
            // Reset inhibitAnyPolicy to default
            pkits.getValidator().setInhibitAnyPolcy(DEFAULT_INHIBIT_ANY_POLICY);
        }
    }
    
    /**
     * Test 51: TE:PP.08.04 - Non-Contiguous Policies
     * The certificates in the path do not assert a contiguous set of policies.
     * Authority-constrained policy set: <empty>
     * User-constrained policy set: <empty>
     * 
     * This test requires 2 sub-tests:
     * 51_1: explicit=false -> accept
     * 51_2: explicit=true  -> REJECT
     */
    
    @Test
    public void testCase51_1() throws Exception {
        // Configuration: explicit=false -> expect accept
        X509Certificate endCert = pkits.loadEndCertificate("test51");
        
        // Configure validator: explicit=false
        pkits.getValidator().clearInitialPolicySet();
        pkits.getValidator().setRequreExplicitPolicy(false);
        
        try {
            PKIXCertPathBuilderResult result = pkits.validateCertificate(endCert, true);
            assertNotNull("TE:PP.08.04 (explicit=false) should accept", result);
            System.out.println("TE:PP.08.04 testCase51_1 PASSED: explicit=false -> accepted");
        } catch (Exception e) {
            fail("TE:PP.08.04 (explicit=false) should accept but failed: " + e.getMessage());
        }
    }
    
    @Test
    public void testCase51_2() throws Exception {
        // Configuration: explicit=true -> expect REJECT
        X509Certificate endCert = pkits.loadEndCertificate("test51");
        
        // Configure validator: explicit=true
        pkits.getValidator().clearInitialPolicySet();
        pkits.getValidator().setRequreExplicitPolicy(true);
        
        try {
            pkits.validateCertificate(endCert, true);
            fail("TE:PP.08.04 (explicit=true) should REJECT but succeeded");
        } catch (Exception e) {
            System.out.println("TE:PP.08.04 testCase51_2 PASSED: explicit=true -> rejected: " + e.getMessage());
        }
    }
    
    /**
     * Test 52: TE:PP.08.05 - User Policy Not in Cert
     * The certificates assert test-policy-3, but user-constrained set does not contain that policy.
     * Authority-constrained policy set: test-policy-3
     * 
     * This test requires 6 sub-tests:
     * 52_1: ipolset=test-policy-1, explicit=false -> accept
     * 52_2: ipolset=test-policy-1, explicit=true  -> REJECT
     * 52_3: ipolset=test-policy-1 and test-policy-2, explicit=false -> accept
     * 52_4: ipolset=test-policy-1 and test-policy-2, explicit=true  -> REJECT
     * 52_5: ipolset=any-policy, explicit=false -> accept
     * 52_6: ipolset=any-policy, explicit=true  -> accept
     */
    
    @Test
    public void testCase52_1() throws Exception {
        // Configuration: ipolset=test-policy-1, explicit=false -> expect accept
        X509Certificate endCert = pkits.loadEndCertificate("test52");
        
        // Configure validator: test-policy-1, explicit=false
        pkits.getValidator().clearInitialPolicySet();
        pkits.getValidator().addInitialPolicy(TEST_POLICY_1);
        pkits.getValidator().setRequreExplicitPolicy(false);
        
        try {
            PKIXCertPathBuilderResult result = pkits.validateCertificate(endCert, true);
            assertNotNull("TE:PP.08.05 (ipolset=test-policy-1, explicit=false) should accept", result);
            System.out.println("TE:PP.08.05 testCase52_1 PASSED: ipolset=test-policy-1, explicit=false -> accepted");
        } catch (Exception e) {
            fail("TE:PP.08.05 (ipolset=test-policy-1, explicit=false) should accept but failed: " + e.getMessage());
        }
    }
    
    @Test
    public void testCase52_2() throws Exception {
        // Configuration: ipolset=test-policy-1, explicit=true -> expect REJECT
        X509Certificate endCert = pkits.loadEndCertificate("test52");
        
        // Configure validator: test-policy-1, explicit=true
        pkits.getValidator().clearInitialPolicySet();
        pkits.getValidator().addInitialPolicy(TEST_POLICY_1);
        pkits.getValidator().setRequreExplicitPolicy(true);
        
        try {
            pkits.validateCertificate(endCert, true);
            fail("TE:PP.08.05 (ipolset=test-policy-1, explicit=true) should REJECT but succeeded");
        } catch (Exception e) {
            System.out.println("TE:PP.08.05 testCase52_2 PASSED: ipolset=test-policy-1, explicit=true -> rejected: " + e.getMessage());
        }
    }
    
    @Test
    public void testCase52_3() throws Exception {
        // Configuration: ipolset=test-policy-1 and test-policy-2, explicit=false -> expect accept
        X509Certificate endCert = pkits.loadEndCertificate("test52");
        
        // Configure validator: test-policy-1 and test-policy-2, explicit=false
        pkits.getValidator().clearInitialPolicySet();
        pkits.getValidator().addInitialPolicy(TEST_POLICY_1);
        pkits.getValidator().addInitialPolicy(TEST_POLICY_2);
        pkits.getValidator().setRequreExplicitPolicy(false);
        
        try {
            PKIXCertPathBuilderResult result = pkits.validateCertificate(endCert, true);
            assertNotNull("TE:PP.08.05 (ipolset=test-policy-1-and-2, explicit=false) should accept", result);
            System.out.println("TE:PP.08.05 testCase52_3 PASSED: ipolset=test-policy-1-and-2, explicit=false -> accepted");
        } catch (Exception e) {
            fail("TE:PP.08.05 (ipolset=test-policy-1-and-2, explicit=false) should accept but failed: " + e.getMessage());
        }
    }
    
    @Test
    public void testCase52_4() throws Exception {
        // Configuration: ipolset=test-policy-1 and test-policy-2, explicit=true -> expect REJECT
        X509Certificate endCert = pkits.loadEndCertificate("test52");
        
        // Configure validator: test-policy-1 and test-policy-2, explicit=true
        pkits.getValidator().clearInitialPolicySet();
        pkits.getValidator().addInitialPolicy(TEST_POLICY_1);
        pkits.getValidator().addInitialPolicy(TEST_POLICY_2);
        pkits.getValidator().setRequreExplicitPolicy(true);
        
        try {
            pkits.validateCertificate(endCert, true);
            fail("TE:PP.08.05 (ipolset=test-policy-1-and-2, explicit=true) should REJECT but succeeded");
        } catch (Exception e) {
            System.out.println("TE:PP.08.05 testCase52_4 PASSED: ipolset=test-policy-1-and-2, explicit=true -> rejected: " + e.getMessage());
        }
    }
    
    @Test
    public void testCase52_5() throws Exception {
        // Configuration: ipolset=any-policy, explicit=false -> expect accept
        X509Certificate endCert = pkits.loadEndCertificate("test52");
        
        // Configure validator: any-policy (RFC 5280 OID 2.5.29.32.0), explicit=false
        pkits.getValidator().clearInitialPolicySet();
        pkits.getValidator().addInitialPolicy(ANY_POLICY);
        pkits.getValidator().setRequreExplicitPolicy(false);
        
        try {
            PKIXCertPathBuilderResult result = pkits.validateCertificate(endCert, true);
            assertNotNull("TE:PP.08.05 (ipolset=any-policy, explicit=false) should accept", result);
            System.out.println("TE:PP.08.05 testCase52_5 PASSED: ipolset=any-policy, explicit=false -> accepted");
        } catch (Exception e) {
            fail("TE:PP.08.05 (ipolset=any-policy, explicit=false) should accept but failed: " + e.getMessage());
        }
    }
    
    @Test
    public void testCase52_6() throws Exception {
        // Configuration: ipolset=any-policy, explicit=true -> expect accept
        X509Certificate endCert = pkits.loadEndCertificate("test52");
        
        // Configure validator: any-policy (RFC 5280 OID 2.5.29.32.0), explicit=true
        pkits.getValidator().clearInitialPolicySet();
        pkits.getValidator().addInitialPolicy(ANY_POLICY);
        pkits.getValidator().setRequreExplicitPolicy(true);
        
        try {
            PKIXCertPathBuilderResult result = pkits.validateCertificate(endCert, true);
            assertNotNull("TE:PP.08.05 (ipolset=any-policy, explicit=true) should accept", result);
            System.out.println("TE:PP.08.05 testCase52_6 PASSED: ipolset=any-policy, explicit=true -> accepted");
        } catch (Exception e) {
            fail("TE:PP.08.05 (ipolset=any-policy, explicit=true) should accept but failed: " + e.getMessage());
        }
    }
    
    /**
     * Test 53: TE:PP.08.06 - Three Policies Asserted
     * The certificates in the path assert three policies (test-policy-1, test-policy-2, test-policy-3).
     * Authority-constrained policy set: test-policy-1, test-policy-2, test-policy-3
     * 
     * This test requires 8 sub-tests:
     * 53_1: ipolset=test-policy-1, explicit=false -> accept
     * 53_2: ipolset=test-policy-1, explicit=true  -> accept
     * 53_3: ipolset=test-policy-1 and test-policy-2, explicit=false -> accept
     * 53_4: ipolset=test-policy-1 and test-policy-2, explicit=true  -> accept
     * 53_5: ipolset=set NOT including test-policy-1,2,3, explicit=false -> accept
     * 53_6: ipolset=set NOT including test-policy-1,2,3, explicit=true  -> REJECT
     * 53_7: ipolset=any-policy, explicit=false -> accept
     * 53_8: ipolset=any-policy, explicit=true  -> accept
     */
    
    @Test
    public void testCase53_1() throws Exception {
        // Configuration: ipolset=test-policy-1, explicit=false -> expect accept
        X509Certificate endCert = pkits.loadEndCertificate("test53");
        
        // Configure validator: test-policy-1, explicit=false
        pkits.getValidator().clearInitialPolicySet();
        pkits.getValidator().addInitialPolicy(TEST_POLICY_1);
        pkits.getValidator().setRequreExplicitPolicy(false);
        
        try {
            PKIXCertPathBuilderResult result = pkits.validateCertificate(endCert, true);
            assertNotNull("TE:PP.08.06 (ipolset=test-policy-1, explicit=false) should accept", result);
            System.out.println("TE:PP.08.06 testCase53_1 PASSED: ipolset=test-policy-1, explicit=false -> accepted");
        } catch (Exception e) {
            fail("TE:PP.08.06 (ipolset=test-policy-1, explicit=false) should accept but failed: " + e.getMessage());
        }
    }
    
    @Test
    public void testCase53_2() throws Exception {
        // Configuration: ipolset=test-policy-1, explicit=true -> expect accept
        X509Certificate endCert = pkits.loadEndCertificate("test53");
        
        // Configure validator: test-policy-1, explicit=true
        pkits.getValidator().clearInitialPolicySet();
        pkits.getValidator().addInitialPolicy(TEST_POLICY_1);
        pkits.getValidator().setRequreExplicitPolicy(true);
        
        try {
            PKIXCertPathBuilderResult result = pkits.validateCertificate(endCert, true);
            assertNotNull("TE:PP.08.06 (ipolset=test-policy-1, explicit=true) should accept", result);
            System.out.println("TE:PP.08.06 testCase53_2 PASSED: ipolset=test-policy-1, explicit=true -> accepted");
        } catch (Exception e) {
            fail("TE:PP.08.06 (ipolset=test-policy-1, explicit=true) should accept but failed: " + e.getMessage());
        }
    }
    
    @Test
    public void testCase53_3() throws Exception {
        // Configuration: ipolset=test-policy-1 and test-policy-2, explicit=false -> expect accept
        X509Certificate endCert = pkits.loadEndCertificate("test53");
        
        // Configure validator: test-policy-1 and test-policy-2, explicit=false
        pkits.getValidator().clearInitialPolicySet();
        pkits.getValidator().addInitialPolicy(TEST_POLICY_1);
        pkits.getValidator().addInitialPolicy(TEST_POLICY_2);
        pkits.getValidator().setRequreExplicitPolicy(false);
        
        try {
            PKIXCertPathBuilderResult result = pkits.validateCertificate(endCert, true);
            assertNotNull("TE:PP.08.06 (ipolset=test-policy-1-and-2, explicit=false) should accept", result);
            System.out.println("TE:PP.08.06 testCase53_3 PASSED: ipolset=test-policy-1-and-2, explicit=false -> accepted");
        } catch (Exception e) {
            fail("TE:PP.08.06 (ipolset=test-policy-1-and-2, explicit=false) should accept but failed: " + e.getMessage());
        }
    }
    
    @Test
    public void testCase53_4() throws Exception {
        // Configuration: ipolset=test-policy-1 and test-policy-2, explicit=true -> expect accept
        X509Certificate endCert = pkits.loadEndCertificate("test53");
        
        // Configure validator: test-policy-1 and test-policy-2, explicit=true
        pkits.getValidator().clearInitialPolicySet();
        pkits.getValidator().addInitialPolicy(TEST_POLICY_1);
        pkits.getValidator().addInitialPolicy(TEST_POLICY_2);
        pkits.getValidator().setRequreExplicitPolicy(true);
        
        try {
            PKIXCertPathBuilderResult result = pkits.validateCertificate(endCert, true);
            assertNotNull("TE:PP.08.06 (ipolset=test-policy-1-and-2, explicit=true) should accept", result);
            System.out.println("TE:PP.08.06 testCase53_4 PASSED: ipolset=test-policy-1-and-2, explicit=true -> accepted");
        } catch (Exception e) {
            fail("TE:PP.08.06 (ipolset=test-policy-1-and-2, explicit=true) should accept but failed: " + e.getMessage());
        }
    }
    
    @Test
    public void testCase53_5() throws Exception {
        // Configuration: ipolset=set NOT including test-policy-1,2,3, explicit=false -> expect accept
        X509Certificate endCert = pkits.loadEndCertificate("test53");
        
        // Configure validator: set NOT including test-policy-1,2,3 (only 4,5), explicit=false
        pkits.getValidator().clearInitialPolicySet();
        pkits.getValidator().addInitialPolicy(TEST_POLICY_4);
        pkits.getValidator().addInitialPolicy(TEST_POLICY_5);
        pkits.getValidator().setRequreExplicitPolicy(false);
        
        try {
            PKIXCertPathBuilderResult result = pkits.validateCertificate(endCert, true);
            assertNotNull("TE:PP.08.06 (ipolset=set-not-including-1-2-3, explicit=false) should accept", result);
            System.out.println("TE:PP.08.06 testCase53_5 PASSED: ipolset=set-not-including-1-2-3, explicit=false -> accepted");
        } catch (Exception e) {
            fail("TE:PP.08.06 (ipolset=set-not-including-1-2-3, explicit=false) should accept but failed: " + e.getMessage());
        }
    }
    
    @Test
    public void testCase53_6() throws Exception {
        // Configuration: ipolset=set NOT including test-policy-1,2,3, explicit=true -> expect REJECT
        X509Certificate endCert = pkits.loadEndCertificate("test53");
        
        // Configure validator: set NOT including test-policy-1,2,3 (only 4,5), explicit=true
        pkits.getValidator().clearInitialPolicySet();
        pkits.getValidator().addInitialPolicy(TEST_POLICY_4);
        pkits.getValidator().addInitialPolicy(TEST_POLICY_5);
        pkits.getValidator().setRequreExplicitPolicy(true);
        
        try {
            pkits.validateCertificate(endCert, true);
            fail("TE:PP.08.06 (ipolset=set-not-including-1-2-3, explicit=true) should REJECT but succeeded");
        } catch (Exception e) {
            System.out.println("TE:PP.08.06 testCase53_6 PASSED: ipolset=set-not-including-1-2-3, explicit=true -> rejected: " + e.getMessage());
        }
    }
    
    @Test
    public void testCase53_7() throws Exception {
        // Configuration: ipolset=any-policy, explicit=false -> expect accept
        X509Certificate endCert = pkits.loadEndCertificate("test53");
        
        // Configure validator: any-policy (RFC 5280 OID 2.5.29.32.0), explicit=false
        pkits.getValidator().clearInitialPolicySet();
        pkits.getValidator().addInitialPolicy(ANY_POLICY);
        pkits.getValidator().setRequreExplicitPolicy(false);
        
        try {
            PKIXCertPathBuilderResult result = pkits.validateCertificate(endCert, true);
            assertNotNull("TE:PP.08.06 (ipolset=any-policy, explicit=false) should accept", result);
            System.out.println("TE:PP.08.06 testCase53_7 PASSED: ipolset=any-policy, explicit=false -> accepted");
        } catch (Exception e) {
            fail("TE:PP.08.06 (ipolset=any-policy, explicit=false) should accept but failed: " + e.getMessage());
        }
    }
    
    @Test
    public void testCase53_8() throws Exception {
        // Configuration: ipolset=any-policy, explicit=true -> expect accept
        X509Certificate endCert = pkits.loadEndCertificate("test53");
        
        // Configure validator: any-policy (RFC 5280 OID 2.5.29.32.0), explicit=true
        pkits.getValidator().clearInitialPolicySet();
        pkits.getValidator().addInitialPolicy(ANY_POLICY);
        pkits.getValidator().setRequreExplicitPolicy(true);
        
        try {
            PKIXCertPathBuilderResult result = pkits.validateCertificate(endCert, true);
            assertNotNull("TE:PP.08.06 (ipolset=any-policy, explicit=true) should accept", result);
            System.out.println("TE:PP.08.06 testCase53_8 PASSED: ipolset=any-policy, explicit=true -> accepted");
        } catch (Exception e) {
            fail("TE:PP.08.06 (ipolset=any-policy, explicit=true) should accept but failed: " + e.getMessage());
        }
    }
    
    // ==================== Section 3.4: Path Length Related Tests (PL) ====================
    
    /**
     * Test 54: TE:PL.01.01 - pathLenConstraint=0 Violated (EE not CA)
     * First certificate has pathLenConstraint=0, but there is one additional intermediate.
     */
    @Test
    public void testCase54() throws Exception {
        expectInvalidPath("test54", "TE:PL.01.01 pathLenConstraint=0 Violated");
    }
    
    /**
     * Test 55: TE:PL.01.02 - pathLenConstraint=0 Violated (EE is CA)
     * First certificate has pathLenConstraint=0, one additional intermediate, end cert is CA.
     */
    @Test
    public void testCase55() throws Exception {
        expectInvalidPath("test55", "TE:PL.01.02 pathLenConstraint=0 Violated CA");
    }
    
    /**
     * Test 56: TE:PL.01.03 - pathLenConstraint=0 Valid (EE not CA)
     * First certificate has pathLenConstraint=0, no additional intermediates.
     */
    @Test
    public void testCase56() throws Exception {
        expectValidPath("test56", "TE:PL.01.03 pathLenConstraint=0 Valid");
    }
    
    /**
     * Test 57: TE:PL.01.04 - pathLenConstraint=0 Valid (EE is CA)
     * First certificate has pathLenConstraint=0, no additional intermediates, end cert is CA.
     */
    @Test
    public void testCase57() throws Exception {
        expectValidPath("test57", "TE:PL.01.04 pathLenConstraint=0 Valid CA");
    }
    
    /**
     * Test 58: TE:PL.01.05 - Multiple pathLenConstraint Violated
     * Path length 4, first cert has pathLenConstraint=6, second and third have pathLenConstraint=0.
     */
    @Test
    public void testCase58() throws Exception {
        expectInvalidPath("test58", "TE:PL.01.05 Multiple pathLenConstraint Violated");
    }
    
    /**
     * Test 59: TE:PL.01.06 - Multiple pathLenConstraint Violated (EE is CA)
     * Same as test 58 but end cert is CA.
     */
    @Test
    public void testCase59() throws Exception {
        expectInvalidPath("test59", "TE:PL.01.06 Multiple pathLenConstraint Violated CA");
    }
    
    /**
     * Test 60: TE:PL.01.07 - Multiple pathLenConstraint Violated 2
     * Path length 5, multiple pathLenConstraint values.
     */
    @Test
    public void testCase60() throws Exception {
        expectInvalidPath("test60", "TE:PL.01.07 Multiple pathLenConstraint Violated 2");
    }
    
    /**
     * Test 61: TE:PL.01.08 - Multiple pathLenConstraint Violated 2 (EE is CA)
     * Same as test 60 but end cert is CA.
     */
    @Test
    public void testCase61() throws Exception {
        expectInvalidPath("test61", "TE:PL.01.08 Multiple pathLenConstraint Violated 2 CA");
    }
    
    /**
     * Test 62: TE:PL.01.09 - Multiple pathLenConstraint Valid
     * Path length 5, pathLenConstraint values allow the path.
     */
    @Test
    public void testCase62() throws Exception {
        expectValidPath("test62", "TE:PL.01.09 Multiple pathLenConstraint Valid");
    }
    
    /**
     * Test 63: TE:PL.01.10 - Multiple pathLenConstraint Valid (EE is CA)
     * Same as test 62 but end cert is CA.
     */
    @Test
    public void testCase63() throws Exception {
        expectValidPath("test63", "TE:PL.01.10 Multiple pathLenConstraint Valid CA");
    }
    
    // ==================== Section 4.1: CRL Related Tests (RL) ====================
    
    /**
     * Test 64: TE:RL.02.01 - Invalid CRL Signature
     * The path has a CRL containing an invalid signature.
     */
    @Test
    public void testCase64() throws Exception {
        expectInvalidPath("test64", "TE:RL.02.01 Invalid CRL Signature");
    }
    
    /**
     * Test 65: TE:RL.03.01 - Wrong CRL Issuer
     * The path contains a CRL from the wrong issuer.
     */
    @Test
    public void testCase65() throws Exception {
        expectInvalidPath("test65", "TE:RL.03.01 Wrong CRL Issuer");
    }
    
    /**
     * Test 66: TE:RL.03.02 - Wrong CRL Issuer with Serial
     * The path contains a CRL with wrong issuer that has the end cert serial on it.
     */
    @Test
    public void testCase66() throws Exception {
        expectInvalidPath("test66", "TE:RL.03.02 Wrong CRL Issuer with Serial");
    }
    
    /**
     * Test 67: TE:RL.03.03 - Two CRLs One Wrong Issuer
     * The path contains two CRLs, one with wrong issuer and one correct.
     */
    @Test
    public void testCase67() throws Exception {
        expectValidPath("test67", "TE:RL.03.03 Two CRLs One Wrong Issuer");
    }
    
    /**
     * Test 68: TE:RL.05.01 - Revoked with Critical crlEntryExtension
     * The intermediate certificate is revoked with a critical crlEntryExtension.
     */
    @Test
    public void testCase68() throws Exception {
        expectInvalidPath("test68", "TE:RL.05.01 Revoked with Critical crlEntryExtension");
    }
    
    /**
     * Test 69: TE:RL.05.02 - Revoked EE with Critical crlEntryExtension
     * The end certificate is revoked with a critical crlEntryExtension.
     */
    @Test
    public void testCase69() throws Exception {
        expectInvalidPath("test69", "TE:RL.05.02 Revoked EE with Critical crlEntryExtension");
    }
    
    /**
     * Test 70: TE:RL.06.01 - Revoked with Critical crlExtension
     * The intermediate certificate is revoked with a critical crlExtension.
     */
    @Test
    public void testCase70() throws Exception {
        expectInvalidPath("test70", "TE:RL.06.01 Revoked with Critical crlExtension");
    }
    
    /**
     * Test 71: TE:RL.06.02 - Revoked EE with Critical crlExtension
     * The end certificate is revoked with a critical crlExtension.
     */
    @Test
    public void testCase71() throws Exception {
        expectInvalidPath("test71", "TE:RL.06.02 Revoked EE with Critical crlExtension");
    }
    
    /**
     * Test 72: TE:RL.07.01 - CRL nextUpdate Expired
     * The path contains a CRL with nextUpdate earlier than current date.
     */
    @Test
    public void testCase72() throws Exception {
        expectInvalidPath("test72", "TE:RL.07.01 CRL nextUpdate Expired");
    }
    
    /**
     * Test 73: TE:RL.07.02 - CRL nextUpdate UTC 50
     * The path contains a CRL with nextUpdate in UTC time with year 50 (should treat as 1950).
     */
    @Test
    public void testCase73() throws Exception {
        expectInvalidPath("test73", "TE:RL.07.02 CRL nextUpdate UTC 50");
    }
    
    /**
     * Test 74: TE:RL.07.03 - CRL nextUpdate Generalized 2050
     * The path contains a CRL with nextUpdate as Generalized time of 2050.
     */
    @Test
    public void testCase74() throws Exception {
        expectValidPath("test74", "TE:RL.07.03 CRL nextUpdate Generalized 2050");
    }
    
    /**
     * Test 75: TE:RL.08.01 - Delta CRL Indicator
     * The path contains a CRL with deltaCRLIndicator critical, no base CRL.
     */
    @Test
    public void testCase75() throws Exception {
        expectInvalidPath("test75", "TE:RL.08.01 Delta CRL Indicator");
    }
    
    /**
     * Test 76: TE:RL.09.01 - Issuing Distribution Point
     * The path contains a CRL with IDP critical stating only CA certs.
     */
    @Test
    public void testCase76() throws Exception {
        expectInvalidPath("test76", "TE:RL.09.01 Issuing Distribution Point");
    }
}
