package org.keysupport.pki.validation.test;

import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.security.KeyStore;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;

/**
 * Utility class to create a JKS truststore with the PKITS trust anchor
 */
public class CreateTruststore {

    public static void main(String[] args) {
        try {
            // Path to the certificate
            String certPath = "C:/Users/neumankyle/OneDrive - U.S. Department of the Treasury/Coding/PKIValStore/resources/PKITS/X509tests/test1/Trust Anchor CP.01.01.crt";
            
            // Path to the truststore to create
            String truststorePath = "C:/Users/neumankyle/OneDrive - U.S. Department of the Treasury/Coding/PKIValStore/resources/PKITS/truststore/pkits.jks";
            
            // Truststore password
            String password = "changeit";
            
            // Load the certificate
            FileInputStream certFis = new FileInputStream(certPath);
            CertificateFactory cf = CertificateFactory.getInstance("X.509");
            X509Certificate cert = (X509Certificate) cf.generateCertificate(certFis);
            certFis.close();
            
            System.out.println("Certificate loaded: " + cert.getSubjectX500Principal().getName());
            
            // Create a new JKS keystore
            KeyStore keyStore = KeyStore.getInstance("JKS");
            keyStore.load(null, password.toCharArray());
            
            // Add the certificate to the keystore
            keyStore.setCertificateEntry("trustanchor", cert);
            
            // Save the keystore to a file
            FileOutputStream fos = new FileOutputStream(truststorePath);
            keyStore.store(fos, password.toCharArray());
            fos.close();
            
            System.out.println("Truststore created successfully at: " + truststorePath);
            
        } catch (Exception e) {
            e.printStackTrace();
        }
    }
}
