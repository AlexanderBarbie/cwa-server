/*
 * Corona-Warn-App
 *
 * SAP SE and all other contributors /
 * copyright owners license this file to you under the Apache
 * License, Version 2.0 (the "License"); you may not use this
 * file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing,
 * software distributed under the License is distributed on an
 * "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 * KIND, either express or implied.  See the License for the
 * specific language governing permissions and limitations
 * under the License.
 */

package app.coronawarn.server.services.distribution.assembly.component;

import app.coronawarn.server.services.distribution.config.DistributionServiceConfig;
import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.io.UncheckedIOException;
import java.nio.file.Files;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Security;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.openssl.PEMKeyPair;
import org.bouncycastle.openssl.PEMParser;
import org.bouncycastle.openssl.jcajce.JcaPEMKeyConverter;
import org.springframework.core.io.Resource;
import org.springframework.core.io.ResourceLoader;
import org.springframework.stereotype.Component;

/**
 * Wrapper component for a {@link CryptoProvider#getPrivateKey() private key} and a {@link CryptoProvider#getPublicKey()
 * public key} from the application properties.
 */
@Component
public class CryptoProvider {

  private final String privateKeyPath;

  private final String publicKeyPath;

  private final ResourceLoader resourceLoader;

  private PrivateKey privateKey;
  private PublicKey publicKey;

  /**
   * Creates a CryptoProvider, using {@link BouncyCastleProvider}.
   */
  CryptoProvider(ResourceLoader resourceLoader, DistributionServiceConfig distributionServiceConfig) {
    this.resourceLoader = resourceLoader;
    this.privateKeyPath = distributionServiceConfig.getPaths().getPrivateKey();
    this.publicKeyPath = distributionServiceConfig.getPaths().getPublicKey();
    Security.addProvider(new BouncyCastleProvider());
  }

  /**
   * Reads and returns the {@link PrivateKey} configured in the application properties.
   */
  public PrivateKey getPrivateKey() {
    if (privateKey == null) {
      Resource privateKeyResource = resourceLoader.getResource(privateKeyPath);
      try (InputStream privateKeyStream = privateKeyResource.getInputStream()) {
      byte[] keyBytes = Files.readAllBytes(Paths.get(filename));

      PKCS8EncodedKeySpec spec = new PKCS8EncodedKeySpec(keyBytes);
      KeyFactory kf = KeyFactory.getInstance("RSA");
      return kf.generatePrivate(spec);
    }
    return privateKey;
  }

  /**
   * Reads and returns the {@link PublicKey} configured in the application properties.
   */
  public PublicKey getPublicKey() {
    if (publicKey == null) {
      Resource publicKeyResource = resourceLoader.getResource(publicKeyPath);
      try (InputStream publicKeyStream = publicKeyResource.getInputStream()) {
        InputStreamReader publicKeyStreamReader = new InputStreamReader(publicKeyStream);
        Object parsed = new PEMParser(publicKeyStreamReader).readObject();
        SubjectPublicKeyInfo subjectPublicKeyInfo = (SubjectPublicKeyInfo) parsed;
        X509EncodedKeySpec xspec = new X509EncodedKeySpec(subjectPublicKeyInfo.getEncoded());
        AlgorithmIdentifier keyAlg = subjectPublicKeyInfo.getAlgorithm();

        KeyFactory.getInstance(subjectPublicKeyInfo.getAlgorithm().toString(), "BC");

        // publicKey = ((SubjectPublicKeyInfo) parsed).parsePublicKey().;
      } catch (IOException e) {
        throw new UncheckedIOException("Failed to load private key from " + privateKeyPath, e);
      } catch (NoSuchAlgorithmException e) {
        e.printStackTrace();
      } catch (NoSuchProviderException e) {
        e.printStackTrace();
      }
    }
    return publicKey;
  }
}
