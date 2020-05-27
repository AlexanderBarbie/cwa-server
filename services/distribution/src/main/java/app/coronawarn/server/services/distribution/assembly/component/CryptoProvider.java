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
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Security;
import java.security.interfaces.ECPublicKey;
import java.security.spec.ECPoint;
import java.security.spec.ECPublicKeySpec;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import org.bouncycastle.jce.ECNamedCurveTable;
import org.bouncycastle.jce.ECPointUtil;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.jce.spec.ECNamedCurveParameterSpec;
import org.bouncycastle.jce.spec.ECNamedCurveSpec;
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

  private final PrivateKey privateKey;
  private final PublicKey publicKey;

  /**
   * Creates a CryptoProvider.
   */
  CryptoProvider(ResourceLoader resourceLoader, DistributionServiceConfig distributionServiceConfig) {
    privateKey = loadPrivateKey(resourceLoader, distributionServiceConfig);
    publicKey = loadPublicKey(resourceLoader, distributionServiceConfig);
  }

  private static PrivateKey getPrivateKeyFromStream(InputStream privateKeyStream) throws IOException {
    InputStreamReader privateKeyStreamReader = new InputStreamReader(privateKeyStream);
    Object parsed = new PEMParser(privateKeyStreamReader).readObject();
    KeyPair pair = new JcaPEMKeyConverter().getKeyPair((PEMKeyPair) parsed);
    return pair.getPrivate();
  }

  private static PublicKey getPublicKeyFromStream(InputStream certificateStream)
      throws IOException, NoSuchAlgorithmException, InvalidKeySpecException, NoSuchProviderException {
    return getPublicKeyFromBytes(certificateStream.readAllBytes());
  }

  private static PublicKey getPublicKeyFromBytes(byte[] bytes)
      throws NoSuchAlgorithmException, InvalidKeySpecException {
    /*
    ECNamedCurveParameterSpec spec = ECNamedCurveTable.getParameterSpec("prime256v1");
    KeyFactory kf = KeyFactory.getInstance("ECDSA", new BouncyCastleProvider());
    ECNamedCurveSpec params = new ECNamedCurveSpec("prime256v1", spec.getCurve(), spec.getG(), spec.getN());
    ECPoint point =  ECPointUtil.decodePoint(params.getCurve(), bytes);
    ECPublicKeySpec pubKeySpec = new ECPublicKeySpec(point, params);
    return kf.generatePublic(pubKeySpec);
    */

    KeyFactory kf = KeyFactory.getInstance("ECDSA", new BouncyCastleProvider());
    InputStream certificateByteStream = new ByteArrayInputStream(bytes);
    return kf.generatePublic(certificateByteStream);
  }

  /**
   * Returns the {@link PrivateKey} configured in the application properties.
   */
  public PrivateKey getPrivateKey() {
    return privateKey;
  }

  private PrivateKey loadPrivateKey(ResourceLoader resourceLoader,
      DistributionServiceConfig distributionServiceConfig) {
    String path = distributionServiceConfig.getPaths().getPrivateKey();
    Resource privateKeyResource = resourceLoader.getResource(path);
    try (InputStream privateKeyStream = privateKeyResource.getInputStream()) {
      return getPrivateKeyFromStream(privateKeyStream);
    } catch (IOException e) {
      throw new UncheckedIOException("Failed to load private key from " + path, e);
    }
  }

  /**
   * Returns the {@link PublicKey} configured in the application properties.
   */
  public PublicKey getPublicKey() {
    return publicKey;
  }

  private PublicKey loadPublicKey(ResourceLoader resourceLoader, DistributionServiceConfig distributionServiceConfig) {
    String path = distributionServiceConfig.getPaths().getPublicKey();
    Resource publicKeyResource = resourceLoader.getResource(path);

    try (InputStream privateKeyStream = publicKeyResource.getInputStream()) {
      return getPublicKeyFromStream(privateKeyStream);
    } catch (Exception e) {
      throw new RuntimeException("Failed to load private key from " + path, e);
    }
  }
}
