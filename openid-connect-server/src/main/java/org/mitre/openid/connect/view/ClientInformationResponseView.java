/*******************************************************************************
 * Copyright 2018 The MIT Internet Trust Consortium
 *
 * Portions copyright 2011-2013 The MITRE Corporation
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 *******************************************************************************/
/**
 *
 */
package org.mitre.openid.connect.view;

import java.io.IOException;
import java.io.Writer;
import java.security.*;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.util.Map;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.apache.commons.codec.binary.Base64;
import org.mitre.oauth2.model.RegisteredClient;
import org.mitre.openid.connect.ClientDetailsEntityJsonProcessor;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.stereotype.Component;
import org.springframework.web.servlet.view.AbstractView;

import com.google.gson.Gson;
import com.google.gson.JsonIOException;
import com.google.gson.JsonObject;

/**
 *
 * Provides representation of a client's registration metadata, to be shown from the dynamic registration endpoint
 * on the client_register and rotate_secret operations.
 *
 * @author jricher
 *
 */
@Component(ClientInformationResponseView.VIEWNAME)
public class ClientInformationResponseView extends AbstractView {

	/**
	 * Logger for this class
	 */
	private static final Logger logger = LoggerFactory.getLogger(ClientInformationResponseView.class);

	public static final String VIEWNAME = "clientInformationResponseView";

	// note that this won't serialize nulls by default
	private Gson gson = new Gson();

	/* (non-Javadoc)
	 * @see org.springframework.web.servlet.view.AbstractView#renderMergedOutputModel(java.util.Map, javax.servlet.http.HttpServletRequest, javax.servlet.http.HttpServletResponse)
	 */
	@Override
	protected void renderMergedOutputModel(Map<String, Object> model, HttpServletRequest request, HttpServletResponse response) {

		response.setContentType(MediaType.APPLICATION_JSON_VALUE);

		RegisteredClient c = (RegisteredClient) model.get("client");
		//OAuth2AccessTokenEntity token = (OAuth2AccessTokenEntity) model.get("token");
		//String uri = (String)model.get("uri"); //request.getRequestURL() + "/" + c.getClientId();

		HttpStatus code = (HttpStatus) model.get(HttpCodeView.CODE);
		if (code == null) {
			code = HttpStatus.OK;
		}
		response.setStatus(code.value());

		JsonObject o = ClientDetailsEntityJsonProcessor.serialize(c);
		JsonObject content = new JsonObject();
		content.addProperty("Result", "OK");
		content.add("RegistrationInfo", o);
		JsonObject output = new JsonObject();
		String base64Content = Base64.encodeBase64String(content.toString().getBytes());
		output.addProperty("Content", base64Content);
		String privateKeyString = "MIIEvAIBADANBgkqhkiG9w0BAQEFAASCBKYwggSiAgEAAoIBAQCVagNIzL0xjLUpzROBhuWWoR8nvbew5+SulaOpGl2B+3Y3S2Nfg6aazMEqTehqUwOfOL94WUslQAibux5qoF0nKycraT5/N2w6Y4Dmuy+2A24vuPQhGiI9MHgmFKVIAjNCvL9Z1iEiaNsx79ZeWjPJF3B1HzFLBkVClEOorzc9wxoEQqoW/yTJRCZkE8DBGxRwNcF7zEKFXAFKjXMihw7gK2y5q9G8a0fdJO1r48ZkfEUd0xbYA6vKtEvq8fPzehpcaldc0snrFelHhS7Jb/qYZBoBrDKRRQuhcR5IZZNUT+o8qV6e3Zk+/u7QPjISfj65DAFeZPZ8AH85IKb94mQdAgMBAAECggEASGq9dMdm22ErXTs8PQc4t60YAJb/NQrv135HeGqC78EFJv+vBlg0o8qhxPNFtmLN2poSky4UMdW7Vl92+o8HFzjfHzc/R0GBfztC+pG3Kiy3dwHZsUGNXsLjOPHAugn29l2tEMmr/ZV8x9NKvyhQ+SIXK20W4xoC76YUtOlXiOMMrKe3qJBVHZnSY2hGxBCMgSkpeB83bosBc5jn/4d5PSXF5GOuKIdTroELnPzfSFVLmC2/9lf8nurvB2NAqqZ/iU9EISsND+okr/8jq1SXH2J6nCRTVm7eJgMkxqwb9tGRMlKcZ5ITfwoBUOFUPg3GxeDE8sHRz/MdJYN6Nsa6MQKBgQDVG6V7oRgqeKIxyKpBdByQrvHIwVy2W/iiLVwjsLrk3kbFe2Y5P/UytVlQoX5UaGpFAzLRnVcVBvoRL7QHlVfs8knQHAbSp0u3vEE5m74aNCcl4QEpLrUxtE7kVPV8+vXwZSUpN4kKJ1xU58Os7va7IvomlaediWqsr8If0qRuFwKBgQCzfIzFGvWqKAWJuqEGgM5IS3SQn0k4bRFb1khlVJgojTuS8sIkTLSGhVftJJf1qolQGzIMZK4tSp0ioY/viz2omLhjh7n1kIWmtgOdJkcumb1nrcgFyM1jcgofTtMh9phKmSuQprCSsaexINdS0hScq4L0QXreXYrqzntiC4tz6wKBgA2z52IZq6ofc55r3raytpt/BED6XfHD3Crha8lHtdy9hiNwmdQYjrWh/4o1uB/JTvv9Bql/ynepqS6tuI+8RJkRwzlEdBPbefzod/EyWHjq3ZGL9D0nqbL2exQnell88Y9xkYAi+AbVHRTAik52VxsVVqxgdxSkH13XN05Ahx4lAoGAYyK6BexcID22wVnpstPWHCxBF9hC8v2bBuSWXBGbcVqAuyuGe9I6K8rew8bgf/pPmYVL4XiCk9WQcR5Xh/GaftLLlX3UAoRuraP+3v/TdTPJX8imoDtG5lSIrr40859mgl2TqHPJN10UyErhY4dRhy9cR1kbalK0dfjSQVcrET0CgYADsiOiiikulzwYoombhU4kITZSxCIuHkTdEbQqOm9CSaJUZVHmdT9YZ1ggCe7r6Kb8ieru7X+RZVuze472SAszNiS6hXE45KNRv1fBbxM5Nu3McGruk8YexfdWcotBSL2vxAZPRTtnuR54ndozcOOwsAS+lzZpfMCJXP9eExw5BQ==";
		PKCS8EncodedKeySpec privateKeySpec = new PKCS8EncodedKeySpec(Base64.decodeBase64(privateKeyString.getBytes()));
		KeyFactory kf = null;
		try {
			kf = KeyFactory.getInstance("RSA");
		} catch (NoSuchAlgorithmException e) {
			e.printStackTrace();
		}
		byte[] signed = null;
		try {
			RSAPrivateKey pk = (RSAPrivateKey) kf.generatePrivate(privateKeySpec);
			Signature Sign = Signature.getInstance("SHA256withRSA");
			Sign.initSign(pk);
			Sign.update(base64Content.getBytes());
			signed = Sign.sign();
		} catch (InvalidKeySpecException e) {
			e.printStackTrace();
		} catch (NoSuchAlgorithmException e) {
			e.printStackTrace();
		} catch (SignatureException e) {
			e.printStackTrace();
		} catch (InvalidKeyException e) {
			e.printStackTrace();
		}
		output.addProperty("Sig", Base64.encodeBase64String(signed));
		try {
			Writer out = response.getWriter();
			gson.toJson(output, out);
		} catch (JsonIOException e) {

			logger.error("JsonIOException in ClientInformationResponseView.java: ", e);

		} catch (IOException e) {

			logger.error("IOException in ClientInformationResponseView.java: ", e);

		}

	}

}
