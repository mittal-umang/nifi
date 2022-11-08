package org.apache.nifi.oauth2;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.DeserializationFeature;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.PropertyNamingStrategies;
import okhttp3.FormBody;
import okhttp3.OkHttpClient;
import okhttp3.Request;
import okhttp3.Response;
import org.apache.nifi.annotation.lifecycle.OnDisabled;
import org.apache.nifi.annotation.lifecycle.OnEnabled;
import org.apache.nifi.components.PropertyDescriptor;
import org.apache.nifi.components.ValidationContext;
import org.apache.nifi.components.ValidationResult;
import org.apache.nifi.components.Validator;
import org.apache.nifi.controller.AbstractControllerService;
import org.apache.nifi.controller.ConfigurationContext;
import org.apache.nifi.expression.ExpressionLanguageScope;
import org.apache.nifi.processor.exception.ProcessException;
import org.apache.nifi.processor.util.StandardValidators;

import java.io.IOException;
import java.io.UncheckedIOException;
import java.util.*;

public class GeneralOauth2AccessTokenProvider extends AbstractControllerService implements OAuth2AccessTokenProvider {
    public static final PropertyDescriptor AUTHORIZATION_SERVER_URL = new PropertyDescriptor.Builder()
            .name("authorization-server-url")
            .displayName("Authorization Server URL")
            .description("The URL of the authorization server that issues access tokens.")
            .required(true)
            .addValidator(StandardValidators.URL_VALIDATOR)
            .expressionLanguageSupported(ExpressionLanguageScope.VARIABLE_REGISTRY)
            .build();

    public static final PropertyDescriptor CUSTOM_HEADERS = new PropertyDescriptor.Builder().name("custom-headers")
            .displayName("Custom Headers").required(true).addValidator(StandardValidators.NON_BLANK_VALIDATOR)
            .description("Provide all custom headers required to generate token in JSON Format")
            .build();

    public static final PropertyDescriptor RESPONSE_MAPPER = new PropertyDescriptor.Builder().name("response-mapping")
            .displayName("Response Mapper").required(false).addValidator(new ResponseMappingValidator())
            .description("Provide Mapping for response to model with fields accessDetails, refreshToken, tokenType," +
                    "expiresIn, scopes as json. e.g {\"accessDetails\":\"\", \"refreshToken\":\"\", \"tokenType\":\"\"," +
                    "\"expiresIn\":\"\", \"scopes\":\"\"}. Use in case response has different keys").build();

    private static final List<PropertyDescriptor> PROPERTIES = Collections.unmodifiableList(Arrays.asList(
            AUTHORIZATION_SERVER_URL, CUSTOM_HEADERS, RESPONSE_MAPPER
    ));

    public static final ObjectMapper ACCESS_DETAILS_MAPPER = new ObjectMapper();

    private volatile String authorizationServerUrl;
    private volatile OkHttpClient httpClient = new OkHttpClient();
    private volatile Map customHeaders;
    private volatile Map responseMapping;
    private volatile AccessToken accessDetails;

    @Override
    public List<PropertyDescriptor> getSupportedPropertyDescriptors() {
        return PROPERTIES;
    }

    @OnEnabled
    public void onEnabled(ConfigurationContext context) {
        authorizationServerUrl =
                context.getProperty(AUTHORIZATION_SERVER_URL).evaluateAttributeExpressions().getValue();
        try {
            customHeaders = ACCESS_DETAILS_MAPPER.readValue(
                    context.getProperty(CUSTOM_HEADERS).evaluateAttributeExpressions().getValue(), Map.class);
            if (context.getProperty(RESPONSE_MAPPER).isSet()) {
                responseMapping = ACCESS_DETAILS_MAPPER.readValue(
                        context.getProperty(RESPONSE_MAPPER).evaluateAttributeExpressions().getValue(), Map.class);
            } else {
                responseMapping = null;
            }
        } catch (JsonProcessingException e) {
            throw new ProcessException(e);
        }

    }

    @OnDisabled
    public void onDisabled() {
        this.accessDetails = null;
    }

    @Override
    public AccessToken getAccessDetails() {
        if (this.accessDetails == null) {
            acquireAccessToken();
        } else if (this.accessDetails.isExpired()) {
            acquireAccessToken();
        }
        return accessDetails;
    }

    private void acquireAccessToken() {
        FormBody.Builder tokenFormBuilder = new FormBody.Builder();
        this.customHeaders.forEach((key, value) -> tokenFormBuilder.add((String) key, (String) value));
        Request acquireTokenRequest = new Request.Builder()
                .url(this.authorizationServerUrl).post(tokenFormBuilder.build())
                .build();

        this.accessDetails = getAccessDetails(acquireTokenRequest);
    }

    private AccessToken getAccessDetails(final Request newRequest) {
        try (final Response response = httpClient.newCall(newRequest).execute()) {
            final String responseBody = Objects.requireNonNull(response.body()).string();
            if (response.isSuccessful()) {
                getLogger().debug("OAuth2 Access Token retrieved [HTTP {}]", response.code());

                if (responseMapping != null) {
                    return ACCESS_DETAILS_MAPPER.configure(DeserializationFeature.FAIL_ON_UNKNOWN_PROPERTIES, false)
                            .setPropertyNamingStrategy(PropertyNamingStrategies.SNAKE_CASE)
                            .readValue(responseBody, AccessToken.class);
                } else {
                    Map<String, String> accessTokenMap = ACCESS_DETAILS_MAPPER.readValue(responseBody, Map.class);
                    return evaluateTokenMap(accessTokenMap);
                }
            } else {
                getLogger().error(
                        String.format("OAuth2 access token request failed [HTTP %d], response:%n%s", response.code(),
                                responseBody));
                throw new ProcessException(
                        String.format("OAuth2 access token request failed [HTTP %d]", response.code()));
            }
        } catch (final IOException e) {
            throw new UncheckedIOException("OAuth2 access token request failed", e);
        }
    }

    private AccessToken evaluateTokenMap(Map<String, String> tokenResponse) throws NullPointerException {
        AccessToken token = new AccessToken();

        token.setAccessToken(((String) responseMapping.get("accessDetails")).isEmpty() ? null :
                tokenResponse.get((String) responseMapping.get("accessDetails")));

        token.setRefreshToken(((String) responseMapping.get("refreshToken")).isEmpty() ? null :
                tokenResponse.get((String) responseMapping.get("refreshToken")));

        token.setTokenType(((String) responseMapping.get("tokenType")).isEmpty() ? null :
                tokenResponse.get((String) responseMapping.get("tokenType")));

        token.setExpiresIn(((String) responseMapping.get("expiresIn")).isEmpty() ? null :
                Long.parseLong(tokenResponse.get((String) responseMapping.get("expiresIn"))));

        token.setScopes(((String) responseMapping.get("scopes")).isEmpty() ? null :
                tokenResponse.get((String) responseMapping.get("scopes")));

        return token;
    }


    private static class ResponseMappingValidator implements Validator {

        @Override
        public ValidationResult validate(String subject, String input, ValidationContext context) {
            try {
                Map<String, String> responseMap = ACCESS_DETAILS_MAPPER.readValue(input, Map.class);
                if (responseMap.keySet()
                        .containsAll(List.of("accessDetails", "refreshToken", "tokenType", "expiresIn", "scopes"))) {

                    return new ValidationResult.Builder().subject(subject).input(input)
                            .explanation("All Keys validated")
                            .valid(true).build();
                }
            } catch (JsonProcessingException jsonProcessingException) {
                throw new ProcessException(jsonProcessingException);
            }

            return new ValidationResult.Builder().subject(subject).input(input).explanation("Keys Missing")
                    .valid(false).build();
        }
    }
}
