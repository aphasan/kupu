package id.my.mdn.kupu.core.security.mechanism;

import jakarta.enterprise.context.ApplicationScoped;
import jakarta.inject.Inject;
import jakarta.security.enterprise.AuthenticationStatus;
import jakarta.security.enterprise.credential.UsernamePasswordCredential;
import jakarta.security.enterprise.identitystore.CredentialValidationResult;
import jakarta.security.enterprise.identitystore.IdentityStoreHandler;
import jakarta.security.enterprise.authentication.mechanism.http.HttpAuthenticationMechanism;
import jakarta.security.enterprise.authentication.mechanism.http.HttpMessageContext;
import jakarta.security.enterprise.authentication.mechanism.http.AuthenticationParameters;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import java.util.Collections;
import java.util.Set;

/**
 * Custom form mechanism that:
 * - prefers a UsernamePasswordCredential passed through AuthenticationParameters
 *   (used by SecurityContext.authenticate(...).credential(...))
 * - falls back to extracting username/password from request parameters for normal form posts
 * - validates credentials with IdentityStoreHandler
 * - calls notifyContainerAboutLogin(...) on success so validateRequest returns SUCCESS
 *   (allowing the calling bean to continue in the same request)
 * - returns responseUnauthorized() on failure
 * - returns doNothing() when no credentials present
 */
@ApplicationScoped
public class CustomFormAuthenticationMechanism implements HttpAuthenticationMechanism {

    @Inject
    private IdentityStoreHandler identityStoreHandler;

    private static final String[] USER_PARAM_NAMES = {"username", "j_username", "user", "email"};
    private static final String[] PASS_PARAM_NAMES = {"password", "j_password", "pass"};

    @Override
    public AuthenticationStatus validateRequest(HttpServletRequest request, HttpServletResponse response, HttpMessageContext context) {

        // 1) Prefer credential passed through AuthenticationParameters (programmatic authenticate())
        AuthenticationParameters authParams = context.getAuthParameters();
        UsernamePasswordCredential credential = null;

        if (authParams != null && authParams.getCredential() instanceof UsernamePasswordCredential) {
            credential = (UsernamePasswordCredential) authParams.getCredential();
        }

        // 2) Fallback: extract from request parameters (classic form submit)
        if (credential == null) {
            String username = extractFirstNonNull(request, USER_PARAM_NAMES);
            String password = extractFirstNonNull(request, PASS_PARAM_NAMES);
            if (username != null && password != null) {
                credential = new UsernamePasswordCredential(username, password);
            }
        }

        // 3) If still no credentials present, do nothing and let other handlers proceed
        if (credential == null) {
            return context.doNothing();
        }

        // 4) Validate credential using IdentityStoreHandler
        CredentialValidationResult result = identityStoreHandler.validate(credential);

        switch (result.getStatus()) {
            case VALID:
                Set<String> groups = result.getCallerGroups() != null ? result.getCallerGroups() : Collections.emptySet();
                // Notify the container about login -> returns SUCCESS (no redirect/forward)
                return context.notifyContainerAboutLogin(result.getCallerPrincipal(), groups);

            case NOT_VALID:
            case INVALID:
            default:
                // Authentication failed: respond unauthorized. Adjust to redirect/forward if you prefer.
                return context.responseUnauthorized();
        }
    }

    private String extractFirstNonNull(HttpServletRequest request, String[] names) {
        for (String n : names) {
            String v = request.getParameter(n);
            if (v != null && !v.trim().isEmpty()) {
                return v.trim();
            }
        }
        return null;
    }
}