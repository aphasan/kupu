package id.my.mdn.kupu.core.security.service;

import id.my.mdn.kupu.core.security.dao.ApplicationSecurityGroupFacade;
import id.my.mdn.kupu.core.security.mechanism.CustomFormAuthenticationMechanism;
import jakarta.enterprise.context.RequestScoped;
import jakarta.faces.application.FacesMessage;
import jakarta.faces.context.ExternalContext;
import jakarta.faces.context.FacesContext;
import jakarta.inject.Inject;
import jakarta.inject.Named;
import jakarta.security.enterprise.AuthenticationStatus;
import jakarta.security.enterprise.SecurityContext;
import jakarta.security.enterprise.authentication.mechanism.http.AuthenticationParameters;
import jakarta.security.enterprise.credential.UsernamePasswordCredential;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import jakarta.servlet.http.HttpSession;
import jakarta.validation.constraints.NotNull;
import java.io.IOException;
import java.io.Serializable;
import java.util.logging.Level;
import java.util.logging.Logger;

@Named(value = "loginPage")
@RequestScoped
public class LoginPage implements Serializable {

    private static final Logger Log = Logger.getLogger(LoginPage.class.getCanonicalName());

    @NotNull
    private String username;

    @NotNull
    private String password;

    @Inject
    private SecurityContext securityContext;

    @Inject
    private ExternalContext externalContext;

    @Inject
    private FacesContext facesContext;

    @Inject
    private ApplicationSecurityGroupFacade groupFacade;

    @Inject
    private HttpServletRequest request;

    public void login() throws IOException {
        switch (continueAuthentication()) {
            case SEND_CONTINUE:
                facesContext.responseComplete();
                break;
            case SEND_FAILURE:
                facesContext.addMessage(
                        "messages",
                        new FacesMessage(
                                FacesMessage.SEVERITY_ERROR,
                                "Login failed",
                                null
                        )
                );
                break;
            case SUCCESS: {
                try {
                    // Try to restore saved request (if present)
                    HttpSession session = request.getSession(false);
                    if (session != null) {
                        Object saved = session.getAttribute(CustomFormAuthenticationMechanism.SAVED_REQUEST);
                        if (saved instanceof String) {
                            String savedUrl = (String) saved;
                            // remove saved request after consuming
                            session.removeAttribute(CustomFormAuthenticationMechanism.SAVED_REQUEST);
                            externalContext.redirect(savedUrl.startsWith("/") ? savedUrl : request.getContextPath() + savedUrl);
                            break;
                        }
                    }
                    // default landing if no saved request
                    externalContext.redirect(request.getContextPath() + "/");
                    break;
                } catch (IOException ex) {
                    Logger.getLogger(LoginPage.class.getName()).log(Level.SEVERE, null, ex);
                }
            }
            case NOT_DONE:
                break;
        }
    }

    public void logout(String landingPage) throws ServletException, IOException {
        request.logout();
        request.getSession().invalidate();
        externalContext.redirect(landingPage);
    }

    public void logout() throws ServletException, IOException {
        logout("/");
    }

    private AuthenticationStatus continueAuthentication() {
        AuthenticationStatus authenticationStatus = securityContext.authenticate(
                (HttpServletRequest) externalContext.getRequest(),
                (HttpServletResponse) externalContext.getResponse(),
                AuthenticationParameters.withParams().credential(
                        new UsernamePasswordCredential(username, password)
                )
        );

        return authenticationStatus;
    }

    public String getUsername() {
        return username;
    }

    public void setUsername(String username) {
        this.username = username;
    }

    public String getPassword() {
        return password;
    }

    public void setPassword(String password) {
        this.password = password;
    }

}