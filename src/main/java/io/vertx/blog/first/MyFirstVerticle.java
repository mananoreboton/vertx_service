package io.vertx.blog.first;

import io.vertx.core.AbstractVerticle;
import io.vertx.core.json.JsonObject;
import io.vertx.ext.auth.oauth2.AccessToken;
import io.vertx.ext.auth.oauth2.OAuth2Auth;
import io.vertx.ext.auth.oauth2.providers.GoogleAuth;
import io.vertx.ext.web.Router;
import io.vertx.ext.web.handler.*;
import io.vertx.ext.web.sstore.LocalSessionStore;

public class MyFirstVerticle extends AbstractVerticle {


    private OAuth2Auth oAuth2Auth = null;
    private OAuth2AuthHandler authHandler;


    @Override
    public void start() throws Exception {
        // To simplify the development of the web components we use a Router to route all HTTP requests
        // to organize our code in a reusable way.
        final Router router = Router.router(vertx);
        // We need cookies and sessions
        router.route().handler(CookieHandler.create());

        // Simple auth service which uses a GitHub to authenticate the user
        OAuth2Auth authProvider = GoogleAuth.create(vertx, CLIENT_ID, CLIENT_SECRET);

        SessionHandler sessionHandler = SessionHandler.create(LocalSessionStore.create(vertx));
        sessionHandler.setAuthProvider(authProvider);
        router.route().handler(sessionHandler);

        // We need a user session handler too to make sure the user is stored in the session between requests
        // Important!
        //router.route().handler(UserSessionHandler.create(authProvider));

        AuthHandler authHandler = OAuth2AuthHandler.create(authProvider, "http://localhost:8080/callback")
                // we now configure the oauth2 handler, it will setup the callback handler
                // as expected by your oauth2 provider.
                .setupCallback(router.route("/callback"))
                // for this resource we require that users have the authority to retrieve the user emails
                .addAuthority("profile");

        // we now protect the resource under the path "/protected"
        // Important! set AFTER CALLBACK
        router.route("/*").handler(authHandler);

        // The protected resource
        router.get("/protected/me").handler(ctx -> {
            AccessToken user = (AccessToken) ctx.user();
            // retrieve the user profile, this is a common feature but not from the official OAuth2 spec
            user.userInfo(res -> {
                if (res.failed()) {
                    // request didn't succeed because the token was revoked so we
                    // invalidate the token stored in the session and render the
                    // index page so that the user can start the OAuth flow again
                    ctx.session().destroy();
                    ctx.fail(res.cause());
                } else {
                    // the request succeeded, so we use the API to fetch the user's emails
                    final JsonObject userInfo = res.result();

                    // fetch the user emails from the github API

                    // the fetch method will retrieve any resource and ensure the right
                    // secure headers are passed.
                    ctx.response().end(userInfo.toString());
                }
            });
        });

        vertx.createHttpServer().requestHandler(router).listen(8080);
    }

}