package tak.gitbucket.oa2.controller

import java.net.URI

import com.nimbusds.oauth2.sdk.id.State
import gitbucket.core.controller._
import gitbucket.core.model.Account
import gitbucket.core.service._
import gitbucket.core.util.Implicits._
import gitbucket.core.util._
import gitbucket.core.util.AdminAuthenticator
import org.scalatra.forms._
import org.slf4j.LoggerFactory

import tak.gitbucket.oa2.service._
import tak.gitbucket.oa2.service.OA2Service._
import tak.gitbucket.oa2.html

class OA2Controller
    extends OA2ControllerBase
    with RepositoryService
    with AdminAuthenticator
    with AccountService
    with AccountFederationService
    with OA2Service

trait OA2ControllerBase extends ControllerBase {
  self: RepositoryService with AdminAuthenticator with AccountService with AccountFederationService with OA2Service =>

  private val KeysSessionOa2Context = "oa2Context"

  case class Oa2Context(state: State, redirectBackURI: String)

  val oa2SettingsForm = mapping(
    "oa2cAuthentication" -> trim(label("OA2", boolean())),
    "issuer" -> trim(label("Issuer", text(required))),
    "authorizationEndpoint" -> trim(label("Authorization Endpoint", text(required))),
    "tokenEndpoint" -> trim(label("Token Endpoint", text(required))),
    "userinfoEndpoint" -> trim(label("Userinfo Endpoint", text(required))),
    "clientId" -> trim(label("Client ID", text(required))),
    "clientSecret" -> trim(label("Client secret", text(required)))
  )(OA2Settings.apply)

  get("/signinoa2") {
    val redirect = params.get("redirect")
    if (redirect.isDefined && redirect.get.startsWith("/")) {
      flash += Keys.Flash.Redirect -> redirect.get
    }
    html.signinoa2(flash.get("error"))
  }

  get("/admin/oa2")(adminOnly {
    val settings = loadOA2Settings()
    html.oa2(
      settings.oa2Authentication,
      settings.issuer,
      settings.authorizationEndpoint,
      settings.tokenEndpoint,
      settings.userinfoEndpoint,
      settings.clientId,
      settings.clientSecret,
      None
    )
  })

  post("/admin/oa2", oa2SettingsForm)(adminOnly { form =>
    saveOA2Settings(form)
    html.oa2(
      form.oa2Authentication,
      form.issuer,
      form.authorizationEndpoint,
      form.tokenEndpoint,
      form.userinfoEndpoint,
      form.clientId,
      form.clientSecret,
      Some("Settings Saved")
    )
  })

  /**
   * Initiate an OAuth2.0 authentication request.
   */
  post("/signin/oa2") {
    val settings = loadOA2Settings()
    if (settings.oa2Authentication) {
      val redirectURI = new URI(s"$baseUrl/signin/oa2")
      val authenticationRequest = createOA2AuthenticationRequest(settings, redirectURI)
      val redirectBackURI = flash.get(Keys.Flash.Redirect) match {
        case Some(redirectBackURI: String) => redirectBackURI + params.getOrElse("hash", "")
        case _                             => "/"
      }
      session.setAttribute(
        KeysSessionOa2Context,
        Oa2Context(authenticationRequest.getState, redirectBackURI)
      )
      redirect(authenticationRequest.toURI.toString)
    } else {
      NotFound()
    }
  }

  /**
   * Handle an OAuth2.0 authentication response.
   */
  get("/signin/oa2") {
    val settings = loadOA2Settings()
    if (settings.oa2Authentication) {
      val redirectURI = new URI(s"$baseUrl/signin/oa2")
      session.get(KeysSessionOa2Context) match {
        case Some(context: Oa2Context) =>
          authenticateOA2(params, redirectURI, context.state, settings) map { account =>
            signin(account, context.redirectBackURI)
          } orElse {
            flash += "error" -> "Sorry, authentication failed. Please try again."
            session.invalidate()
            redirect("/signin")
          }
        case _ =>
          flash += "error" -> "Sorry, something wrong. Please try again."
          session.invalidate()
          redirect("/signin")
      }
    } else {
      NotFound()
    }
  }

  /**
   * Set account information into HttpSession and redirect.
   */
  private def signin(account: Account, redirectUrl: String = "/") = {
    session.setAttribute(Keys.Session.LoginAccount, account)
    updateLastLoginDate(account.userName)

    if (redirectUrl.stripSuffix("/") == request.getContextPath) {
      redirect("/")
    } else {
      redirect(redirectUrl)
    }
  }

}
