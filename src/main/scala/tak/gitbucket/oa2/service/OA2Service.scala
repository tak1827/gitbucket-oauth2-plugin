package tak.gitbucket.oa2.service

import java.io.File
import java.net.URI
import java.util.Arrays

import com.nimbusds.oauth2.sdk._
import com.nimbusds.oauth2.sdk.auth.ClientSecretBasic
import com.nimbusds.oauth2.sdk.id._
import com.nimbusds.oauth2.sdk.token.AccessToken
import com.nimbusds.oauth2.sdk.http._
import com.nimbusds.oauth2.sdk.auth.Secret
import com.nimbusds.oauth2.sdk.id.{ClientID, Issuer}
import com.nimbusds.openid.connect.sdk.op.OIDCProviderMetadata
import com.nimbusds.openid.connect.sdk.{AuthenticationErrorResponse, _}
import gitbucket.core.model.Account
import gitbucket.core.model.Profile.profile.blockingApi._
import gitbucket.core.service._
import gitbucket.core.util.Directory._
import gitbucket.core.util.SyntaxSugars._
import org.slf4j.LoggerFactory
import scala.collection.JavaConverters.mapAsJavaMap
import net.minidev.json.JSONObject

import tak.gitbucket.oa2.service.OA2Service._

/**
 * Service class for the OAuth2.0 authentication.
 */
trait OA2Service {
  self: AccountFederationService =>

  private val logger = LoggerFactory.getLogger(classOf[OA2Service])

  private val OA2_SCOPE = new Scope(OIDCScopeValue.EMAIL, OIDCScopeValue.PROFILE)

  val OA2Conf = new File(GitBucketHome, "oa2.conf")

  def saveOA2Settings(settings: OA2Settings): Unit =
    defining(new java.util.Properties()) { props =>
      props.setProperty(Oa2Authentication, settings.oa2Authentication.toString)
      props.setProperty(Oa2Issuer, settings.issuer)
      props.setProperty(Oa2AuthorizationEndpoint, settings.authorizationEndpoint)
      props.setProperty(Oa2TokenEndpoint, settings.tokenEndpoint)
      props.setProperty(Oa2UserinfoEndpoint, settings.userinfoEndpoint)
      props.setProperty(Oa2ClientId, settings.clientId)
      props.setProperty(Oa2ClientSecret, settings.clientSecret)
      using(new java.io.FileOutputStream(OA2Conf)) { out =>
        props.store(out, null)
      }
    }

  def loadOA2Settings(): OA2Settings =
    defining(new java.util.Properties()) { props =>
      if (OA2Conf.exists) {
        using(new java.io.FileInputStream(OA2Conf)) { in =>
          props.load(in)
        }
      }

      OA2Settings(
        getValue(props, Oa2Authentication, false),
        getValue(props, Oa2Issuer, "http://localhost/test"),
        getValue(props, Oa2AuthorizationEndpoint, "http://localhost/oauth/authorize"),
        getValue(props, Oa2TokenEndpoint, "http://localhost/oauth/token"),
        getValue(props, Oa2UserinfoEndpoint, "http://localhost/api/user"),
        getValue(props, Oa2ClientId, "XXXX"),
        getValue(props, Oa2ClientSecret, "XXXX")
      )
    }

  /**
   * Obtain the OA2 metadata from discovery and create an authentication request.
   *
   * @param issuer      Issuer, used to construct the discovery endpoint URL, e.g. https://accounts.google.com
   * @param clientID    Client ID (given by the issuer)
   * @param redirectURI Redirect URI
   * @return Authorization request
   */
  def createOA2AuthenticationRequest(settings: OA2Settings, redirectURI: URI): AuthorizationRequest = {
    var clientID = new ClientID(settings.clientId);
    new AuthorizationRequest.Builder(new ResponseType(ResponseType.Value.CODE), clientID)
      .scope(OA2_SCOPE)
      .state(new State())
      .redirectionURI(redirectURI)
      .endpointURI(new URI(settings.authorizationEndpoint))
      .build()
  }

  /**
   * Proceed the OAuth2.0 authentication.
   *
   * @param params      Query parameters of the authentication response
   * @param redirectURI Redirect URI
   * @param state       State saved in the session
   * @param oidc        OIDC settings
   * @return Account
   */
  def authenticateOA2(
    params: Map[String, String],
    redirectURI: URI,
    state: State,
    settings: OA2Settings
  )(implicit s: Session): Option[Account] =
    validateOA2AuthenticationResponse(params, state, redirectURI) flatMap { authenticationResponse =>
      obtainOA2CToken(authenticationResponse.getAuthorizationCode, redirectURI, settings) flatMap { token =>
        obtainUserInfo(token, settings) flatMap { json =>
          getOrCreateFederatedUser(
            settings.issuer,
            "oauth2",
            json.get("email").toString(),
            Option(json.get("name").toString()),
            Option(json.get("name").toString())
          )
        }
      }
    }

  /**
   * Validate the authorization response.
   *
   * @param params      Query parameters of the authentication response
   * @param state       State saved in the session
   * @param redirectURI Redirect URI
   * @return Authorization response
   */
  def validateOA2AuthenticationResponse(
    params: Map[String, String],
    state: State,
    redirectURI: URI
  ): Option[AuthenticationSuccessResponse] =
    try {
      AuthenticationResponseParser.parse(redirectURI, mapAsJavaMap(params)) match {
        case response: AuthenticationSuccessResponse =>
          if (response.getState == state) {
            Some(response)
          } else {
            logger.info(s"OA2 authorization state did not match: response(${response.getState}) != session($state)")
            None
          }
        case response: AuthenticationErrorResponse =>
          logger.info(s"OA2 authorization response has error: ${response.getErrorObject}")
          None
      }
    } catch {
      case e: ParseException =>
        logger.info(s"OA2 authorization response has error: $e")
        None
    }

  /**
   * Obtain the access token from the OAuth2.0 Provider.
   *
   * @param authorizationCode Authorization code in the query string
   * @param nonce             Nonce
   * @param redirectURI       Redirect URI
   * @param oidc              OIDC settings
   * @return Token response
   */
  def obtainOA2CToken(
    authorizationCode: AuthorizationCode,
    redirectURI: URI,
    settings: OA2Settings
  ): Option[AccessToken] = {
    val tokenEndpoint = new URI(settings.tokenEndpoint)
    val clientID = new ClientID(settings.clientId);
    val clientSecret = new Secret(settings.clientSecret)
    val tokenRequest = new TokenRequest(
      tokenEndpoint,
      new ClientSecretBasic(clientID, clientSecret),
      new AuthorizationCodeGrant(authorizationCode, redirectURI)
    )
    val httpResponse = tokenRequest.toHTTPRequest.send()
    try {
      TokenResponse.parse(httpResponse) match {
        case response: AccessTokenResponse =>
          Some(response.getTokens.getAccessToken)
        case response: TokenErrorResponse =>
          logger.info(s"OA2 token response has error: ${response.getErrorObject.toJSONObject}")
          None
      }
    } catch {
      case e: ParseException =>
        logger.info(s"OA2 token response has error: $e")
        None
    }
  }

  /**
   * Obtain the user information from the resource Provider.
   *
   * @param token AccessToken
   * @param oidc  OIDC settings
   * @return JSONObject
   */
  def obtainUserInfo(
    token: AccessToken,
    settings: OA2Settings
  ): Option[JSONObject] = {
    val userinfoEndpoint = new URI(settings.userinfoEndpoint).toURL
    val httpRequest = new HTTPRequest(HTTPRequest.Method.GET, userinfoEndpoint);
    httpRequest.setContentType(CommonContentTypes.APPLICATION_URLENCODED);
    httpRequest.setAuthorization(token.toAuthorizationHeader())
    try {
      val httpResponse = httpRequest.send()
      if (httpResponse.getStatusCode() == HTTPResponse.SC_OK) {
        Some(httpResponse.getContentAsJSONObject)
      } else {
        logger.info(s"OA2 resource request has error: hogefuga")
        None
      }
    } catch {
      case e: ParseException =>
        logger.info(s"OA2 obtain user info has error: $e")
        None
    }
  }

}

object OA2Service {
  import scala.reflect.ClassTag

  case class OA2Settings(
    oa2Authentication: Boolean,
    issuer: String,
    authorizationEndpoint: String,
    tokenEndpoint: String,
    userinfoEndpoint: String,
    clientId: String,
    clientSecret: String
  )

  private val Oa2Authentication = "oa2_authentication"
  private val Oa2Issuer = "oa2_issuer"
  private val Oa2AuthorizationEndpoint = "oa2_authorization_endpoint"
  private val Oa2TokenEndpoint = "oa2_token_endpoint"
  private val Oa2UserinfoEndpoint = "oa2_userinfo_endpoint"
  private val Oa2ClientId = "oa2_client_id"
  private val Oa2ClientSecret = "oa2_client_secret"

  private def getValue[A: ClassTag](props: java.util.Properties, key: String, default: A): A =
    defining(props.getProperty(key)) { value =>
      if (value == null || value.isEmpty) default
      else convertType(value).asInstanceOf[A]
    }

  private def getOptionValue[A: ClassTag](props: java.util.Properties, key: String, default: Option[A]): Option[A] =
    defining(props.getProperty(key)) { value =>
      if (value == null || value.isEmpty) default
      else Some(convertType(value)).asInstanceOf[Option[A]]
    }

  private def convertType[A: ClassTag](value: String) =
    defining(implicitly[ClassTag[A]].runtimeClass) { c =>
      if (c == classOf[Boolean]) value.toBoolean
      else if (c == classOf[Int]) value.toInt
      else value
    }
}
