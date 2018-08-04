import io.github.gitbucket.solidbase.model.Version
import gitbucket.core.plugin.Link
import gitbucket.core.controller.Context
import gitbucket.core.service.RepositoryService.RepositoryInfo

import tak.gitbucket.oa2.controller.OA2Controller

class Plugin extends gitbucket.core.plugin.Plugin {
  override val pluginId: String = "oauth2"

  override val pluginName: String = "OAuth2.0"

  override val description: String = "login by OAuth2.0"

  override val versions: List[Version] = List(new Version("1.0.0"))

  override val controllers = Seq(
    "/*" -> new OA2Controller
  )

  override val systemSettingMenus: Seq[(Context) => Option[Link]] = Seq(
    (ctx: Context) => Some(Link("OAuth2.0","OAuth2.0","admin/oa2"))
  )

  // override val globalMenus: Seq[(Context) => Option[Link]] = Seq(
  //   (ctx: Context) => Some(Link("OAuth2.0","OAuth2.0","/signinoa2"))
  // )

}
