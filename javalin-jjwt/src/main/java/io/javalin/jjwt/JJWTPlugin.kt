package io.javalin.jjwt

import io.javalin.Javalin
import io.javalin.core.plugin.Plugin
import io.javalin.http.Context
import io.jsonwebtoken.Claims

class JJWTPlugin(private val config: JJWTPluginConfig): Plugin {

    override fun apply(app: Javalin) {
        app.before(JwtFilter(config))
    }

    fun Context.jwt(): String = config.jwtAttributeName
            ?.let { attribute<String>(it) }
            ?: throw IllegalStateException("no jwt attribute configured")

    fun Context.claims(): Claims = config.claimsAttributeName
            ?.let { attribute<Claims>(it) }
            ?: throw IllegalStateException("no claims attribute configured")
}
