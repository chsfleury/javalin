package io.javalin.jjwt

import io.javalin.http.Context
import io.javalin.http.Handler
import io.jsonwebtoken.Claims
import io.jsonwebtoken.JwtParser
import io.jsonwebtoken.Jwts
import java.security.Key

class JwtFilter(private val config: JJWTPluginConfig): Handler {
    private val parser: JwtParser = Jwts.parserBuilder().also {
        when (val key = config.signingKey) {
            is String -> it.setSigningKey(key)
            is ByteArray -> it.setSigningKey(key)
            is Key -> it.setSigningKey(key)
        }
    }.build()

    override fun handle(ctx: Context) {
        findJwt(ctx)?.also { token ->
            try {
                config.jwtAttributeName?.also { ctx.attribute(it, token) }
                config.claimsAttributeName?.also { ctx.attribute(it, parseToken(token)) }
            } catch (e: Exception) {
                config.invalidJwtHandler(ctx, e)
            }
        }
    }

    private fun parseToken(jwt: String): Claims = parser
            .parseClaimsJws(jwt)
            .body

    private fun findJwt(ctx: Context): String? = config.headerName
            ?.let { extractJwtFromHeader(it, ctx) }
            ?: config.paramName?.let { ctx.queryParam(it) }
            ?: config.cookieName?.let { ctx.cookie(it) }

    private fun extractJwtFromHeader(headerName: String, ctx: Context): String? = ctx.header(headerName)
            ?.let { value ->
                config.headerPrefix
                        ?.let { value.substring(it.length) }
                        ?: value
            }
}
