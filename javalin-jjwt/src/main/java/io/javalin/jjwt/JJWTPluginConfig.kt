package io.javalin.jjwt

import io.javalin.http.Context
import org.eclipse.jetty.http.HttpStatus
import java.security.Key

data class JJWTPluginConfig (
        val signingKey: Any,
        val paramName: String? = null,
        val headerName: String? = null,
        val cookieName: String? = null,
        val headerPrefix: String? = null,
        val jwtAttributeName: String? = "jwt",
        val claimsAttributeName: String? = "claims",
        val invalidJwtHandler: (Context, Exception) -> Unit = { ctx, ex ->
            ctx.status(HttpStatus.UNAUTHORIZED_401)
            val body = ex.message
            if (body != null) {
                ctx.result(body)
            }
        }
)
