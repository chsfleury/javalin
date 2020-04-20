package io.javalin.jjwt

import io.javalin.Javalin
import io.javalin.core.util.Header
import io.javalin.plugin.json.JavalinJackson
import io.javalin.testing.TestUtil
import org.assertj.core.api.Assertions
import org.assertj.core.api.Assertions.assertThat
import org.assertj.core.api.Assertions.entry
import org.junit.Test

class TestJJWTPlugin {
    /**
    { "alg": "HS256", "typ": "JWT" }.{ "sub": "javalin-jjwt", "name": "Javalin" }.signature
     */
    private val jwt: String = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJqYXZhbGluLWpqd3QiLCJuYW1lIjoiSmF2YWxpbiJ9.NGqRQXZRFcbPH8rn0PLv3vohfxx5MkoE3YShPtcqQN8"

    private fun createTestApp(options: JJWTPluginConfig) = Javalin
            .create { it.registerPlugin(JJWTPlugin(options)) }
            .get("/jwt") { ctx ->
                ctx.result(ctx.attribute<String>(options.jwtAttributeName!!) ?: throw IllegalStateException())
            }
            .get("/claims") { ctx ->
                ctx.json(ctx.attribute<Map<String, Any>>(options.claimsAttributeName!!) ?: throw IllegalStateException())
            }

    @Test
    fun `should add attributes from header`() {
        val options = JJWTPluginConfig(
                signingKey = "YU9yZlE1eFQzTVpkVEZLUUN6UXRuNS12WlVtTERoTzB5cVZTRDctNWJNZw==",
                headerName = Header.AUTHORIZATION,
                jwtAttributeName = "token"
        )
        TestUtil.test(createTestApp(options)) { _, http ->
            assertThat(http.getBody("/jwt", mapOf(Header.AUTHORIZATION to jwt))).isEqualTo(jwt)
            val body = http.getBody("/claims", mapOf(Header.AUTHORIZATION to jwt))
            val claims = JavalinJackson.fromJson(body, Map::class.java) as Map<String, Any>
            assertThat(claims).contains(entry("sub", "javalin-jjwt"), entry("name", "Javalin"))
        }
    }

    @Test
    fun `should add attributes from param`() {
        val options = JJWTPluginConfig(
                signingKey = "YU9yZlE1eFQzTVpkVEZLUUN6UXRuNS12WlVtTERoTzB5cVZTRDctNWJNZw==",
                paramName = "token",
                jwtAttributeName = "token"
        )
        TestUtil.test(createTestApp(options)) { _, http ->
            assertThat(http.getBody("/jwt?token=$jwt")).isEqualTo(jwt)
            val body = http.getBody("/claims?token=$jwt", mapOf(Header.AUTHORIZATION to jwt))
            val claims = JavalinJackson.fromJson(body, Map::class.java) as Map<String, Any>
            assertThat(claims).contains(entry("sub", "javalin-jjwt"), entry("name", "Javalin"))
        }
    }

    @Test
    fun `should add attributes from header before param`() {
        val options = JJWTPluginConfig(
                signingKey = "YU9yZlE1eFQzTVpkVEZLUUN6UXRuNS12WlVtTERoTzB5cVZTRDctNWJNZw==",
                headerName = Header.AUTHORIZATION,
                paramName = "token",
                jwtAttributeName = "token"
        )
        TestUtil.test(createTestApp(options)) { _, http ->
            assertThat(http.getBody("/jwt?token=badToken", mapOf(Header.AUTHORIZATION to jwt))).isEqualTo(jwt)
        }
    }

    @Test
    fun `should get a 401 because of bad token`() {
        val options = JJWTPluginConfig(
                signingKey = "YU9yZlE1eFQzTVpkVEZLUUN6UXRuNS12WlVtTERoTzB5cVZTRDctNWJNZw==",
                paramName = "token",
                jwtAttributeName = "token"
        )
        TestUtil.test(createTestApp(options)) { _, http ->
            assertThat(http.getBody("/jwt?token=badToken")).isEqualTo(jwt)
        }
    }
}
