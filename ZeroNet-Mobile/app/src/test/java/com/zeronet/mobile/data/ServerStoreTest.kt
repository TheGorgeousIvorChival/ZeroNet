package com.zeronet.mobile.data

import android.database.sqlite.SQLiteDatabase
import com.zeronet.mobile.model.Server
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Before
import org.junit.Test
import org.junit.runner.RunWith
import org.robolectric.RobolectricTestRunner
import org.robolectric.RuntimeEnvironment
import org.robolectric.annotation.Config

@RunWith(RobolectricTestRunner::class)
@Config(sdk = [35])
class ServerStoreTest {
    private val context = RuntimeEnvironment.getApplication()

    /** The store is a process singleton; each test gets a fresh database. */
    @Before
    fun freshStore() {
        ServerStore::class.java.getDeclaredField("instance").apply { isAccessible = true }.set(null, null)
        context.deleteDatabase("servers.db")
    }

    private fun server(key: String) = Server(
        key = key, link = "vless://$key@example.com:443", name = key, protocol = "vless",
        transport = "tcp", security = "reality", host = "example.com", port = 443,
        country = "DE", source = Server.SOURCE_USER,
    )

    @Test
    fun `a version 2 database upgrades with every server still included`() {
        // A servers.db as the previous release wrote it: no excluded column.
        val file = context.getDatabasePath("servers.db")
        file.parentFile?.mkdirs()
        SQLiteDatabase.openOrCreateDatabase(file, null).use { db ->
            db.execSQL(
                """CREATE TABLE servers(key TEXT PRIMARY KEY, link TEXT NOT NULL, name TEXT NOT NULL,
                   protocol TEXT NOT NULL, transport TEXT NOT NULL, security TEXT NOT NULL,
                   host TEXT NOT NULL, port INTEGER NOT NULL, country TEXT NOT NULL, source TEXT NOT NULL,
                   favorite INTEGER NOT NULL DEFAULT 0, delay_ms INTEGER NOT NULL DEFAULT -1,
                   tested_at INTEGER NOT NULL DEFAULT 0, alive_count INTEGER NOT NULL DEFAULT 0,
                   fail_count INTEGER NOT NULL DEFAULT 0, first_seen INTEGER NOT NULL, last_error TEXT)""",
            )
            db.execSQL("CREATE TABLE history(network TEXT NOT NULL, key TEXT NOT NULL, score REAL NOT NULL, last_ok INTEGER NOT NULL, PRIMARY KEY(network, key)) WITHOUT ROWID")
            db.execSQL("CREATE TABLE subscriptions(id TEXT PRIMARY KEY, name TEXT NOT NULL, url TEXT NOT NULL, enabled INTEGER NOT NULL DEFAULT 1, updated_at INTEGER NOT NULL DEFAULT 0, count INTEGER NOT NULL DEFAULT 0)")
            db.execSQL("INSERT INTO servers(key, link, name, protocol, transport, security, host, port, country, source, first_seen) VALUES('old', 'vless://old', 'old', 'vless', 'tcp', 'tls', 'h', 443, 'DE', 'user', 0)")
            db.version = 2
        }
        val store = ServerStore.get(context)
        val old = store.all().single { it.key == "old" }
        assertFalse("existing servers must stay available to auto-selection", old.excluded)
    }

    @Test
    fun `an excluded server is kept but left out of automatic picks`() {
        val store = ServerStore.get(context)
        store.upsert(listOf(server("a"), server("b")))
        store.recordResult("a", 100, "wifi")
        store.recordResult("b", 120, "wifi")
        assertEquals(2, store.historyLinks("wifi", 10).size)

        store.setExcluded("a", true)
        assertTrue(store.all().single { it.key == "a" }.excluded)
        assertEquals(setOf("a"), store.excludedKeys())
        assertEquals(listOf("vless://b@example.com:443"), store.historyLinks("wifi", 10))

        // A later refresh of the same link must not silently re-include it.
        store.upsert(listOf(server("a")))
        assertTrue(store.all().single { it.key == "a" }.excluded)

        store.setExcluded("a", false)
        assertEquals(2, store.historyLinks("wifi", 10).size)
    }
}
