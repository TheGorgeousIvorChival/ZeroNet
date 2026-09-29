package com.zeronet.mobile.ui

import com.zeronet.mobile.model.ConnectionProfile
import com.zeronet.mobile.ui.effects.holdsHandheld
import com.zeronet.mobile.ui.effects.hopHeightDp
import com.zeronet.mobile.ui.effects.hopsPerSecond
import com.zeronet.mobile.ui.effects.pose
import com.zeronet.mobile.ui.effects.speedDp
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

class KangarooTest {
    @Test fun theFasterTheModeTheFasterTheyHop() {
        val normal = hopsPerSecond(ConnectionProfile.Normal)
        val fast = hopsPerSecond(ConnectionProfile.Fast)
        assertEquals(normal, hopsPerSecond(ConnectionProfile.Legacy), 0f)
        assertTrue(fast > normal * 1.5f)
        assertTrue(hopsPerSecond(ConnectionProfile.Gaming) >= fast)
        assertTrue(speedDp(ConnectionProfile.Fast) > speedDp(ConnectionProfile.Normal) * 2f)
        assertTrue(hopHeightDp(ConnectionProfile.Fast) > hopHeightDp(ConnectionProfile.Normal))
    }

    @Test fun onlyGamingModeHasTheHandheld() {
        assertTrue(holdsHandheld(ConnectionProfile.Gaming))
        for (p in listOf(ConnectionProfile.Normal, ConnectionProfile.Fast, ConnectionProfile.Legacy)) assertFalse(p.name, holdsHandheld(p))
    }

    @Test fun aHopGoesUpAndComesBackDownWithItsLegsOutAtBothEnds() {
        val start = pose(0f)
        val top = pose(0.5f)
        val landing = pose(0.999f)
        assertEquals(0f, start.lift, 1e-4f)
        assertEquals(1f, top.lift, 1e-4f)
        assertEquals(0f, landing.lift, 1e-2f)
        assertTrue(start.legs > 0.99f && landing.legs > 0.95f)
        assertTrue(top.legs < 0.01f)
        assertTrue(start.squash > 0.99f && top.squash < 0.01f)
    }

    @Test fun everyPhaseGivesAUsablePoseAndTheCycleRepeats() {
        for (i in -30..130) {
            val p = pose(i / 40f)
            assertTrue(p.lift in 0f..1f && p.legs in 0f..1f && p.squash in 0f..1f)
            assertTrue(p.lean.isFinite() && p.tail.isFinite())
        }
        assertEquals(pose(0.3f).lift, pose(3.3f).lift, 1e-4f)
        assertEquals(pose(0.3f).tail, pose(-1.7f).tail, 1e-3f)
    }
}
