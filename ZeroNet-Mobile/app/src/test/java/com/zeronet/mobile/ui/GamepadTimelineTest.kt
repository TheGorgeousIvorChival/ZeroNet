package com.zeronet.mobile.ui

import com.zeronet.mobile.ui.effects.GamepadTimeline
import com.zeronet.mobile.ui.effects.Pad
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test

class GamepadTimelineTest {
    @Test fun everyButtonIsPressedOnceInOrderAndTheWholeThingFitsItsTime() {
        val order = GamepadTimeline.presses
        assertEquals(Pad.entries.toSet(), order.map { it.first }.toSet())
        assertEquals(Pad.entries.size, order.size)
        assertEquals(order.map { it.second }.sorted(), order.map { it.second })
        assertTrue(order.last().second + GamepadTimeline.PRESS_MS < GamepadTimeline.TOTAL_MS)
        assertTrue(order.first().second > GamepadTimeline.DROP_IN_MS)
    }

    @Test fun aButtonGoesDownQuicklyIsHeldAndComesBackUp() {
        val at = GamepadTimeline.presses.first { it.first == Pad.A }.second.toFloat()
        assertEquals(0f, GamepadTimeline.depth(Pad.A, at - 1f), 0f)
        assertEquals(0f, GamepadTimeline.depth(Pad.A, at), 1e-6f)
        assertEquals(1f, GamepadTimeline.depth(Pad.A, at + 40f), 1e-6f)
        assertEquals(1f, GamepadTimeline.depth(Pad.A, at + 90f), 1e-6f)
        val rising = GamepadTimeline.depth(Pad.A, at + 140f)
        assertTrue(rising in 0.01f..0.99f)
        assertEquals(0f, GamepadTimeline.depth(Pad.A, at + GamepadTimeline.PRESS_MS + 1f), 0f)
        // The others are not pressed while A is.
        assertEquals(0f, GamepadTimeline.depth(Pad.B, at + 40f), 0f)
    }

    @Test fun eachPressIsReportedExactlyOnceAsTheClockPassesIt() {
        var last = 0f
        val seen = mutableListOf<Pad>()
        var ms = 0f
        while (ms < GamepadTimeline.TOTAL_MS) {
            ms += 16f
            seen += GamepadTimeline.newPresses(last, ms)
            last = ms
        }
        assertEquals(GamepadTimeline.presses.map { it.first }, seen)
    }

    @Test fun theControllerFadesInAndOutAndDropsIntoPlace() {
        assertEquals(0f, GamepadTimeline.opacity(0f), 0f)
        assertEquals(1f, GamepadTimeline.opacity(1500f), 0f)
        assertEquals(0f, GamepadTimeline.opacity(GamepadTimeline.TOTAL_MS.toFloat()), 1e-6f)
        assertEquals(0f, GamepadTimeline.drop(0f), 1e-6f)
        assertEquals(1f, GamepadTimeline.drop(GamepadTimeline.DROP_IN_MS.toFloat()), 1e-6f)
        // A little overshoot on the way.
        assertTrue((0..40).map { GamepadTimeline.drop(it * 10f) }.max() >= 1f)
    }
}
