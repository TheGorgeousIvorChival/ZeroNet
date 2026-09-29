package com.zeronet.mobile.ui.effects

import androidx.compose.foundation.Canvas
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.runtime.Composable
import androidx.compose.ui.Modifier
import androidx.compose.ui.geometry.CornerRadius
import androidx.compose.ui.geometry.Offset
import androidx.compose.ui.geometry.Size
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.graphics.Path
import androidx.compose.ui.graphics.StrokeCap
import androidx.compose.ui.graphics.drawscope.DrawScope
import androidx.compose.ui.graphics.drawscope.Stroke
import androidx.compose.ui.graphics.drawscope.rotate
import androidx.compose.ui.graphics.drawscope.withTransform
import androidx.compose.ui.semantics.clearAndSetSemantics
import androidx.compose.ui.unit.dp
import com.zeronet.mobile.model.ConnectionProfile
import com.zeronet.mobile.ui.home.rememberAmbientClock
import com.zeronet.mobile.ui.theme.LocalReducedMotion
import kotlin.math.PI
import kotlin.math.abs
import kotlin.math.cos
import kotlin.math.sin

/**
 * A kangaroo with a joey in her pouch, and a smaller joey hopping after, who
 * cross the screen while a connection is being made. The faster the mode, the
 * faster they hop; in gaming mode she holds a handheld console.
 */
@Composable
fun KangarooRunner(profile: ConnectionProfile, modifier: Modifier = Modifier) {
    val reduced = LocalReducedMotion.current
    val clock = rememberAmbientClock(!reduced)
    Canvas(modifier.fillMaxWidth().height(46.dp).clearAndSetSemantics { }) {
        val ms = if (reduced) 0f else clock.floatValue
        drawKangaroos(profile, ms)
    }
}

/** Hops per second. */
fun hopsPerSecond(profile: ConnectionProfile): Float = when (profile) {
    ConnectionProfile.Normal, ConnectionProfile.Legacy -> 1.15f
    ConnectionProfile.Fast -> 2.1f
    ConnectionProfile.Gaming -> 2.1f
}

/** How far one hop carries her, in dp: quicker modes stretch out. */
fun strideDp(profile: ConnectionProfile): Float = when (profile) {
    ConnectionProfile.Normal, ConnectionProfile.Legacy -> 24f
    ConnectionProfile.Fast, ConnectionProfile.Gaming -> 34f
}

/** How high a hop goes, in dp. */
fun hopHeightDp(profile: ConnectionProfile): Float = when (profile) {
    ConnectionProfile.Normal, ConnectionProfile.Legacy -> 9f
    ConnectionProfile.Fast, ConnectionProfile.Gaming -> 12f
}

/** Gaming mode has her playing on a handheld. */
fun holdsHandheld(profile: ConnectionProfile) = profile == ConnectionProfile.Gaming

/** Ground speed in dp per second. */
fun speedDp(profile: ConnectionProfile): Float = hopsPerSecond(profile) * strideDp(profile)

/**
 * The body at a moment of a hop, [phase] in `0..1` (0 is the push-off, 0.5 the
 * top, 1 the landing).
 */
data class Pose(
    /** Height off the ground, `0..1` of the hop. */
    val lift: Float,
    /** How far the hind legs are stretched out behind, `0` (tucked) to `1` (pushing off). */
    val legs: Float,
    /** Lean of the whole body, in degrees, nose down positive. */
    val lean: Float,
    /** Swing of the tail, in degrees. */
    val tail: Float,
    /** Squash at landing and push-off, `0..1`. */
    val squash: Float,
)

fun pose(phase: Float): Pose {
    val p = phase - kotlin.math.floor(phase)
    val lift = sin(PI.toFloat() * p)
    // Legs are out at both ends of a hop, tucked in the middle.
    val legs = abs(cos(PI.toFloat() * p)).let { it * it }
    val lean = -10f * cos(PI.toFloat() * p) * lift.coerceAtLeast(0.25f)
    val tail = 14f * sin(2f * PI.toFloat() * p + 0.6f)
    val squash = (1f - lift).let { it * it * it * it }
    return Pose(lift, legs, lean, tail, squash)
}

private val FUR = Color(0xFFC98B4E)
private val FUR_DARK = Color(0xFF8E5B2C)
private val BELLY = Color(0xFFEBCFA0)
private val EYE = Color(0xFF2B1B10)

private fun DrawScope.drawKangaroos(profile: ConnectionProfile, ms: Float) {
    val unit = 1.dp.toPx()
    val seconds = ms / 1000f
    val hops = hopsPerSecond(profile)
    val phase = seconds * hops
    val ground = size.height - 5f * unit

    // The ground: a line of small dashes that slide the other way.
    val slide = (seconds * speedDp(profile) * unit) % (14f * unit)
    var x = -slide
    while (x < size.width) {
        drawLine(Color.White.copy(alpha = 0.10f), Offset(x, ground + 2f * unit), Offset(x + 6f * unit, ground + 2f * unit), 1f * unit, StrokeCap.Round)
        x += 14f * unit
    }

    // She stays near the middle while the ground slides past, and wanders a little.
    val centre = size.width * 0.5f + sin(seconds * 0.6f) * size.width * 0.12f
    val joeyAt = centre - 40f * unit
    // Dust from the landing.
    val landing = phase - kotlin.math.floor(phase)
    if (landing < 0.35f) {
        val puff = landing / 0.35f
        drawCircle(Color.White.copy(alpha = 0.22f * (1f - puff)), (2f + 4f * puff) * unit, Offset(centre - 12f * unit - puff * 8f * unit, ground - 2f * unit))
    }

    hopper(Offset(centre, ground), unit * 1.0f, phase, profile, hopHeightDp(profile) * unit, mother = true)
    hopper(Offset(joeyAt, ground), unit * 0.5f, phase - 0.16f, profile, hopHeightDp(profile) * unit * 0.8f, mother = false)
}

private fun DrawScope.hopper(base: Offset, scale: Float, phase: Float, profile: ConnectionProfile, height: Float, mother: Boolean) {
    val p = pose(phase)
    val lifted = Offset(base.x, base.y - p.lift * height)
    // A shadow that shrinks as she rises.
    drawOval(Color.Black.copy(alpha = 0.22f * (1f - 0.6f * p.lift)), Offset(base.x - 11f * scale, base.y - 1f * scale), Size(22f * scale * (1f - 0.3f * p.lift), 3.5f * scale))
    withTransform({
        translate(lifted.x, lifted.y)
        scale(scale, scale * (1f - 0.10f * p.squash), pivot = Offset.Zero)
        rotate(p.lean, pivot = Offset(0f, -14f))
    }) {
        // Tail first, behind everything.
        val tail = Path().apply {
            moveTo(-7f, -13f)
            cubicTo(-16f, -11f, -22f, -6f + p.tail * 0.2f, -27f, -3f + p.tail * 0.35f)
            cubicTo(-21f, -9f, -15f, -9.5f, -7f, -8f)
            close()
        }
        drawPath(tail, FUR_DARK)

        // Hind leg: thigh, shin and a long foot, stretched out behind at push-off and landing.
        val stretch = p.legs
        val thighAngle = -20f + 55f * stretch
        rotate(thighAngle, pivot = Offset(-4f, -12f)) {
            drawOval(FUR_DARK, Offset(-12f, -17f), Size(16f, 10f))
        }
        val kneeX = -6f - 7f * stretch
        val kneeY = -6f + 1f * stretch
        val footX = -6f - 12f * stretch + 3f * (1f - stretch)
        val footY = -1f - 3f * (1f - stretch)
        drawLine(FUR_DARK, Offset(-5f, -10f), Offset(kneeX, kneeY), 4f, StrokeCap.Round)
        drawLine(FUR_DARK, Offset(kneeX, kneeY), Offset(footX, footY), 3f, StrokeCap.Round)
        drawLine(FUR_DARK, Offset(footX, footY), Offset(footX + 9f, footY + 0.5f + 1.5f * stretch), 3f, StrokeCap.Round)

        // Body, belly and pouch.
        drawOval(FUR, Offset(-10f, -24f), Size(21f, 17f))
        drawOval(BELLY, Offset(-1f, -20f), Size(11f, 11f))
        if (mother) {
            drawOval(FUR_DARK.copy(alpha = 0.75f), Offset(0.5f, -17f), Size(8f, 6f))
            // The joey in the pouch: its head and ears.
            val joey = Offset(4.5f, -18.5f)
            drawCircle(FUR, 2.7f, joey)
            drawPath(triangle(Offset(3f, -20.5f), 1.2f, -3.2f), FUR)
            drawPath(triangle(Offset(6f, -20.5f), 1.2f, -3.2f), FUR)
            drawCircle(EYE, 0.55f, Offset(5.3f, -18.8f))
        }

        // Neck, head, snout, ears, eye.
        drawLine(FUR, Offset(6f, -20f), Offset(10f, -27f), 6f, StrokeCap.Round)
        drawOval(FUR, Offset(6.5f, -32f), Size(9f, 7.5f))
        drawOval(FUR, Offset(13f, -30f), Size(6f, 3.6f))
        drawCircle(EYE, 0.9f, Offset(11.5f, -28.6f))
        drawCircle(EYE, 0.6f, Offset(18.6f, -28.8f))
        rotate(-8f + p.lean * 0.3f, pivot = Offset(8.5f, -32f)) {
            drawPath(triangle(Offset(8f, -32f), 2.4f, -8f), FUR)
            drawPath(triangle(Offset(8f, -32f), 1.2f, -6f), BELLY)
        }

        // Arms: tucked, or holding the handheld.
        if (mother && holdsHandheld(profile)) {
            handheld(p)
        } else {
            drawLine(FUR_DARK, Offset(8f, -19f), Offset(12f, -16f + 1.2f * p.lift), 2.2f, StrokeCap.Round)
        }
    }
}

private fun triangle(base: Offset, halfWidth: Float, height: Float): Path = Path().apply {
    moveTo(base.x - halfWidth, base.y)
    lineTo(base.x, base.y + height)
    lineTo(base.x + halfWidth, base.y)
    close()
}

/** A small handheld console held in front, its screen glowing. */
private fun DrawScope.handheld(p: Pose) {
    val body = Color(0xFF2A2F3A)
    drawLine(FUR_DARK, Offset(8f, -19f), Offset(15f, -15f), 2.2f, StrokeCap.Round)
    drawRoundRect(body, Offset(12f, -20f), Size(15f, 8.5f), CornerRadius(1.8f))
    drawRoundRect(Color(0xFF7FE3B0).copy(alpha = 0.85f), Offset(16.2f, -19f), Size(6.6f, 5.6f), CornerRadius(0.8f))
    drawCircle(Color(0xFFFF5A5F), 0.9f, Offset(24.6f, -17.5f))
    drawCircle(Color(0xFF4DA3FF), 0.9f, Offset(23.2f, -15.6f))
    drawCircle(Color.White.copy(alpha = 0.5f), 1.1f, Offset(14.2f, -16.4f))
    // Her fingers on it.
    drawCircle(FUR, 1.4f, Offset(13.8f, -13.4f + 0.6f * p.lift))
    drawCircle(FUR, 1.4f, Offset(25.6f, -13.4f + 0.6f * p.lift))
}
